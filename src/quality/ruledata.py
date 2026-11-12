import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import pathspec
import yaml

from quality import QualityError
from quality.kinds import CODE_KIND, KindMap
from quality.suppress import COMMENTS_FILE, comment_patterns, nocheck_names

RESERVED_FILES = ("tools.yml", "limits.yml", "kinds.yml", COMMENTS_FILE)
ANY_KIND = "any"
BUILTIN = "builtin"
SIZE_GUARD = "size-guard"
BINARY_GUARD = "binary-guard"
FOLDER_ITEMS = "folder-items"
PREFIX_GROUPS = "prefix-groups"
UNUSED_NOCHECK = "unused-nocheck"
RUNNER_CHECKS = (SIZE_GUARD, BINARY_GUARD, FOLDER_ITEMS, PREFIX_GROUPS, UNUSED_NOCHECK)
RULE_DIR = "rule_dir"
PLACEHOLDERS = "placeholders"
COMMENTS = "comments"
NOCHECK_NAMES = "nocheck_names"
PARSES = "parses"


def require(mapping: dict, key: str, where: str):
    if not isinstance(mapping, dict) or key not in mapping:
        raise QualityError(f"rule data: {where} is missing key {key!r}")
    return mapping[key]


def gitignore_spec(patterns: list):
    return pathspec.GitIgnoreSpec.from_lines(patterns)


@dataclass(frozen=True, eq=False)
class Rule:
    id: str
    severity: str
    summary: str
    enforcer: object
    hard: bool
    metric: dict | None
    file_level: bool
    history: bool
    pending: bool
    tier: str | None
    exclude: object
    changed_only: bool

    def excludes(self, path: str) -> bool:
        return self.exclude is not None and self.exclude.match_file(path)

    def pending_tools(self) -> list:
        return sorted({settings["tool"] for settings in self.enforcer.values()})

    def file_gap(self) -> bool:
        """
        Returns:
            True for a file-level changed_only rule, such as a file a tool read
            only in part: it names each file once, and only a .qualityignore.yml
            entry naming that very file, read from the base side, waives it. A
            changed_only rule with lines keeps per-line nochecks and entries.
        """
        return self.changed_only and self.file_level

    def waived_from_base(self) -> bool:
        """
        Returns:
            True for a hard rule and for a changed_only rule, a gap a tool
            left: `--base` reads their .qualityignore.yml entries from the
            base side, so a pull request cannot waive its own finding or gap.
        """
        return self.hard or self.changed_only


@dataclass(frozen=True, eq=False)
class Binding:
    rule: Rule
    tool: str
    settings: dict
    kinds: frozenset

    def binds(self, path_kinds: frozenset) -> bool:
        """
        Args:
            path_kinds: Every kind of one file, possibly none.

        Returns:
            True when the file shares a kind with the binding, or the binding
            names the `any` kind, which holds every file, kindless ones included.
        """
        return ANY_KIND in self.kinds or bool(path_kinds & self.kinds)


@dataclass(frozen=True, eq=False)
class RuleData:
    rules: tuple
    tools: dict
    limits: dict
    kinds: KindMap

    def limit(self, key: str):
        return require(self.limits, key, "limits.yml")

    def tool(self, name: str) -> dict:
        return require(self.tools, name, "tools.yml")

    def members(self, name: str) -> list:
        return [rule for rule in self.rules if rule.id == name or rule.id.startswith(f"{name}.")]

    def pending_rules(self, tiers: tuple) -> list:
        return [rule for rule in self.rules if rule.pending and rule.tier in tiers]

    def runner_rule(self, enforcer: str) -> Rule:
        """
        Args:
            enforcer: Name of a check the runner performs itself, such as size-guard.

        Returns:
            The one rule naming that enforcer.

        Raises:
            QualityError: No rule or more than one names it.
        """
        found = [rule for rule in self.rules if rule.enforcer == enforcer]
        if len(found) != 1:
            raise QualityError(f"rule data: exactly one rule must name enforcer {enforcer!r}")
        return found[0]

    def has_history_rules(self) -> bool:
        return any(rule.history and not rule.pending for rule in self.rules)

    def bindings(self) -> dict:
        grouped = {}
        for rule in self.rules:
            if not rule.pending and isinstance(rule.enforcer, dict):
                for binding in rule_bindings(rule, self.kinds):
                    grouped.setdefault(binding.tool, []).append(binding)
        return grouped

    def visible_kinds(self, binding: Binding, path: str, kinds: frozenset) -> frozenset:
        """
        Args:
            binding: Rule binding to one tool.
            path: Path relative to the repository root.
            kinds: Every kind of the file.

        Returns:
            The kinds the binding binds the file by: all of them for a builtin
            that does not set `parses` and for a tool whose tools.yml entry sets
            `templates`, else its parsed kinds.
        """
        if binding.tool == BUILTIN and not binding.settings.get(PARSES):
            return kinds
        if self.tools.get(binding.tool, {}).get("templates"):
            return kinds
        return self.kinds.parsed_kinds(path, kinds)

    def kind_rules(self, files: dict, tiers: tuple) -> tuple:
        """
        Args:
            files: Path to every kind of the file.
            tiers: Tiers whose pending rules count.

        Returns:
            Two maps of kind to sorted rule ids: the active rules that run on
            a file by that kind, and the pending rules that would.
        """
        active = [binding for bindings in self.bindings().values() for binding in bindings]
        pending = [
            binding for rule in self.pending_rules(tiers) for binding in rule_bindings(rule, self.kinds)
        ]
        return self.ids_per_kind(active, files), self.ids_per_kind(pending, files)

    def every_binding(self) -> list:
        return [
            binding
            for rule in self.rules
            if isinstance(rule.enforcer, dict)
            for binding in rule_bindings(rule, self.kinds)
        ]

    def ids_per_path(self, bindings: list, files: dict) -> dict:
        found = {}
        for path, kinds in files.items():
            for binding in bindings:
                if not binding.rule.excludes(path) and binding.binds(self.visible_kinds(binding, path, kinds)):
                    found.setdefault(path, set()).add(binding.rule.id)
        return found

    def ids_per_kind(self, bindings: list, files: dict) -> dict:
        found = {}
        for path, kinds in files.items():
            for binding in bindings:
                if not binding.rule.excludes(path):
                    for kind in binding.kinds & self.visible_kinds(binding, path, kinds):
                        found.setdefault(kind, set()).add(binding.rule.id)
        return {kind: sorted(ids) for kind, ids in found.items()}


def rule_bindings(rule: Rule, kind_map: KindMap) -> list:
    """
    Args:
        rule: Catalogue rule whose enforcer maps kinds to settings.
        kind_map: File kind classification.

    Returns:
        One binding per tool and distinct settings, so that kinds sharing
        their settings share one tool run and kinds with their own pattern
        or language keep it.
    """
    grouped = {}
    for kind, settings in rule.enforcer.items():
        kinds = kind_map.code if kind == CODE_KIND else (kind,)
        tool = settings["tool"] if "tool" in settings else BUILTIN
        key = (tool, json.dumps(settings, sort_keys=True))
        grouped.setdefault(key, (settings, set()))[1].update(kinds)
    return [
        Binding(rule, tool, settings, frozenset(kinds))
        for (tool, _), (settings, kinds) in grouped.items()
    ]


def filled(value, placeholders: dict):
    """
    Args:
        value: Loaded YAML.
        placeholders: Strings to replace where a value equals one exactly.

    Returns:
        A copy of the value with each such string replaced.
    """
    if isinstance(value, dict):
        return {key: filled(item, placeholders) for key, item in value.items()}
    if isinstance(value, list):
        return [filled(item, placeholders) for item in value]
    if isinstance(value, str) and value in placeholders:
        return placeholders[value]
    return value


def build_rule(raw: dict, where: str, placeholders: dict) -> Rule:
    rule_id = require(raw, "id", where)
    entry = f"{where} rule {rule_id}"
    metric = raw.get("metric")
    if metric is not None:
        require(metric, "limit", entry)
    exclude = raw.get("exclude")
    rule = Rule(
        id=rule_id,
        severity=require(raw, "severity", entry),
        summary=require(raw, "summary", entry),
        enforcer=filled(require(raw, "enforcer", entry), placeholders),
        hard=bool(raw.get("hard")),
        metric=metric,
        file_level=bool(raw.get("file_level")),
        history=bool(raw.get("history")),
        pending=bool(raw.get("pending")),
        tier=raw.get("tier"),
        exclude=gitignore_spec(exclude) if exclude else None,
        changed_only=bool(raw.get("changed_only")),
    )
    if rule.changed_only and rule.hard:
        raise QualityError(f"rule data: {entry} sets changed_only with hard")
    if rule.history and not rule.hard:
        raise QualityError(f"rule data: {entry} sets history without hard")
    if not isinstance(rule.enforcer, dict) and rule.enforcer not in RUNNER_CHECKS:
        raise QualityError(f"rule data: {entry} names an enforcer the runner does not know")
    if rule.pending:
        require(raw, "tier", entry)
    return rule


def check_unique(rules: list) -> None:
    repeated = sorted(rule_id for rule_id, count in Counter(rule.id for rule in rules).items() if count > 1)
    if repeated:
        raise QualityError(f"rule data: duplicate rule id {repeated[0]}")


def check_allow_list(rules: list, tools: dict) -> None:
    for rule in rules:
        if rule.pending or not isinstance(rule.enforcer, dict):
            continue
        for settings in rule.enforcer.values():
            if "tool" not in settings:
                require(settings, BUILTIN, f"enforcer of rule {rule.id}")
            elif settings["tool"] not in tools:
                raise QualityError(
                    f"rule {rule.id}: enforcer names tool {settings['tool']!r} "
                    "outside rules/tools.yml"
                )


def read_yaml(path: Path):
    try:
        return yaml.safe_load(path.read_bytes())
    except OSError:
        raise QualityError(f"rule data: cannot read {path.name}") from None
    except yaml.YAMLError:
        raise QualityError(f"rule data: {path.name} is not valid YAML") from None


def lowered(listing: dict) -> dict:
    return {key: [value.lower() for value in values] for key, values in listing.items()}


def load_kinds(raw: dict) -> KindMap:
    known = lowered(require(raw, "known_suffixes", "kinds.yml"))
    require(known, CODE_KIND, "kinds.yml known_suffixes")
    return KindMap(
        extensions={
            suffix.lower(): kind for suffix, kind in require(raw, "extensions", "kinds.yml").items()
        },
        shebangs=require(raw, "shebangs", "kinds.yml"),
        globs={
            kind: gitignore_spec(patterns)
            for kind, patterns in lowered(require(raw, "globs", "kinds.yml")).items()
        },
        names=lowered(require(raw, "names", "kinds.yml")),
        known=known,
        binary_names=[name.lower() for name in require(raw, "binary_names", "kinds.yml")],
        code=tuple(require(raw, "code", "kinds.yml")),
        markers=require(raw, "comment_markers", "kinds.yml"),
        templates=tuple(require(raw, "templates", "kinds.yml")),
    )


def anchor_rule_dirs(tools: dict, directory: Path, comments: dict) -> dict:
    """
    Args:
        tools: Content of tools.yml.
        directory: Directory the rule data was loaded from.
        comments: Comment patterns, comments.yml and the nocheck names, under
            the keys `placeholders`, `comments` and `nocheck_names`.

    Returns:
        tools.yml with every `rule_dir` resolved against that directory, so a
        tool reads this repository's rule files and never the target's, and
        given what its rule files compose their comment patterns from.
    """
    if not isinstance(tools, dict):
        return tools
    return {
        name: (
            {**settings, RULE_DIR: str(directory.resolve() / settings[RULE_DIR]), **comments}
            if isinstance(settings, dict) and RULE_DIR in settings
            else settings
        )
        for name, settings in tools.items()
    }


def locate(option: str | None) -> Path:
    """
    Args:
        option: The --rules value, or None to use the packaged rule data.

    Returns:
        The directory holding tools.yml.

    Raises:
        QualityError: No directory holds tools.yml.
    """
    package = Path(__file__).resolve().parent
    candidates = [Path(option)] if option else [package / "rules", package.parents[1] / "rules"]
    for candidate in candidates:
        if (candidate / "tools.yml").is_file():
            return candidate
    raise QualityError("rule data: no directory holds tools.yml")


def load(directory: Path) -> RuleData:
    """
    Args:
        directory: Directory holding tools.yml, limits.yml, kinds.yml,
            comments.yml and the catalogue.

    Returns:
        The validated rule data.

    Raises:
        QualityError: A key is missing, a rule id repeats, or an enforcer
            names a tool outside the allow-list.
    """
    entries = [
        (path.name, raw)
        for path in sorted(directory.glob("*.yml"))
        if path.name not in RESERVED_FILES
        for raw in read_yaml(path) or []
    ]
    comments = read_yaml(directory / COMMENTS_FILE)
    placeholders = comment_patterns(comments)
    names = nocheck_names([require(raw, "id", where) for where, raw in entries])
    shared = {PLACEHOLDERS: placeholders, COMMENTS: comments, NOCHECK_NAMES: names}
    tools = anchor_rule_dirs(read_yaml(directory / "tools.yml"), directory, shared)
    rules = [build_rule(raw, where, placeholders) for where, raw in entries]
    check_unique(rules)
    check_allow_list(rules, tools)
    return RuleData(
        rules=tuple(rules),
        tools=tools,
        limits=read_yaml(directory / "limits.yml"),
        kinds=load_kinds(read_yaml(directory / "kinds.yml")),
    )
