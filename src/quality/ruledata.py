import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

import pathspec
import yaml

from quality import QualityError

RESERVED_FILES = ("tools.yml", "limits.yml", "kinds.yml")
VERSION_SUFFIX = re.compile(r"[0-9.]+$")
CODE_KIND = "code"
BUILTIN = "builtin"
SIZE_GUARD = "size-guard"
FOLDER_ITEMS = "folder-items"
PREFIX_GROUPS = "prefix-groups"
RUNNER_CHECKS = (SIZE_GUARD, FOLDER_ITEMS, PREFIX_GROUPS)


def require(mapping: dict, key: str, where: str):
    if not isinstance(mapping, dict) or key not in mapping:
        raise QualityError(f"rule data: {where} is missing key {key!r}")
    return mapping[key]


def gitignore_spec(patterns: list):
    return pathspec.GitIgnoreSpec.from_lines(patterns)


def interpreter_name(word: str) -> str:
    return VERSION_SUFFIX.sub("", PurePosixPath(word.removeprefix("-S")).name)


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

    def excludes(self, path: str) -> bool:
        return self.exclude is not None and self.exclude.match_file(path)

    def pending_tools(self) -> list:
        return sorted({settings["tool"] for settings in self.enforcer.values()})


@dataclass(frozen=True, eq=False)
class Binding:
    rule: Rule
    tool: str
    settings: dict
    kinds: frozenset


@dataclass(frozen=True, eq=False)
class KindMap:
    extensions: dict
    shebangs: dict
    globs: dict
    code: tuple
    markers: dict

    def kinds_of(self, path: str, first_line: bytes) -> frozenset:
        """
        Args:
            path: Path relative to the repository root.
            first_line: Start of the file, read only without a known extension.

        Returns:
            Every kind the file belongs to.
        """
        found = {kind for kind, spec in self.globs.items() if spec.match_file(path)}
        suffix = PurePosixPath(path).suffix
        if suffix in self.extensions:
            found.add(self.extensions[suffix])
        else:
            kind = self.shebang_kind(first_line)
            if kind is not None:
                found.add(kind)
        return frozenset(found)

    def shebang_kind(self, first_line: bytes) -> str | None:
        """
        Args:
            first_line: Start of the file.

        Returns:
            The kind of its interpreter. Every word after `env` counts, because
            `env -S python3 -u` and `env -u NAME python3` both run Python.
        """
        if not first_line.startswith(b"#!"):
            return None
        names = [interpreter_name(w) for w in first_line[2:].decode("utf-8", "replace").split()]
        candidates = names[1:] if names[:1] == ["env"] else names[:1]
        return next((self.shebangs[name] for name in candidates if name in self.shebangs), None)

    def needs_first_line(self, path: str) -> bool:
        return PurePosixPath(path).suffix not in self.extensions

    def code_name(self, path: str) -> bool:
        suffix = PurePosixPath(path).suffix
        return not suffix or self.extensions.get(suffix) in self.code


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


def rule_bindings(rule: Rule, kind_map: KindMap) -> list:
    per_tool = {}
    for kind, settings in rule.enforcer.items():
        kinds = kind_map.code if kind == CODE_KIND else (kind,)
        tool = settings["tool"] if "tool" in settings else BUILTIN
        per_tool.setdefault(tool, (settings, set()))[1].update(kinds)
    return [
        Binding(rule, tool, settings, frozenset(kinds))
        for tool, (settings, kinds) in per_tool.items()
    ]


def build_rule(raw: dict, where: str) -> Rule:
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
        enforcer=require(raw, "enforcer", entry),
        hard=bool(raw.get("hard")),
        metric=metric,
        file_level=bool(raw.get("file_level")),
        history=bool(raw.get("history")),
        pending=bool(raw.get("pending")),
        tier=raw.get("tier"),
        exclude=gitignore_spec(exclude) if exclude else None,
    )
    if rule.history and not rule.hard:
        raise QualityError(f"rule data: {entry} sets history without hard")
    if not isinstance(rule.enforcer, dict) and rule.enforcer not in RUNNER_CHECKS:
        raise QualityError(f"rule data: {entry} names an enforcer the runner does not know")
    if rule.pending:
        require(raw, "tier", entry)
    return rule


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


def load_kinds(raw: dict) -> KindMap:
    return KindMap(
        extensions=require(raw, "extensions", "kinds.yml"),
        shebangs=require(raw, "shebangs", "kinds.yml"),
        globs={
            kind: gitignore_spec(patterns)
            for kind, patterns in require(raw, "globs", "kinds.yml").items()
        },
        code=tuple(require(raw, "code", "kinds.yml")),
        markers=require(raw, "comment_markers", "kinds.yml"),
    )


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
        directory: Directory holding tools.yml, limits.yml, kinds.yml and the catalogue.

    Returns:
        The validated rule data.

    Raises:
        QualityError: A key is missing or an enforcer names a tool outside the allow-list.
    """
    tools = read_yaml(directory / "tools.yml")
    rules = []
    for path in sorted(directory.glob("*.yml")):
        if path.name not in RESERVED_FILES:
            for raw in read_yaml(path) or []:
                rules.append(build_rule(raw, path.name))
    check_allow_list(rules, tools)
    return RuleData(
        rules=tuple(rules),
        tools=tools,
        limits=read_yaml(directory / "limits.yml"),
        kinds=load_kinds(read_yaml(directory / "kinds.yml")),
    )
