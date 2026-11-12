import re
from dataclasses import dataclass

import yaml

from quality import QualityError
from quality.repo import IGNORE_FILE
from quality.ruledata import RuleData, gitignore_spec
from quality.suppress import rule_matches

ALLOWED_KEYS = {"rule", "paths", "reason"}
GLOB_CHARACTERS = re.compile(r"[*?\[\\]")


@dataclass(frozen=True, eq=False)
class IgnoreEntry:
    rule: str
    paths: tuple
    reason: str
    spec: object

    def covers(self, rule_id: str, path: str) -> bool:
        if not rule_matches(rule_id, self.rule):
            return False
        return self.spec is None or self.spec.match_file(path)

    def literal_paths(self) -> set:
        return {item.removeprefix("/") for item in self.paths}

    def names(self, rule_id: str, path: str) -> bool:
        return rule_matches(rule_id, self.rule) and path in self.literal_paths()

    def waives(self, hit) -> bool:
        if hit.rule.changed_only:
            return self.names(hit.rule.id, hit.path)
        return self.covers(hit.rule.id, hit.path)

    def public(self) -> dict:
        return {"rule": self.rule, "paths": list(self.paths), "reason": self.reason}


def text_field(raw: dict, key: str, position: int) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise QualityError(f"{IGNORE_FILE}: entry {position} needs a non-empty {key}")
    return value


def path_list(raw: dict, position: int) -> tuple:
    paths = raw.get("paths")
    if paths is None:
        return ()
    if not isinstance(paths, list) or not all(isinstance(path, str) for path in paths):
        raise QualityError(f"{IGNORE_FILE}: entry {position} paths must be a list of strings")
    if not paths:
        raise QualityError(f"{IGNORE_FILE}: entry {position} paths must not be empty")
    return tuple(paths)


def narrow_enough(pattern: str) -> bool:
    """
    Args:
        pattern: One gitignore pattern of a hard rule entry.

    Returns:
        True when its first segment is a literal name and it holds no `**`,
        so that `*.py` or `[a-z]*` cannot switch a hard rule off repo-wide.
    """
    first = pattern.removeprefix("/").split("/", 1)[0]
    if "**" in pattern or pattern.startswith("!") or first in ("", ".", ".."):
        return False
    return GLOB_CHARACTERS.search(first) is None


def check_hard(rule: str, paths: tuple, position: int, data: RuleData) -> None:
    if not any(member.hard for member in data.members(rule)):
        return
    if not paths:
        raise QualityError(f"{IGNORE_FILE}: entry {position} names a hard rule and needs paths")
    for pattern in paths:
        if not narrow_enough(pattern):
            raise QualityError(
                f"{IGNORE_FILE}: entry {position} names a hard rule and rejects {pattern!r}: "
                "its first segment must be a literal name, and ** is not allowed"
            )


def check_literal(rule: str, paths: tuple, position: int, data: RuleData) -> None:
    if not any(member.id == rule and member.changed_only for member in data.rules):
        return
    for pattern in paths or ("",):
        if not pattern or pattern.startswith("!") or pattern.endswith("/") or GLOB_CHARACTERS.search(pattern):
            raise QualityError(
                f"{IGNORE_FILE}: entry {position} names {rule}, which only a list of literal file paths waives, "
                f"and rejects {pattern!r}"
            )


def parse_entry(raw: object, position: int, data: RuleData) -> IgnoreEntry:
    if not isinstance(raw, dict):
        raise QualityError(f"{IGNORE_FILE}: entry {position} must be a mapping")
    unknown = sorted(str(key) for key in raw if key not in ALLOWED_KEYS)
    if unknown:
        raise QualityError(f"{IGNORE_FILE}: entry {position} has unknown keys {unknown}")
    rule = text_field(raw, "rule", position)
    paths = path_list(raw, position)
    reason = text_field(raw, "reason", position)
    check_hard(rule, paths, position, data)
    check_literal(rule, paths, position, data)
    return IgnoreEntry(rule, paths, reason, gitignore_spec(paths) if paths else None)


def parse(content: bytes | None, data: RuleData) -> list:
    """
    Args:
        content: File content, or None when the file is absent.
        data: Rule data deciding which rules are hard.

    Returns:
        The entries in file order.

    Raises:
        QualityError: The file breaks the schema. The message never quotes
            the file, because YAML errors carry a source snippet.
    """
    if content is None:
        return []
    try:
        document = yaml.safe_load(content)
    except yaml.YAMLError:
        raise QualityError(f"{IGNORE_FILE}: not valid YAML") from None
    if document is None:
        return []
    if not isinstance(document, list):
        raise QualityError(f"{IGNORE_FILE}: top level must be a list of entries")
    return [parse_entry(raw, index, data) for index, raw in enumerate(document, start=1)]


def split_ignored(hits: list, soft_entries: list, hard_entries: list) -> tuple:
    """
    Args:
        hits: Findings on the head side.
        soft_entries: Entries consulted for the other rules.
        hard_entries: Entries consulted for hard and changed_only rules, which
            `--base` reads from the base side, so a pull request cannot waive
            its own finding.

    Returns:
        The remaining findings and the entries that applied.
    """
    kept = []
    applied = []
    for hit in hits:
        entries = hard_entries if hit.rule.hard or hit.rule.changed_only else soft_entries
        entry = next((item for item in entries if item.waives(hit)), None)
        if entry is None:
            kept.append(hit)
        elif entry not in applied:
            applied.append(entry)
    return kept, applied


def refuse_stale(stale: list) -> None:
    if stale:
        raise QualityError(f"stale {IGNORE_FILE} entry: {describe(stale[0])}")


def stale_names(entries: list, hits: list, checked: set, rule_ids: set) -> list:
    """
    Args:
        entries: Head side entries.
        hits: Findings before any entry applied.
        checked: Files this run checked.
        rule_ids: changed_only rules of the running tiers.

    Returns:
        The entries naming one of those rules and a checked file that rule
        did not flag, so they outlived their gap.
    """
    flagged = {(hit.rule.id, hit.path) for hit in hits}
    return [
        entry
        for entry in entries
        if entry.rule in rule_ids
        and any(path in checked and (entry.rule, path) not in flagged for path in entry.literal_paths())
    ]


def audit_lines(old: list, new: list) -> list:
    """
    Args:
        old: Entries on the base side.
        new: Entries on the head side.

    Returns:
        One audit line per added, removed or changed entry.
    """
    before = {(entry.rule, entry.paths): entry for entry in old}
    after = {(entry.rule, entry.paths): entry for entry in new}
    lines = []
    for key in sorted(before.keys() - after.keys()):
        lines.append(f"audit: {IGNORE_FILE} removed {describe(before[key])}")
    for key in sorted(after.keys() - before.keys()):
        lines.append(f"audit: {IGNORE_FILE} added {describe(after[key])}")
    for key in sorted(before.keys() & after.keys()):
        if before[key].reason != after[key].reason:
            lines.append(f"audit: {IGNORE_FILE} changed {describe(after[key])}")
    return lines


def describe(entry: IgnoreEntry) -> str:
    return f"rule={entry.rule} paths={list(entry.paths)} reason={entry.reason}"
