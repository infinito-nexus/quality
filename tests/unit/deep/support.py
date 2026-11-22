from pathlib import Path

from quality.adapters.base import Bound
from quality.ruledata import load, rule_bindings
from quality.snapshot import Snapshot

RULES = Path(__file__).resolve().parents[3] / "rules"
DATA = load(RULES)
VULNERABLE = "security.vulnerable-dependency"


def binding(rule_id: str, tool: str):
    rule = next(rule for rule in DATA.rules if rule.id == rule_id)
    return next(item for item in rule_bindings(rule, DATA.kinds) if item.tool == tool)


def bound_of(rule_id: str, tool: str, kinds: dict) -> Bound:
    """
    Args:
        rule_id: Catalogue rule.
        tool: Tool the rule is bound to.
        kinds: Path to its kind, or to "" for a lockfile that has none.

    Returns:
        The rule bound to those files.
    """
    files = list(kinds)
    return Bound(binding(rule_id, tool), files, {path: frozenset({kinds[path]} - {""}) for path in files})


def snapshot_of(root: Path, files: dict) -> Snapshot:
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text, encoding="utf-8")
    return Snapshot(root, dict.fromkeys(files), [], set(), DATA.kinds, set(), {}, None, {})
