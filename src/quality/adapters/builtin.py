from quality import QualityError
from quality.gate import metric_hit


def file_lines(item, snapshot) -> list:
    """
    Args:
        item: Bound rule with its files.
        snapshot: Snapshot holding the files.

    Returns:
        One metric finding per file over the limit.
    """
    rule = item.binding.rule
    hits = []
    for path in item.files:
        value = snapshot.line_count(path)
        if value > rule.metric["limit"]:
            hits.append(metric_hit(rule, path, None, value, ""))
    return hits


def run_builtin(item, snapshot) -> list:
    name = item.binding.settings["builtin"]
    if name != "file-lines":
        raise QualityError(f"rule {item.binding.rule.id}: unknown builtin {name!r}")
    return file_lines(item, snapshot)
