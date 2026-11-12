from quality.gate import code_hit
from quality.ignorefile import split_ignored
from quality.ruledata import UNUSED_NOCHECK, RuleData
from quality.suppress import idle, nocheck_rule, split_nocheck

NOCHECK_BYTES = b"nocheck:"


def unused_nochecks(data: RuleData, snapshot, paths: list, applied: list) -> list:
    """
    Args:
        data: Rule data of the run.
        snapshot: Snapshot holding the files.
        paths: Files of this run.
        applied: NocheckLine records of the nochecks that waived a finding.

    Returns:
        One finding per nocheck that waived nothing on its line although
        a rule it names ran on the file, or although no rule it names can
        fire there in any run.
    """
    rule = data.runner_rule(UNUSED_NOCHECK)
    used = {(item.path, item.line) for item in applied}
    files = {path: snapshot.kinds_of(path) for path in paths if NOCHECK_BYTES in snapshot.data(path)}
    able = data.ids_per_path(data.every_binding(), files)
    return [
        code_hit(rule, path, line, "", snapshot)
        for path in files
        for line, comment in snapshot.comments(path).items()
        if (path, line) not in used
        and idle(nocheck_rule(comment), snapshot.ran.get(path, set()), able.get(path, set()))
    ]


def suppressed(data: RuleData, snapshot, paths: list, hits: list, entries: tuple) -> tuple:
    """
    Args:
        data: Rule data of the run.
        snapshot: Snapshot the findings came from.
        paths: Files of this run.
        hits: Its findings.
        entries: The soft and the hard `.qualityignore.yml` entries.

    Returns:
        The findings left, the unused nochecks, the applied ignore
        entries, and the applied nocheck lines.
    """
    kept, ignored = split_ignored(hits, *entries)
    kept, nocheck = split_nocheck(kept, snapshot)
    unused, waived = split_ignored(unused_nochecks(data, snapshot, paths, nocheck), *entries)
    return kept, unused, ignored + [entry for entry in waived if entry not in ignored], nocheck
