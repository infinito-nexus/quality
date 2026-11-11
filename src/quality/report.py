import json
from dataclasses import dataclass

from quality import printable

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


@dataclass(frozen=True, order=True)
class Unchecked:
    path: str
    reason: str


def unchecked_of(snapshot, wanted: set | None) -> list:
    """
    Args:
        snapshot: Snapshot whose rules have run.
        wanted: Paths to report, or None for every path.

    Returns:
        One entry per path no rule could fully read, with the reason.
    """
    return [
        Unchecked(path, reason)
        for path, reason in sorted(snapshot.unread.items())
        if wanted is None or path in wanted
    ]


@dataclass(frozen=True, repr=False)
class Outcome:
    findings: list
    ignored: list
    nocheck: list
    unchecked: list
    notes: list
    incomplete: list


def public_finding(hit) -> dict:
    """
    Args:
        hit: Internal finding.

    Returns:
        The only form of a finding that leaves the runner: exactly rule, path,
        line, severity, summary, value and commit.
    """
    return {
        "rule": hit.rule.id,
        "path": hit.path,
        "line": hit.line,
        "severity": hit.rule.severity,
        "summary": hit.rule.summary,
        "value": hit.value,
        "commit": hit.commit,
    }


def exit_code(outcome: Outcome) -> int:
    """
    Args:
        outcome: Finished check.

    Returns:
        1 with findings, 2 when the mode must not claim clean while rules are
        pending, otherwise 0.
    """
    if outcome.findings:
        return EXIT_FINDINGS
    return EXIT_ERROR if outcome.incomplete else EXIT_CLEAN


def render_json(outcome: Outcome) -> str:
    document = {
        "findings": [public_finding(hit) for hit in sorted_hits(outcome.findings)],
        "ignored": [entry.public() for entry in outcome.ignored],
        "nocheck": [
            {"path": item.path, "line": item.line, "rule": item.rule} for item in outcome.nocheck
        ],
        "unchecked": sorted({item.path for item in outcome.unchecked}),
        "notes": outcome.notes,
        "incomplete": outcome.incomplete,
    }
    return json.dumps(document, indent=2, sort_keys=True)


def sorted_hits(hits: list) -> list:
    return sorted(hits, key=lambda hit: (hit.path, hit.line or 0, hit.rule.id))


def text_line(hit) -> str:
    item = public_finding(hit)
    location = item["path"] if item["line"] is None else f"{item['path']}:{item['line']}"
    value = "" if item["value"] is None else f" (value {item['value']})"
    commit = "" if item["commit"] is None else f" (commit {item['commit']})"
    return f"{location}: {item['rule']} [{item['severity']}] {item['summary']}{value}{commit}"


def render_text(outcome: Outcome) -> str:
    lines = [text_line(hit) for hit in sorted_hits(outcome.findings)]
    lines += [f"unchecked: {item.path} {item.reason}" for item in sorted(set(outcome.unchecked))]
    lines += outcome.notes
    if outcome.incomplete:
        lines.append(f"incomplete: pending rules {', '.join(outcome.incomplete)}")
    lines.append(f"quality: {len(outcome.findings)} finding(s)")
    return "\n".join(printable(line) for line in lines)
