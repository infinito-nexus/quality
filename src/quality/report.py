import json
from dataclasses import dataclass

from quality import printable

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2
FULL_SCORE = 100
BLOCKER_SEVERITY = "critical"
LEGAL_KEYS = ("legal", "legal_blockers", "legal_unchecked")


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


@dataclass(frozen=True)
class Legal:
    """
    Args:
        score: 100 less the legal weight of every counted finding, at least 0.
        blockers: Counted findings of a critical rule, each of which forbids the commit.
        unchecked: Dependencies or files whose licence could not be judged.
    """

    score: int
    blockers: int
    unchecked: int


@dataclass(frozen=True, repr=False)
class Outcome:
    findings: list
    ignored: list
    nocheck: list
    unchecked: list
    notes: list
    incomplete: list
    unparsed: list
    architecture: int | None
    legal: Legal | None


def architecture_of(findings: list) -> int:
    """
    Args:
        findings: Findings a diff mode reports, so only hits new against its base.

    Returns:
        100 less the architecture weight of every finding whose rule carries
        one, the findings of one group, such as both fragments of a clone,
        weighed once; at least 0.
    """
    weights = {
        (hit.rule.id, hit.group) if hit.group else index: hit.rule.architecture
        for index, hit in enumerate(findings)
        if hit.rule.architecture
    }
    return max(0, FULL_SCORE - sum(weights.values()))


def legal_of(findings: list, unchecked: list) -> Legal:
    """
    Args:
        findings: Findings a diff mode reports, so only hits new against its base.
        unchecked: The new findings legal.checks.split_unchecked() took out.

    Returns:
        The legal score of the findings whose rule carries a legal weight.
    """
    counted = [hit for hit in findings if hit.rule.legal]
    blockers = sum(hit.rule.severity == BLOCKER_SEVERITY for hit in counted)
    return Legal(max(0, FULL_SCORE - sum(hit.rule.legal for hit in counted)), blockers, len(unchecked))


def legal_fields(legal: Legal | None) -> dict:
    values = (None, None, None) if legal is None else (legal.score, legal.blockers, legal.unchecked)
    return dict(zip(LEGAL_KEYS, values, strict=True))


def public_finding(hit) -> dict:
    """
    Args:
        hit: Internal finding.

    Returns:
        The only form of a finding that leaves the runner: exactly rule, path,
        line, severity, summary, value, commit and lens, the principle the rule
        checks or None.
    """
    return {
        "rule": hit.rule.id,
        "path": hit.path,
        "line": hit.line,
        "severity": hit.rule.severity,
        "summary": hit.rule.summary,
        "value": hit.value,
        "commit": hit.commit,
        "lens": hit.rule.lens,
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
        "parse_incomplete": outcome.unparsed,
        "architecture": outcome.architecture,
        **legal_fields(outcome.legal),
    }
    return json.dumps(document, indent=2, sort_keys=True)


def sorted_hits(hits: list) -> list:
    return sorted(hits, key=lambda hit: (hit.path, hit.line or 0, hit.rule.id))  # nocheck: clean.default-value -- a finding without a line sorts as line 0


def text_line(hit) -> str:
    item = public_finding(hit)
    location = item["path"] if item["line"] is None else f"{item['path']}:{item['line']}"
    value = "" if item["value"] is None else f" (value {item['value']})"
    commit = "" if item["commit"] is None else f" (commit {item['commit']})"
    lens = "" if item["lens"] is None else f" (lens {item['lens']})"
    return f"{location}: {item['rule']} [{item['severity']}] {item['summary']}{value}{commit}{lens}"


def render_text(outcome: Outcome) -> str:
    lines = [text_line(hit) for hit in sorted_hits(outcome.findings)]
    lines += [f"unchecked: {item.path} {item.reason}" for item in sorted(set(outcome.unchecked))]
    unparsed = [f"parse incomplete: {path}" for path in outcome.unparsed]
    lines += [line for line in unparsed if line not in outcome.notes]
    lines += outcome.notes
    if outcome.incomplete:
        lines.append(f"incomplete: pending rules {', '.join(outcome.incomplete)}")
    if outcome.architecture is not None:
        lines.append(f"architecture: {outcome.architecture}")
    lines.append(f"quality: {len(outcome.findings)} finding(s)")
    return "\n".join(printable(line) for line in lines)
