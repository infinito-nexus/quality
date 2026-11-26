from dataclasses import dataclass

from quality.report import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS

SCORES = ("security", "legal", "architecture", "break_risk", "confidence", "efficiency", "speed")
JUDGEMENTS = {"break_risk": "kvb-quality-break-risk", "confidence": "kvb-quality-confidence"}
JUDGEMENT_REASON = "a judgement, not a measurement: its callers fill {score}"
FINDING_KEYS = ("lens", "rule", "severity", "path", "line", "message", "commit", "tier", "blob")


@dataclass(frozen=True)
class Result:
    """
    Args:
        lens: Name of the lens.
        version: Its tool and rule-set version; None when it did not run.
        findings: Its review findings, each with exactly FINDING_KEYS.
        scores: The score names it fills, to their values.
        reason: Why it did not run, or None when it ran.
        error: A tool error, which makes the review exit 2, or None.
    """

    lens: str
    version: str | None
    findings: list
    scores: dict
    reason: str | None
    error: str | None


def skipped(lens: str, reason: str) -> Result:
    return Result(lens, None, [], {}, reason, None)


def failed(lens: str, error: str) -> Result:
    return Result(lens, None, [], {}, error, error)


def judgements() -> list:
    """
    Returns:
        One skipped result per score only a judgement can fill, named after
        the skill that fills it.
    """
    return [skipped(skill, JUDGEMENT_REASON.format(score=score)) for score, skill in JUDGEMENTS.items()]


def order(finding: dict) -> tuple:
    line = -1 if finding["line"] is None else finding["line"]
    return (finding["path"], line, finding["lens"], finding["rule"] or "", finding["commit"] or "")


def assemble(results: list) -> dict:
    """
    Args:
        results: Every lens result of the review.

    Returns:
        The review document: findings ordered by path and line, every score
        of SCORES (None where no lens filled it), the version of every lens
        that ran, the lenses that ran and the skipped ones with their reason.
    """
    scores = dict.fromkeys(SCORES)
    for result in results:
        scores.update(result.scores)
    ran = [result for result in results if result.reason is None]
    return {
        "findings": sorted((finding for result in results for finding in result.findings), key=order),
        "scores": scores,
        "lenses": {result.lens: result.version for result in ran},
        "ran": [result.lens for result in ran],
        "skipped": skipped_entries(results),
    }


def skipped_entries(results: list) -> list:
    return [{"lens": result.lens, "reason": result.reason} for result in results if result.reason is not None]


def exit_code(results: list) -> int:
    """
    Args:
        results: Every lens result of the review.

    Returns:
        2 when a lens had a tool error, else 1 with findings, else 0, as
        `quality check` exits.
    """
    if any(result.error is not None for result in results):
        return EXIT_ERROR
    return EXIT_FINDINGS if any(result.findings for result in results) else EXIT_CLEAN
