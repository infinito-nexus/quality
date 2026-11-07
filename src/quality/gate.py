import re
from collections import Counter
from dataclasses import dataclass

from quality.ruledata import Rule

PATH_TOKEN = re.compile(r"[^\s`'\"]*/[^\s`'\"]*")
DIGITS = re.compile(r"\d+")
PATH_PLACEHOLDER = "<path>"


@dataclass(frozen=True, repr=False, eq=False)
class Hit:
    rule: Rule
    path: str
    line: int | None
    message: str
    source: str
    value: int | None
    entity: str
    commit: str | None


def code_hit(rule: Rule, path: str, row: int | None, message: str, snapshot) -> Hit:
    """
    Args:
        rule: Catalogue rule.
        path: Path relative to the snapshot root.
        row: Line number, ignored for file-level rules.
        message: Tool message; it stays in memory and is never printed.
        snapshot: Snapshot holding the source line of the fingerprint.

    Returns:
        The finding.
    """
    line = None if rule.file_level or row is None else row
    source = "" if line is None else snapshot.source_key(path, line)
    return Hit(rule, path, line, message, source, None, "", None)


def metric_hit(rule: Rule, path: str, row: int | None, value: int, entity: str) -> Hit:
    return Hit(rule, path, row, "", "", value, entity, None)


def normalise_message(message: str) -> str:
    return DIGITS.sub("0", PATH_TOKEN.sub(PATH_PLACEHOLDER, message))


def fingerprint(hit: Hit) -> tuple:
    return (hit.rule.id, hit.source)


def per_file_key(hit: Hit, path: str) -> tuple:
    return (path, hit.rule.id, normalise_message(hit.message))


def metric_key(hit: Hit, path: str) -> tuple:
    return (hit.rule.id, path, hit.entity)


@dataclass(frozen=True, repr=False)
class Baseline:
    fingerprints: Counter
    per_file: Counter
    metrics: dict


def baseline_of(hits: list, renames: dict) -> Baseline:
    """
    Args:
        hits: Findings of that side, unsuppressed.
        renames: Map of base path to head path.

    Returns:
        The multisets and metric values the head side is compared with.
    """
    fingerprints = Counter()
    per_file = Counter()
    metrics = {}
    for hit in hits:
        path = renames.get(hit.path, hit.path)
        if hit.rule.metric is not None:
            metrics.setdefault(metric_key(hit, path), []).append(hit.value)
        else:
            fingerprints[fingerprint(hit)] += 1
            per_file[per_file_key(hit, path)] += 1
    for values in metrics.values():
        values.sort(reverse=True)
    return Baseline(fingerprints, per_file, metrics)


def merge_baselines(baselines: list) -> Baseline:
    """
    Args:
        baselines: One baseline per parent.

    Returns:
        The per-key maximum, so that a finding in either parent counts as known.
    """
    fingerprints = Counter()
    per_file = Counter()
    metrics = {}
    for baseline in baselines:
        fingerprints |= baseline.fingerprints
        per_file |= baseline.per_file
        for key, values in baseline.metrics.items():
            metrics[key] = pointwise_maximum(metrics.get(key, []), values)
    return Baseline(fingerprints, per_file, metrics)


def pointwise_maximum(left: list, right: list) -> list:
    longer, shorter = (left, right) if len(left) >= len(right) else (right, left)
    return [
        max(value, shorter[index]) if index < len(shorter) else value
        for index, value in enumerate(longer)
    ]


def new_fingerprint_hits(hits: list, baseline: Baseline) -> list:
    fingerprint_rise = Counter(fingerprint(hit) for hit in hits)
    fingerprint_rise.subtract(baseline.fingerprints)
    file_rise = Counter(per_file_key(hit, hit.path) for hit in hits)
    file_rise.subtract(baseline.per_file)
    ordered = sorted(hits, key=lambda hit: (hit.path, hit.line or 0), reverse=True)
    new = []
    for hit in ordered:
        print_key = fingerprint(hit)
        file_key = per_file_key(hit, hit.path)
        if fingerprint_rise[print_key] > 0 and file_rise[file_key] > 0:
            fingerprint_rise[print_key] -= 1
            file_rise[file_key] -= 1
            new.append(hit)
    return new


def new_metric_hits(hits: list, baseline: Baseline) -> list:
    positions = Counter()
    new = []
    for hit in sorted(hits, key=lambda item: item.value, reverse=True):
        key = metric_key(hit, hit.path)
        known = baseline.metrics.get(key, [])
        index = positions[key]
        positions[key] += 1
        if index >= len(known) or hit.value > known[index]:
            new.append(hit)
    return new


def new_hits(hits: list, baseline: Baseline) -> list:
    """
    Args:
        hits: Non-hard findings on the head side.
        baseline: Merged baseline of every parent.

    Returns:
        Fingerprint findings whose fingerprint count and per-file count both
        rose, and metric findings that grew or are new.
    """
    plain = [hit for hit in hits if hit.rule.metric is None]
    metric = [hit for hit in hits if hit.rule.metric is not None]
    return new_fingerprint_hits(plain, baseline) + new_metric_hits(metric, baseline)
