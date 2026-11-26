#!/usr/bin/env kvb-quality-python
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import NamedTuple

from launch import TIMED
from ledger import fingerprint
from staging import located

WEIGHTS = {"critical": 50, "high": 25, "medium": 10, "low": 2, "info": 0}
RANK = list(WEIGHTS)
SAFE = 100
SHOWN = 5
COUNTS = ("files_scanned", "lines_scanned")
UNKNOWN = "?"
FAULT = re.compile(rf"{TIMED.pattern}|could not be read and were skipped")
SKIP = re.compile(r"Skipped .+ exceeds .+ limit")


class Unreadable(Exception):
    pass


class Uncovered(Exception):
    pass


class Result(NamedTuple):
    """
    Attributes:
        scanned: the count of files medusa scanned.
        found: the findings that count.
        passed: the findings the accepted-findings ledger accepts.
        missed: the repository paths of the copied files medusa never takes up.
    """

    scanned: int
    found: list
    passed: list
    missed: list


def plural(n: int, noun: str) -> str:
    return f"{n} {noun}{'' if n == 1 else 's'}"


def shown(items: list[str]) -> str:
    return ", ".join(items[:SHOWN]) + (f", +{len(items) - SHOWN} more" if len(items) > SHOWN else "")


def report(reports: Path) -> tuple[str, list, dict]:
    """Returns:
        the name of medusa's newest report in reports, its `findings` list and
        its `scan_summary`; Unreadable when it lacks one of them.
    """
    files = sorted(reports.glob("medusa-scan-*.json")) if reports.is_dir() else []
    if not files:
        raise Unreadable(f"no medusa-scan-*.json in {reports}")
    name = files[-1].name
    try:
        loaded = json.loads(files[-1].read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise Unreadable(f"{name}: {error}") from None
    entries = loaded.get("findings") if isinstance(loaded, dict) else None
    if not isinstance(entries, list):
        raise Unreadable(f"{name} holds no findings list")
    summary = loaded.get("scan_summary")
    if not isinstance(summary, dict) or any(type(summary.get(k)) is not int for k in COUNTS):
        raise Unreadable(f"{name} holds no files_scanned and lines_scanned counts")
    return name, entries, summary


def finding(entry: object, tree: Path, names: dict[str, str]) -> dict | None:
    """Returns:
        one entry of medusa's findings at its repository path, None for one
        without a known severity.
    """
    severity = str(entry.get("severity", "")).lower() if isinstance(entry, dict) else ""
    if severity not in WEIGHTS:
        return None
    line = entry.get("line") if isinstance(entry.get("line"), int) else None
    named = entry.get("file")
    scratch = located(str(named) if named else UNKNOWN, tree)
    sha1, context = fingerprint(tree, scratch, line)
    return {
        "severity": severity,
        "rule": entry.get("rule_id") if isinstance(entry.get("rule_id"), str) else None,
        "path": names.get(scratch, scratch),  # nocheck: clean.default-value -- a finding outside the copied files, as one without a file, keeps the path medusa named
        "line": line,
        "sha1": sha1,
        "context": context,
    }


def order(entry: dict) -> tuple[int, str, int]:
    return RANK.index(entry["severity"]), entry["path"], entry["line"] if entry["line"] is not None else 0


def findings(reports: Path, tree: Path, names: dict[str, str]) -> tuple[list[dict], dict]:
    """Returns:
        the findings of medusa's report at their repository paths, by
        severity, path and line, and its `scan_summary`.
    """
    name, entries, summary = report(reports)
    found = [finding(entry, tree, names) for entry in entries]
    if None in found:
        raise Unreadable(f"{name}: a finding without a known severity")
    return sorted(found, key=order), summary


def uncovered(said: list[str], summary: dict, sizes: dict[str, tuple[int, int, int]]) -> str | None:
    """Returns:
        why medusa never covers the scanned files: its SKIP line, or the count
        it took up when it is not every scanned one, else None.
    """
    for line in said:
        if SKIP.search(line):
            return line
    if summary["files_scanned"] != len(sizes):
        return f"medusa took up {summary['files_scanned']} of {plural(len(sizes), 'file')} its rules take up"
    return None


def cut(code: int, said: list[str], summary: dict, sizes: dict[str, tuple[int, int, int]]) -> str | None:
    """Returns:
        why this run fell short: a non-zero exit, its FAULT line or fewer
        `lines_scanned` than the scanned files hold, else None.
    """
    if code:
        return f"medusa exit {code}"
    for line in said:
        if FAULT.search(line):
            return line
    expected = sum(counted for _, counted, _ in sizes.values())
    if summary["lines_scanned"] != expected:
        return f"medusa counted {summary['lines_scanned']} of {expected} lines"
    return None


def tally(found: list[dict]) -> tuple[dict[str, int], int]:
    """Returns:
        the count of found per severity and the security value: SAFE less
        each finding's weight, at least 0.
    """
    counts = {severity: sum(f["severity"] == severity for f in found) for severity in WEIGHTS}
    return counts, max(0, SAFE - sum(WEIGHTS[s] * n for s, n in counts.items()))


def document(result: Result) -> dict:
    counts, value = tally(result.found)
    return {
        "security": value, "files": result.scanned, **counts, "findings": result.found, "accepted": result.passed,
        "not_covered": result.missed,
    }


def summary_line(result: Result) -> str:
    counts, value = tally(result.found)
    places = [f"{f['severity']} {f['path']}:{f['line'] if f['line'] is not None else UNKNOWN}" for f in result.found]
    detail = f": {shown(places)}" if places else ""
    waived = f", {len(result.passed)} accepted" if result.passed else ""
    rest = f"; not covered: {shown(result.missed)}" if result.missed else ""
    return (
        f"🛡️ security {value} % critical {counts['critical']} (medusa: {plural(len(result.found), 'finding')}{waived} "
        f"in {plural(result.scanned, 'file')}{detail}{rest})"
    )


def exit_code(found: list[dict]) -> int:
    """Returns:
        1 for a critical finding, 3 under SAFE without one, else 0.
    """
    counts, value = tally(found)
    if counts["critical"]:
        return 1
    return 3 if value < SAFE else 0
