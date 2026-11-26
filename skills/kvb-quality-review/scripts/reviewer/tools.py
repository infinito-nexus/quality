import hashlib
import importlib
import json
import os
import re
import sys
from pathlib import Path

from quality import QualityError
from quality.process import run

from .document import Result, failed, skipped
from .options import Request
from .target import Change, changed_paths, worktree_blobs

SKILLS = Path(__file__).resolve().parents[3]
SECURITY_SCRIPT = SKILLS / "kvb-quality-security" / "scripts" / "security.py"
MEASURE_SCRIPT = SKILLS / "kvb-quality-performance" / "scripts" / "measure.py"
SECURITY = "security"
PERFORMANCE = "performance"
SECURITY_SECONDS = 2 * 3600
MEASURE_SECONDS = 6 * 3600
VERSION_SECONDS = 60
SCANNED = (0, 1, 3)
UNSCORED = 4
MEASURED = (0, 3)
DIGEST_LENGTH = 16
TALLY_MODULE = "verdict"
BROKEN = (QualityError, ValueError, LookupError, TypeError, AttributeError, ImportError)
MEDUSA_LINE = re.compile(r"^security: medusa (?P<path>.+) from \S+$", re.MULTILINE)
NO_BASE = "{script} compares against a base commit; this change has none"
NOT_IN_WORKTREE = "{script} reads the working tree, which does not hold {target}"
NOT_MEASURED = "runs only with --measure, since it needs a base measurement"


def script_version(script: Path) -> str:
    return f"{script.name} sha256:{hashlib.sha256(script.read_bytes()).hexdigest()[:DIGEST_LENGTH]}"


def unreachable(script: Path, change: Change) -> str | None:
    """
    Args:
        script: The script of a lens that reads the working tree.
        change: The reviewed change.

    Returns:
        Why the script cannot review the change, or None when it can.
    """
    if change.base is None:
        return NO_BASE.format(script=script.name)
    if not change.worktree:
        return NOT_IN_WORKTREE.format(script=script.name, target=change.target)
    return None


def last_line(stream: bytes) -> str:
    lines = stream.decode("utf-8", errors="replace").strip().splitlines()
    return lines[-1] if lines else "no output"


def launched(argv: list, change: Change, seconds: int):
    """
    Args:
        argv: The script and its arguments, run by this interpreter.
        change: The reviewed change; the script runs in its root.
        seconds: Seconds before the script's process group is killed.

    Returns:
        The finished process.

    Raises:
        QualityError: The script could not start, timed out or died from a signal.
    """
    return run([sys.executable, *argv], change.repo.root, dict(os.environ), seconds)


def medusa_version(change: Change, stderr: bytes) -> str:
    """
    Args:
        change: The reviewed change.
        stderr: What security.py printed on stderr, naming the medusa it ran.

    Returns:
        `medusa <its --version line>`, the rule-set version of the scan.
    """
    named = MEDUSA_LINE.search(stderr.decode("utf-8", errors="replace"))
    if named is None:
        return "medusa unnamed by security.py"
    try:
        result = run([named["path"], "--version"], change.repo.root, dict(os.environ), VERSION_SECONDS)
    except QualityError:
        return "medusa version unreadable"
    return f"medusa {last_line(result.stdout)}" if result.code == 0 else "medusa version unreadable"


def security_value(document: dict, found: list) -> int:
    """
    Args:
        document: The JSON of a security.py scan that scored.
        found: Its findings this review keeps.

    Returns:
        The scan's value when it keeps every finding, else the value of the
        kept ones as security.py tallies them.
    """
    if len(found) == len(document["findings"]):
        return document["security"]
    folder = str(SECURITY_SCRIPT.parent)
    if folder not in sys.path:
        sys.path.append(folder)
    return importlib.import_module(TALLY_MODULE).tally(found)[1]


def security_finding(item: dict, blobs: dict) -> dict:
    return {
        "lens": SECURITY,
        "rule": item["rule"],
        "severity": item["severity"],
        "path": item["path"],
        "line": item["line"],
        "message": f"MEDUSA {item['severity']} finding",
        "commit": None,
        "tier": None,
        "blob": blobs.get(item["path"]),
    }


def security_result(request: Request, change: Change) -> Result:
    """
    Args:
        request: The parsed command line.
        change: The reviewed change.

    Returns:
        The security lens: security.py --json over the working tree against
        the change's base. It honours the shared accepted-findings ledger
        itself; a scan it cannot score (exit 4) is skipped with its problem,
        any other failure is a tool error. Findings carry the blob hash of
        the working tree file the scan read.
    """
    reason = unreachable(SECURITY_SCRIPT, change)
    if reason is not None:
        return skipped(SECURITY, reason)
    argv = [str(SECURITY_SCRIPT), "--repo", change.repo.root, "--base", change.base, "--json"]
    try:
        completed = launched(argv, change, SECURITY_SECONDS)
        if completed.code not in (*SCANNED, UNSCORED):
            return failed(SECURITY, f"security.py exit {completed.code}: {last_line(completed.stderr)}")
        document = json.loads(completed.stdout)
        if completed.code == UNSCORED:
            return skipped(SECURITY, f"security.py: {document['problem']}")
        return scanned(request, change, document, completed.stderr)
    except BROKEN as error:
        return failed(SECURITY, f"security.py broke its --json contract or could not run: {error!r}")


def scanned(request: Request, change: Change, document: dict, stderr: bytes) -> Result:
    """
    Args:
        request: The parsed command line.
        change: The reviewed change.
        document: The JSON of a security.py scan that scored.
        stderr: What the scan printed on stderr.

    Returns:
        The security lens of that scan, limited to the files the change
        adds or modifies, since security.py also scans untracked files and
        unstaged edits, and to --path.
    """
    touched = changed_paths(change)
    found = [item for item in document["findings"] if item["path"] in touched and request.covers(item["path"])]
    blobs = worktree_blobs(change.repo, sorted({item["path"] for item in found}))
    findings = [security_finding(item, blobs) for item in found]
    version = f"{script_version(SECURITY_SCRIPT)}; {medusa_version(change, stderr)}"
    return Result(SECURITY, version, findings, {SECURITY: security_value(document, found)}, None, None)


def performance_result(request: Request, change: Change) -> Result:
    """
    Args:
        request: The parsed command line.
        change: The reviewed change.

    Returns:
        The performance lens: measure.py --json runs the command after `--`
        on the base and on the working tree and fills efficiency and speed;
        skipped without --measure.
    """
    if not request.measure:
        return skipped(PERFORMANCE, NOT_MEASURED)
    reason = unreachable(MEASURE_SCRIPT, change)
    if reason is not None:
        return skipped(PERFORMANCE, reason)
    argv = [str(MEASURE_SCRIPT), "--base", change.base, "--json", "--", *request.command]
    try:
        completed = launched(argv, change, MEASURE_SECONDS)
        if completed.code not in MEASURED:
            return failed(PERFORMANCE, f"measure.py exit {completed.code}: {last_line(completed.stderr)}")
        figures = json.loads(completed.stdout)
        scores = {"efficiency": figures["efficiency"], "speed": figures["speed"]}
    except BROKEN as error:
        return failed(PERFORMANCE, f"measure.py broke its --json contract or could not run: {error!r}")
    return Result(PERFORMANCE, script_version(MEASURE_SCRIPT), [], scores, None, None)
