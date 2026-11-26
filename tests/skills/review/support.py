import importlib
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src"
SCRIPTS = ROOT / "skills" / "kvb-quality-review" / "scripts"
REVIEW = SCRIPTS / "review.py"
EXCEPTIONS = SCRIPTS / "exceptions.py"


def module(name: str):
    """
    Args:
        name: A module of the reviewer package beside review.py.

    Returns:
        The imported module, with the scripts folder on sys.path as running
        review.py puts it there.
    """
    if str(SCRIPTS) not in sys.path:
        sys.path.insert(0, str(SCRIPTS))
    return importlib.import_module(f"reviewer.{name}")


def run_review(cwd: Path, *argv: str) -> subprocess.CompletedProcess:
    return run(REVIEW, cwd, *argv)


def run(script: Path, cwd: Path, *argv: str) -> subprocess.CompletedProcess:
    """
    Args:
        script: A script of kvb-quality-review.
        cwd: Directory it runs in.
        argv: Its command line.

    Returns:
        The finished process, run by this interpreter with the checkout's
        quality package.
    """
    return subprocess.run(
        [sys.executable, "-B", str(script), *argv],
        cwd=cwd,
        env={"PATH": os.environ["PATH"], "PYTHONPATH": str(SRC)},
        capture_output=True,
        text=True,
        check=False,
    )


def finding(path: str, line: int | None) -> dict:
    """
    Args:
        path: Repository path of the finding.
        line: Its line, or None.

    Returns:
        A review finding of the quality lens with every contract key.
    """
    return {
        "lens": "quality",
        "rule": "coding.unused-import",
        "severity": "medium",
        "path": path,
        "line": line,
        "message": "Imported name is never used",
        "commit": None,
        "tier": "fast",
        "blob": None,
    }
