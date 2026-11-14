import os
import time
from pathlib import Path

import pytest

CORE_VARIABLE = "QUALITY_CORE_DIR"
STAT = Path("/proc/stat")
QUIET_PERCENT = 50
SAMPLE_S = 5


def core_dir() -> Path:
    """
    Returns:
        The core checkout QUALITY_CORE_DIR names; the test is skipped while
        it is unset.
    """
    value = os.environ.get(CORE_VARIABLE)
    if not value:
        pytest.skip(f"needs {CORE_VARIABLE}, a core checkout the benchmarks only read")
    return Path(value).resolve()


def setting(name: str) -> str:
    """
    Args:
        name: Environment variable a benchmark needs next to QUALITY_CORE_DIR.

    Returns:
        Its value; the test fails while it is unset.
    """
    value = os.environ.get(name)
    if not value:
        pytest.fail(f"{name} is required next to {CORE_VARIABLE}")
    return value


def cpu_ticks() -> list:
    return [int(value) for value in STAT.read_text(encoding="ascii").splitlines()[0].split()[1:9]]


def cpu_busy(seconds: float) -> float:
    """
    Args:
        seconds: Length of the sample.

    Returns:
        Percent of all CPUs busy during the sample, from /proc/stat; iowait counts as idle.
    """
    before = cpu_ticks()
    time.sleep(seconds)
    after = cpu_ticks()
    total = sum(after) - sum(before)
    idle = after[3] + after[4] - before[3] - before[4]
    return 100 * (total - idle) / total


def require_quiet_host(moment: str) -> None:
    """
    Args:
        moment: When the sample is taken, "before" or "after" the timed run.

    Raises:
        pytest.skip.Exception: QUIET_PERCENT or more of the CPUs were busy over SAMPLE_S seconds.
    """
    busy = cpu_busy(SAMPLE_S)
    if busy >= QUIET_PERCENT:
        pytest.skip(f"host {busy:.0f} % busy {moment} the timed run, a budget holds below {QUIET_PERCENT} % only")
