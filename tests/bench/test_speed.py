import os
import subprocess
import tempfile
import time

import pytest

from tests.bench.support import core_dir, require_quiet_host, setting
from tests.distribution.support import built, clean_env
from tests.integration.support import DEEP_TOOLS

BUDGET_S = 360
CPUS = 20


def test_all_on_core_with_the_deep_tier_stays_within_its_budget():
    core = core_dir()
    database = setting("QUALITY_DB_DIR")
    offered = len(os.sched_getaffinity(0))
    if offered < CPUS:
        pytest.skip(f"the budget holds for {CPUS} CPUs, this process may use {offered}")
    quality = built("default") / "bin" / "quality"
    argv = [str(quality), "check", "--all", "--verbose", "--db", database, "--threads", str(CPUS)]
    require_quiet_host("before")
    started = time.monotonic()
    result = subprocess.run(
        argv,
        cwd=core,
        env={**clean_env(), "TMPDIR": tempfile.gettempdir()},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    elapsed = time.monotonic() - started
    assert result.returncode in (0, 1), result.stderr
    for tool in DEEP_TOOLS:
        assert f"tool {tool}:" in result.stderr, tool
    require_quiet_host("after")
    assert elapsed <= BUDGET_S, f"{elapsed:.1f} s"
