import fcntl
import os
import stat
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from quality import QualityError
from quality.db import NETWORK_VARIABLES, open_bundle
from tests.integration.support import RULES, TEST_CACHE, TEST_DB, Target, quality

WRITE_BITS = stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH


def max_age_days() -> int:
    return yaml.safe_load((RULES / "limits.yml").read_text(encoding="utf-8"))["db_max_age_days"]


def fresh(root: Path) -> bool:
    try:
        open_bundle(root, max_age_days() - 1, datetime.now(timezone.utc))
    except QualityError:
        return False
    return True


def set_writable(root: Path, writable: bool) -> None:
    """
    Args:
        root: Bundle directory.
        writable: True restores owner write access before an update, False takes
            every write bit away, so each scan proves it reads the bundle only.
    """
    if not root.exists():
        return
    for path in [root, *root.rglob("*")]:
        mode = path.stat().st_mode
        path.chmod(mode | stat.S_IWUSR if writable else mode & ~WRITE_BITS)


@pytest.fixture(scope="session")
def vulnerability_database():
    TEST_CACHE.mkdir(exist_ok=True)
    with (TEST_CACHE.parent / "quality-test-cache.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if not fresh(TEST_DB):
            set_writable(TEST_DB, True)
            network = {name: os.environ[name] for name in NETWORK_VARIABLES if name in os.environ}
            result = quality(TEST_CACHE, "db", "update", "--db", str(TEST_DB), extra_env=network)
            assert result.returncode == 0, result.stderr
        set_writable(TEST_DB, False)
    return TEST_DB


@pytest.fixture
def target(tmp_path, request):
    deep = request.node.get_closest_marker("deep") is not None
    if deep:
        request.getfixturevalue("vulnerability_database")
    return Target.create(tmp_path / "repo", deep)


@pytest.fixture(params=["staged", "base"])
def mode(request):
    return request.param
