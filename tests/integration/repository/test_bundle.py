import shutil
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from quality.db import OSV_DIR, TRIVY_DIR, open_bundle, tree_digest, write_manifest
from tests.integration.repository.support import VULNERABLE
from tests.integration.support import (
    LAUNCHER,
    RULES,
    TEST_DB,
    VULNERABLE_PIN,
    path_with,
    quality,
    report,
    rules_with_enforcers,
    rules_without_pending,
    write_shim,
)
from tests.service.support import load_launcher


def max_age_days() -> int:
    return yaml.safe_load((RULES / "limits.yml").read_text(encoding="utf-8"))["db_max_age_days"]


@pytest.mark.deep
def test_db_missing_exits_2(target, tmp_path):
    target.write("a.py", "x = 1\n")
    target.commit()
    target.write("b.py", "y = 1\n")
    target.stage()
    missing = tmp_path / "no-db"
    empty_cache = {"XDG_CACHE_HOME": str(tmp_path / "empty-cache")}
    for flags in (("--base", "main"), ("--all",)):
        for result in (
            target.check(*flags, "--db", str(missing)),
            target.check(*flags, extra_env=empty_cache),
        ):
            assert result.returncode == 2
            assert "quality db update" in result.stderr
    unset = target.check("--all", extra_env={"XDG_CACHE_HOME": ""})
    assert unset.returncode == 2
    assert "XDG_CACHE_HOME" in unset.stderr
    assert target.check("--staged", "--db", str(missing)).returncode == 0
    assert target.check("--staged", extra_env=empty_cache).returncode == 0


def small_bundle(root: Path, date: datetime) -> str:
    (root / TRIVY_DIR / "db").mkdir(parents=True)
    (root / TRIVY_DIR / "db" / "trivy.db").write_bytes(b"trivy")
    (root / OSV_DIR).mkdir()
    digest = tree_digest(root)
    write_manifest(root, date, digest)
    return digest


@pytest.mark.deep
def test_db_too_old_exits_2(target, tmp_path):
    target.write("a.py", "x = 1\n")
    target.commit()
    limit = timedelta(days=max_age_days())
    now = datetime.now(timezone.utc)
    old = tmp_path / "old"
    small_bundle(old, now - limit - timedelta(minutes=1))
    result = target.check("--base", "main", "--db", str(old))
    assert result.returncode == 2
    assert f"older than {limit.days} days" in result.stderr
    assert "quality db update" in result.stderr
    recent = tmp_path / "recent"
    digest = small_bundle(recent, now - limit + timedelta(minutes=5))
    result = target.check("--base", "main", "--db", str(recent))
    assert result.returncode == 0, result.stderr
    assert digest in result.stdout


@pytest.mark.deep
@pytest.mark.parametrize(
    ("linked", "refusal"),
    [(False, "does not match its digest"), (True, "which is no regular file")],
    ids=["added", "linked"],
)
def test_bundle_content_must_match_its_digest(target, tmp_path, linked, refusal):
    rules = rules_with_enforcers(tmp_path / "rules", VULNERABLE, {"lockfile"})
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    target.write("requirements.txt", VULNERABLE_PIN)
    target.commit()
    tampered = tmp_path / "tampered"
    small_bundle(tampered, datetime.now(timezone.utc))
    clean = tmp_path / "clean"
    clean.mkdir()
    with zipfile.ZipFile(clean / "all.zip", "w") as archive:
        archive.writestr("PYSEC-0000-0.json", '{"id": "PYSEC-0000-0", "affected": []}')
    ecosystems = tampered / OSV_DIR / "osv-scalibr"
    ecosystems.mkdir()
    if linked:
        (ecosystems / "PyPI").symlink_to(clean)
    else:
        shutil.copytree(clean, ecosystems / "PyPI")
    result = target.check("--base", "main", "--rules", str(rules), "--db", str(tampered))
    assert result.returncode == 2
    assert refusal in result.stderr
    assert "quality db update" in result.stderr


@pytest.mark.deep
def test_hosted_scan_command_reads_the_bundle_it_names(target, tmp_path):
    note = open_bundle(TEST_DB, max_age_days(), datetime.now(timezone.utc)).note()
    write_shim(tmp_path / "shims", "quality", 'exec "$PYTHON" -I -B -c "$LAUNCHER" "$@"')
    target.write("a.py", "import os\n")
    target.commit()
    env = {
        "PATH": path_with(tmp_path / "shims"),
        "HOME": str(tmp_path),
        "XDG_CACHE_HOME": str(tmp_path),
        "TMPDIR": tempfile.gettempdir(),
        "PYTHON": sys.executable,
        "LAUNCHER": LAUNCHER,
    }
    argv = [*load_launcher().SCAN_COMMAND, str(target.path), str(TEST_DB)]
    result = subprocess.run(argv, env=env, capture_output=True, text=True, check=False)
    document = report(result)
    assert note in document["notes"]
    assert "coding.unused-import" in {item["rule"] for item in document["findings"]}


def test_db_update_refuses_a_bundle_it_cannot_swap_whole(target, tmp_path):
    mount = tmp_path / "ro" / "db"
    mount.mkdir(parents=True)
    (tmp_path / "ro").chmod(0o555)
    try:
        result = quality(target.path, "db", "update", "--db", str(mount))
    finally:
        (tmp_path / "ro").chmod(0o755)
    assert result.returncode == 2
    assert f"cannot stage the update next to {mount}" in result.stderr
    assert "Traceback" not in result.stderr
    assert list(mount.iterdir()) == []


@pytest.mark.deep
def test_report_names_db(target, tmp_path):
    note = open_bundle(TEST_DB, max_age_days(), datetime.now(timezone.utc)).note()
    target.write("a.py", "x = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    target.write("b.py", "import os\n")
    target.commit()
    reduced = rules_without_pending(tmp_path / "rules", True)
    for flags in (("--base", "main"), ("--all", "--rules", str(reduced))):
        assert note in target.check(*flags).stdout.splitlines()
        assert note in report(target.check(*flags, "--json"))["notes"]
    target.write("c.py", "y = 1\n")
    target.stage()
    assert "vulnerability database" not in target.check("--staged").stdout


def test_hosted_launcher_accepts_the_real_report(target):
    target.write(".qualityignore.yml", "- rule: clean.file-lines\n  paths: [big.py]\n  reason: fixture\n")
    target.write("big.py", "x = 1\n" * 501)
    target.write("a.py", "import os\nimport sys  # nocheck: coding.unused-import -- fixture\n")
    target.write("gap.ts", "interface I<in out T> {\n  f(x: T): T;\n}\n")
    target.commit()
    document = report(target.check("--all", "--json"))
    assert document["findings"] and document["ignored"] and document["nocheck"]
    assert document["parse_incomplete"] == ["gap.ts"]
    assert load_launcher().fits(document, load_launcher().REPORT)
