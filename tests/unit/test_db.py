import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from quality import QualityError, db
from quality.modes import tool_environment
from quality.ruledata import load

RULES = Path(__file__).resolve().parents[2] / "rules"
NOW = datetime(2026, 11, 11, 12, 0, 0, tzinfo=timezone.utc)


def bundle_at(root: Path, date: datetime) -> Path:
    (root / db.TRIVY_DIR / "db").mkdir(parents=True)
    (root / db.TRIVY_DIR / "db" / "trivy.db").write_bytes(b"trivy")
    (root / db.OSV_DIR).mkdir()
    db.write_manifest(root, date, db.tree_digest(root))
    return root


def test_location_prefers_option_then_xdg_then_home(tmp_path):
    assert db.location(str(tmp_path / "x"), {}) == tmp_path / "x"
    cache = {"XDG_CACHE_HOME": "/c", "HOME": "/h"}
    assert db.location(None, cache) == Path("/c/quality/db")
    assert db.location(None, {"XDG_CACHE_HOME": "rel", "HOME": "/h"}) == Path(
        "/h/.cache/quality/db"
    )


def test_location_without_any_root_names_the_key():
    with pytest.raises(QualityError, match="XDG_CACHE_HOME"):
        db.location(None, {"HOME": "relative"})


def test_missing_bundle_names_the_update_command(tmp_path):
    with pytest.raises(QualityError, match="quality db update"):
        db.open_bundle(tmp_path / "absent", 7, NOW)


def test_bundle_age_limit(tmp_path):
    limit = timedelta(days=7)
    fresh = db.open_bundle(bundle_at(tmp_path / "fresh", NOW - limit), 7, NOW)
    assert fresh.date == NOW - limit
    with pytest.raises(QualityError, match="older than 7 days.*quality db update"):
        db.open_bundle(bundle_at(tmp_path / "old", NOW - limit - timedelta(seconds=1)), 7, NOW)


def test_note_names_date_and_digest(tmp_path):
    bundle = db.open_bundle(bundle_at(tmp_path / "b", NOW), 7, NOW)
    assert bundle.note() == f"vulnerability database: 2026-11-11T12:00:00Z {bundle.digest}"
    assert bundle.digest.startswith("sha256:")


@pytest.mark.parametrize(
    "manifest",
    ["not json", '{"format": 99, "date": "2026-11-11T12:00:00Z", "digest": "d"}', '{"format": 1}'],
)
def test_unreadable_manifest_fails_closed(tmp_path, manifest):
    (tmp_path / db.MANIFEST).write_text(manifest, encoding="utf-8")
    with pytest.raises(QualityError, match="quality db update"):
        db.open_bundle(tmp_path, 7, NOW)


def test_future_dated_bundle_refused(tmp_path):
    root = bundle_at(tmp_path / "b", NOW + timedelta(seconds=1))
    with pytest.raises(QualityError, match="in the future.*quality db update"):
        db.open_bundle(root, 7, NOW)


def test_content_must_match_the_manifest_digest(tmp_path):
    root = bundle_at(tmp_path / "b", NOW)
    (root / db.TRIVY_DIR / "db" / "trivy.db").write_bytes(b"other")
    with pytest.raises(QualityError, match="does not match its digest.*quality db update"):
        db.open_bundle(root, 7, NOW)
    empty = tmp_path / "manifest-only"
    empty.mkdir()
    db.write_manifest(empty, NOW, db.tree_digest(root))
    with pytest.raises(QualityError, match="does not match its digest.*quality db update"):
        db.open_bundle(empty, 7, NOW)


@pytest.mark.parametrize("linked", ["PyPI", "all.zip"])
def test_a_link_anywhere_in_the_bundle_is_refused(tmp_path, linked):
    root = bundle_at(tmp_path / "b", NOW)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "all.zip").write_bytes(b"zip")
    (root / db.OSV_DIR / "PyPI").mkdir()
    link = root / db.OSV_DIR / "PyPI" / "all.zip"
    if linked == "PyPI":
        (root / db.OSV_DIR / "PyPI").rmdir()
        link = root / db.OSV_DIR / "PyPI"
    link.symlink_to(elsewhere if linked == "PyPI" else elsewhere / "all.zip")
    with pytest.raises(QualityError, match="holds osv/PyPI.*no regular file.*quality db update"):
        db.open_bundle(root, 7, NOW)


def test_a_linked_bundle_directory_is_refused(tmp_path):
    root = bundle_at(tmp_path / "b", NOW)
    link = tmp_path / "link"
    link.symlink_to(root)
    with pytest.raises(QualityError, match="is a link.*point --db at the directory itself"):
        db.open_bundle(link, 7, NOW)
    assert db.open_bundle(root, 7, NOW).digest.startswith("sha256:")


def test_a_link_above_the_bundle_is_resolved_once_at_open(tmp_path):
    verified = bundle_at(tmp_path / "verified" / "db", NOW).resolve()
    forged = tmp_path / "forged" / "db"
    forged.mkdir(parents=True)
    parent = tmp_path / "parent-link"
    parent.symlink_to(verified.parent)
    bundle = db.open_bundle(parent / "db", 7, NOW)
    parent.unlink()
    parent.symlink_to(forged.parent)
    assert bundle.trivy_cache() == verified / db.TRIVY_DIR
    scan = tool_environment("/bin", tmp_path, bundle)
    assert scan["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"] == str(verified / db.OSV_DIR)


def fake_fetch(work: Path, *_args) -> None:
    (work / db.TRIVY_DIR / "db").mkdir(parents=True, exist_ok=True)
    (work / db.TRIVY_DIR / "db" / "trivy.db").write_bytes(b"trivy")
    (work / db.OSV_DIR).mkdir(exist_ok=True)


def test_update_stages_beside_the_bundle_inside_a_read_only_tree(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "fetch_trivy", fake_fetch)
    monkeypatch.setattr(db, "fetch_osv", fake_fetch)
    mount = tmp_path / "ro" / "db"
    mount.mkdir(parents=True)
    (tmp_path / "ro").chmod(0o555)
    try:
        with pytest.raises(QualityError, match="cannot stage the update next to .*point --db at a directory inside"):
            db.update(mount, load(RULES), os.environ["PATH"], {})
        db.update(mount / "bundle", load(RULES), os.environ["PATH"], {})
        db.update(mount / "bundle", load(RULES), os.environ["PATH"], {})
    finally:
        (tmp_path / "ro").chmod(0o755)
    assert [path.name for path in mount.iterdir()] == ["bundle"]
    assert db.open_bundle(mount / "bundle", 7, datetime.now(timezone.utc)).handle is not None


def test_open_bundle_keeps_update_from_swapping_it(tmp_path):
    root = bundle_at(tmp_path / "db", NOW)
    bundle = db.open_bundle(root, 7, NOW)
    work = bundle_at(tmp_path / "work", NOW)
    with pytest.raises(QualityError, match="in use by a running check"):
        db.replace_bundle(work, root)
    assert work.is_dir()
    bundle.handle.close()
    db.replace_bundle(work, root)
    assert not work.exists()


def test_digest_covers_content_not_manifest(tmp_path):
    root = bundle_at(tmp_path / "b", NOW)
    before = db.tree_digest(root)
    db.write_manifest(root, NOW - timedelta(days=1), "other")
    assert db.tree_digest(root) == before
    (root / db.OSV_DIR / "PyPI").mkdir()
    (root / db.OSV_DIR / "PyPI" / "all.zip").write_bytes(b"zip")
    assert db.tree_digest(root) != before


def test_update_refuses_a_foreign_directory(tmp_path):
    foreign = tmp_path / "home"
    foreign.mkdir()
    (foreign / "notes.txt").write_text("keep", encoding="utf-8")
    with pytest.raises(QualityError, match="holds no vulnerability database"):
        db.update(foreign, load(RULES), os.environ["PATH"], {})
    assert (foreign / "notes.txt").read_text(encoding="utf-8") == "keep"


def test_failed_fetch_keeps_the_old_bundle(tmp_path):
    root = bundle_at(tmp_path / "db", NOW)
    before = db.tree_digest(root)
    shims = tmp_path / "shims"
    shims.mkdir()
    trivy = shims / "trivy"
    trivy.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    trivy.chmod(0o755)
    with pytest.raises(QualityError, match="trivy could not fetch"):
        db.update(root, load(RULES), str(shims), {})
    assert db.tree_digest(root) == before
    assert sorted(path.name for path in tmp_path.iterdir()) == ["db", "shims"]


def test_network_env_passes_only_proxy_and_certificates(tmp_path):
    environ = {"HTTPS_PROXY": "http://proxy", "SSL_CERT_FILE": "/ca", "GITHUB_TOKEN": "t"}
    env = db.network_env("/bin", tmp_path, environ)
    assert env["HTTPS_PROXY"] == "http://proxy"
    assert env["SSL_CERT_FILE"] == "/ca"
    assert "GITHUB_TOKEN" not in env


def test_scan_environment_has_no_network_and_no_semgrep_metrics(tmp_path):
    bundle = db.Bundle(tmp_path, NOW, "sha256:x", None)
    env = tool_environment("/bin", tmp_path / "home", bundle)
    assert not set(env) & set(db.NETWORK_VARIABLES)
    assert env["SEMGREP_ENABLE_VERSION_CHECK"] == "0"
    assert env["SEMGREP_SEND_METRICS"] == "off"
    assert env["EIO_BACKEND"] == "posix"
    assert env["HOME"] == str(tmp_path / "home")
    assert env["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"] == str(tmp_path / db.OSV_DIR)
    assert "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY" not in tool_environment("/bin", tmp_path, None)
