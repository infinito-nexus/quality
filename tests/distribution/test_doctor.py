import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from quality.db import tree_digest, write_manifest
from quality.doctor import diagnose
from tests.distribution.support import ROOT, built, needs_nix, tools
from tests.integration.support import quality, write_shim

VERSION = "1.2.3"


def fresh_bundle(root: Path) -> Path:
    for name in ("trivy", "osv"):
        (root / name).mkdir(parents=True)
        (root / name / "data").write_text(name, encoding="utf-8")
    write_manifest(root, datetime.now(timezone.utc), tree_digest(root))
    return root


def shims(directory: Path, versions: dict) -> dict:
    """
    Args:
        directory: Directory for one shim per tool.
        versions: Tool name to the version its shim prints.

    Returns:
        The pin manifest naming each shim and its version.
    """
    pins = {}
    for name, version in versions.items():
        write_shim(directory, name, f"echo '{name} version {version}'")
        pins[name] = {"package": name, "version": version, "path": str(directory / name), "licences": ["MIT"]}
    return pins


def every_tool() -> list:
    return ["git", *tools()]


@pytest.fixture
def setup(tmp_path):
    directory = tmp_path / "bin"
    pins = shims(directory, {name: VERSION for name in every_tool()})
    pins_path = tmp_path / "pins.json"
    pins_path.write_text(json.dumps(pins), encoding="utf-8")
    return directory, pins, pins_path, fresh_bundle(tmp_path / "db")


def test_doctor_lists_every_tool_with_its_version(setup):
    directory, _pins, pins_path, bundle = setup
    lines, gaps = diagnose(None, str(bundle), {"PATH": str(directory)}, pins_path)
    assert gaps == []
    for name in every_tool():
        assert f"{name} {VERSION} {directory / name}" in lines
    assert lines[-1].startswith("vulnerability database: ")


@pytest.mark.parametrize(
    "change, gap",
    [
        (lambda directory, _pins: write_shim(directory, "ruff", "echo 'ruff 9.9.9'"), "ruff: pinned 1.2.3, but `ruff --version` reports 9.9.9"),
        (lambda directory, _pins: write_shim(directory, "trivy", f"echo 'Version: {VERSION}0'"), "trivy: pinned 1.2.3, but `trivy --version` reports 1.2.30"),
        (lambda directory, _pins: (directory / "jscpd").unlink(), "jscpd: missing tool"),
        (lambda directory, _pins: write_shim(directory, "lizard", "exit 3"), "lizard: `lizard --version` exited 3"),
        (lambda _directory, pins: pins.pop("semgrep"), "semgrep: no pinned version"),
        (lambda _directory, pins: pins.pop("git"), "git: no pinned version"),
        (lambda _directory, pins: pins["ruff"].pop("path"), "ruff: malformed pin, needs a version and a path"),
        (lambda _directory, pins: pins["ruff"].update(version=1), "ruff: malformed pin, needs a version and a path"),
        (lambda _directory, pins: pins.update(ruff=VERSION), "ruff: malformed pin, needs a version and a path"),
        (lambda _directory, pins: pins["gitleaks"].update(path="/nix/store/x-gitleaks/bin/gitleaks"), "gitleaks: resolves to"),
    ],
)
def test_doctor_names_each_gap(setup, change, gap):
    directory, pins, pins_path, bundle = setup
    change(directory, pins)
    pins_path.write_text(json.dumps(pins), encoding="utf-8")
    _lines, gaps = diagnose(None, str(bundle), {"PATH": str(directory)}, pins_path)
    assert any(line.startswith(gap) for line in gaps), gaps
    assert len(gaps) == 1, gaps


def test_doctor_names_every_tool_of_an_empty_manifest(setup):
    directory, _pins, pins_path, bundle = setup
    pins_path.write_text("{}", encoding="utf-8")
    _lines, gaps = diagnose(None, str(bundle), {"PATH": str(directory)}, pins_path)
    assert sorted(gaps) == sorted(f"{name}: no pinned version" for name in every_tool())


def test_doctor_names_a_manifest_that_is_no_object(setup):
    directory, pins, pins_path, bundle = setup
    pins_path.write_text(json.dumps(list(pins.values())), encoding="utf-8")
    _lines, gaps = diagnose(None, str(bundle), {"PATH": str(directory)}, pins_path)
    assert gaps == [f"no pinned versions: {pins_path} holds no JSON object"]


def test_doctor_names_a_missing_database_and_manifest(setup, tmp_path):
    directory, _pins, _pins_path, _bundle = setup
    _lines, gaps = diagnose(None, str(tmp_path / "none"), {"PATH": str(directory)}, tmp_path / "pins.missing")
    assert gaps[0].startswith("no pinned versions: ")
    assert gaps[-1].startswith("vulnerability database: no vulnerability database at ")


def test_doctor_without_path_names_every_tool_missing(setup):
    _directory, _pins, pins_path, bundle = setup
    lines, gaps = diagnose(None, str(bundle), {}, pins_path)
    assert gaps[0] == "environment is missing key 'PATH'"
    assert sorted(gaps[1:]) == sorted(f"{name}: missing tool" for name in every_tool())
    assert lines[0].startswith("quality ")


@needs_nix
def test_built_doctor_runs_under_env_i(tmp_path):
    quality = built("default") / "bin" / "quality"
    bundle = fresh_bundle(tmp_path / "db")
    result = subprocess.run(["env", "-i", str(quality), "doctor", "--db", str(bundle)], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    pins = json.loads(next(built("default").glob("lib/python*/site-packages/quality/pins.json")).read_text(encoding="utf-8"))
    for name in every_tool():
        assert f"{name} {pins[name]['version']} {pins[name]['path']}" in result.stdout.splitlines(), name
    unset = subprocess.run(["env", "-i", str(quality), "doctor"], capture_output=True, text=True, check=False)
    assert unset.returncode == 2
    assert "quality: gap: vulnerability database: environment is missing key 'XDG_CACHE_HOME'" in unset.stderr
    assert unset.stdout.splitlines()[:-1] == result.stdout.splitlines()[:-1]


def test_doctor_is_a_subcommand(setup):
    directory, _pins, _pins_path, bundle = setup
    result = quality(ROOT, "doctor", "--db", str(bundle), path_value=str(directory))
    assert result.returncode == 2
    assert "quality: gap: no pinned versions: " in result.stderr
    assert f"ruff {VERSION} {directory / 'ruff'}" in result.stdout.splitlines()
