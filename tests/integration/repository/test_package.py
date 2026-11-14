import os
import shutil
import subprocess
import sys
import tempfile
import tomllib
import zipfile
from pathlib import Path

import pytest

from tests.distribution.support import SYSTEM, copy_of, needs_nix, nix_eval
from tests.integration.support import (
    DEEP_TOOLS,
    ROOT,
    TEST_DB,
    catalogue,
    git,
    pending_tools,
    report,
    rules_without_pending,
)

SERVICE_PATHS = ("service/web/", "ansible/roles/web-app-cst-quality-check/")


def project() -> dict:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def tracked_files() -> list:
    listing = git(ROOT, "ls-files", "-c", "-z").stdout
    return [name for name in listing.split("\0") if name]


def copy_of_this_repository(destination: Path) -> None:
    for name in tracked_files():
        source = ROOT / name
        if source.is_file():
            target_file = destination / name
            target_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target_file)


@pytest.fixture(scope="module")
def wheel(tmp_path_factory) -> Path:
    work = tmp_path_factory.mktemp("wheel")
    copy = work / "copy"
    copy_of_this_repository(copy)
    for path in SERVICE_PATHS:
        planted = copy / path / "planted.py"
        planted.parent.mkdir(parents=True, exist_ok=True)
        planted.write_text("x = 1\n", encoding="utf-8")
    dist = work / "dist"
    subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--no-isolation", "--outdir", dist, copy],
        check=True,
        capture_output=True,
    )
    return next(dist.glob("kvb_quality-*.whl"))


def test_license_is_mit():
    text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert text.startswith("MIT License")
    assert "Permission is hereby granted, free of charge" in text
    assert project()["project"]["license"] == "MIT"


def test_name_and_script():
    assert project()["project"]["name"] == "kvb-quality"
    assert project()["project"]["scripts"] == {"quality": "quality.cli:main"}


def test_mirrors_list_the_right_project():
    lines = (ROOT / "MIRRORS").read_text(encoding="utf-8").splitlines()
    assert lines[0] == "git@github.com:infinito-nexus/quality.git"
    assert "https://pypi.org/project/kvb-quality/" in lines
    assert "https://pypi.org/project/quality/" not in lines


def test_dependencies_are_only_pyyaml_and_pathspec():
    assert sorted(project()["project"]["dependencies"]) == ["PyYAML", "pathspec"]


def test_package_excludes_service(wheel):
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        entry_points = next(name for name in names if name.endswith("entry_points.txt"))
        assert "quality = quality.cli:main" in archive.read(entry_points).decode()
    assert "quality/cli.py" in names
    assert "quality/rules/tools.yml" in names
    assert "quality/rules/semgrep/javascript.yml" in names
    leaked = [name for name in names if "service" in name or "ansible" in name or "planted" in name]
    assert leaked == []


@needs_nix
def test_package_excludes_service_from_image(tmp_path):
    attribute = f"packages.{SYSTEM}.image.drvPath"
    image = nix_eval(ROOT, attribute)
    planted = copy_of(ROOT, tmp_path / "planted")
    for path in SERVICE_PATHS:
        (planted / path / "planted.py").write_text("x = 1\n", encoding="utf-8")
    assert nix_eval(planted, attribute) == image
    control = copy_of(ROOT, tmp_path / "control")
    (control / "src" / "quality" / "planted.py").write_text("x = 1\n", encoding="utf-8")
    assert nix_eval(control, attribute) != image
    source = Path(nix_eval(ROOT, f"packages.{SYSTEM}.default.src"))
    assert sorted(path.name for path in source.iterdir()) == ["LICENSE", "README.md", "pyproject.toml", "rules", "src"]
    assert [path for path in source.rglob("*") if "service" in path.name or "ansible" in path.name] == []


@pytest.mark.deep
def test_wheel_runs_from_its_packaged_rules(wheel, target, tmp_path):
    unpacked = tmp_path / "unpacked"
    with zipfile.ZipFile(wheel) as archive:
        archive.extractall(unpacked)
    target.write("a.py", "import os\n")
    target.write("app.js", "new Function(location.hash)();\n")
    target.commit()
    launcher = (
        "import sys\n"
        f"sys.path.insert(0, {str(unpacked)!r})\n"
        "from quality.cli import main\n"
        "sys.exit(main(sys.argv[1:]))\n"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", launcher, "check", "--all", "--db", str(TEST_DB)],
        cwd=target.path,
        env={"PATH": os.environ["PATH"], "TMPDIR": tempfile.gettempdir()},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1, result.stderr
    assert "coding.unused-import" in result.stdout
    assert "security.static-analysis" in result.stdout


@pytest.mark.deep
def test_all_on_this_repository(target):
    pending = pending_tools()
    if pending:
        pytest.skip(f"pending rules need {', '.join(pending)}: phase C adds their adapters")
    copy_of_this_repository(target.path)
    target.commit()
    assert target.check("--all").returncode == 0


@pytest.mark.deep
def test_all_on_this_repository_reports_what_it_cannot_claim(target, tmp_path):
    copy_of_this_repository(target.path)
    target.commit()
    result = target.check("--all", "--json")
    document = report(result)
    pending = sorted(rule["id"] for rule in catalogue() if rule.get("pending"))
    assert document["findings"] == []
    assert [note for note in document["notes"] if note.startswith("parse incomplete:")] == []
    assert result.returncode == (2 if pending else 0)
    assert [entry for entry in document["ignored"] if entry["rule"] == "coding.dockerfile"] == []
    assert {"path": "service/dev/Dockerfile", "line": 2, "rule": "coding.dockerfile"} in (
        document["nocheck"]
    )
    assert sorted(document["incomplete"]) == pending
    assert "security.secret" not in pending
    assert "coding.dockerfile" not in pending
    reduced = rules_without_pending(tmp_path / "rules", True)
    verbose = target.check("--all", "--verbose", "--rules", str(reduced))
    assert verbose.returncode == 0, verbose.stdout
    for tool in ("gitleaks", "hadolint"):
        assert f"tool {tool}: exit 0" in verbose.stderr
    for tool in DEEP_TOOLS:
        assert f"tool {tool}:" in verbose.stderr
