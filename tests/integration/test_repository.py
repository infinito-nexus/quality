import os
import shutil
import subprocess
import sys
import tempfile
import tomllib
import zipfile
from pathlib import Path

import pytest

from tests.integration.support import (
    ROOT,
    Target,
    git,
    pending_tools,
    report,
    rules_without_pending,
)

SERVICE_PATHS = ("service/web/", "ansible/roles/web-app-cst-quality-check/")


def project() -> dict:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def tracked_or_new_files() -> list:
    listing = git(ROOT, "ls-files", "-co", "--exclude-standard", "-z").stdout
    return [name for name in listing.split("\0") if name]


def copy_of_this_repository(destination: Path) -> None:
    for name in tracked_or_new_files():
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
        planted.parent.mkdir(parents=True)
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
    assert lines[0] == "git@github.com:kevinveenbirkenbach/quality.git"
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
    leaked = [name for name in names if "service" in name or "ansible" in name or "planted" in name]
    assert leaked == []


def test_package_excludes_service_from_image():
    pytest.skip("needs nix: the image is built by phase D, this criterion holds for the wheel only")


def test_wheel_runs_from_its_packaged_rules(wheel, target, tmp_path):
    unpacked = tmp_path / "unpacked"
    with zipfile.ZipFile(wheel) as archive:
        archive.extractall(unpacked)
    target.write("a.py", "import os\n")
    target.commit()
    launcher = (
        "import sys\n"
        f"sys.path.insert(0, {str(unpacked)!r})\n"
        "from quality.cli import main\n"
        "sys.exit(main(sys.argv[1:]))\n"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", launcher, "check", "--all"],
        cwd=target.path,
        env={"PATH": os.environ["PATH"], "TMPDIR": tempfile.gettempdir()},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1, result.stderr
    assert "coding.unused-import" in result.stdout


def test_all_on_this_repository(tmp_path):
    missing = [tool for tool in pending_tools() if shutil.which(tool) is None]
    if missing:
        pytest.skip(f"needs {', '.join(missing)}: the deep tier and secret scanner are phase C")
    copy = Target.create(tmp_path / "self")
    copy_of_this_repository(copy.path)
    copy.commit()
    assert copy.check("--all").returncode == 0


def test_all_on_this_repository_reports_what_it_cannot_claim(tmp_path):
    copy = Target.create(tmp_path / "self")
    copy_of_this_repository(copy.path)
    copy.commit()
    result = copy.check("--all", "--json")
    document = report(result)
    assert document["findings"] == []
    assert result.returncode == 2
    assert "security.secret" in document["incomplete"]
    reduced = rules_without_pending(tmp_path / "rules")
    assert copy.check("--all", "--rules", str(reduced)).returncode == 0
