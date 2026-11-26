import hashlib
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = Path("scripts") / "install.sh"
ROOTS = (Path(".claude") / "skills", Path(".agents") / "skills")
CODEX = Path(".codex") / "skills"
PACKAGE = ("pyproject.toml", "README.md", "LICENSE")
PACKAGE_TREES = ("src", "rules")
BUILT = shutil.ignore_patterns("__pycache__", "*.py[co]", "*.egg-info", "build")
VENV = Path(".local") / "share" / "kvb-quality" / "venv"
LAUNCHER = Path(".local") / "bin" / "kvb-quality-python"
OFFLINE = "No matching distribution found for"
SKILL = "---\nname: {name}\ndescription: Fixture skill {name}.\n---\n# {name}\n"


def checkout(base: Path, skills: Path) -> Path:
    """
    Args:
        base: Empty folder the copy is made in.
        skills: Folder copied as the copy's skills/, caches included.

    Returns:
        A copy of this checkout's install script beside those skills.
    """
    repo = base / "repo"
    (repo / SCRIPT).parent.mkdir(parents=True)
    shutil.copy2(ROOT / SCRIPT, repo / SCRIPT)
    shutil.copytree(skills, repo / "skills", symlinks=True)
    return repo


def with_package(repo: Path) -> Path:
    for name in PACKAGE:
        shutil.copy2(ROOT / name, repo / name)
    for name in PACKAGE_TREES:
        shutil.copytree(ROOT / name, repo / name, ignore=BUILT)
    return repo


def fixture_skills(base: Path, names: tuple) -> Path:
    """
    Args:
        base: Folder the skills folder is made in.
        names: Skill names, one folder each with a SKILL.md, an executable
            script and a bytecode cache the install must leave behind.

    Returns:
        The skills folder.
    """
    skills = base / "skills"
    for name in names:
        scripts = skills / name / "scripts"
        (scripts / "__pycache__").mkdir(parents=True)
        (skills / name / "SKILL.md").write_text(SKILL.format(name=name), encoding="utf-8")
        (scripts / "tool.py").write_text("#!/usr/bin/env kvb-quality-python\n", encoding="utf-8")
        (scripts / "tool.py").chmod(0o755)
        (scripts / "__pycache__" / "tool.cpython-312.pyc").write_bytes(b"\x00cache")
    return skills


def install(repo: Path, home: Path, step: str) -> subprocess.CompletedProcess:
    env = {
        "PATH": os.environ["PATH"],
        "HOME": str(home),
        "LC_ALL": "C",
        "PIP_NO_INDEX": "1",
        "PIP_NO_CACHE_DIR": "1",
        "PIP_CONFIG_FILE": os.devnull,
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
    }
    if "PIP_FIND_LINKS" in os.environ:
        env["PIP_FIND_LINKS"] = os.environ["PIP_FIND_LINKS"]
    return subprocess.run(
        ["bash", str(repo / SCRIPT), step], env=env, capture_output=True, text=True, check=False, timeout=600
    )


def digest(folder: Path) -> dict:
    """
    Args:
        folder: A folder; its links are recorded, never followed.

    Returns:
        Each path below it to its kind and mode, plus the sha256 of a file or
        the target of a link.
    """
    tree = {}
    for path in sorted(folder.rglob("*")):
        info = path.lstat()
        mode = stat.S_IMODE(info.st_mode)
        if stat.S_ISLNK(info.st_mode):
            tree[path.relative_to(folder).as_posix()] = ("link", os.readlink(path))
        elif stat.S_ISDIR(info.st_mode):
            tree[path.relative_to(folder).as_posix()] = ("dir", mode)
        else:
            tree[path.relative_to(folder).as_posix()] = ("file", mode, hashlib.sha256(path.read_bytes()).hexdigest())
    return tree


def stamps(folder: Path) -> dict:
    """
    Args:
        folder: A folder.

    Returns:
        Each path below it, the folder included, to its inode and change
        time, which every rewrite, rename or chmod moves.
    """
    return {
        path.as_posix(): (path.lstat().st_ino, path.lstat().st_ctime_ns)
        for path in [folder, *sorted(folder.rglob("*"))]
    }


def without_caches(folder: Path) -> dict:
    return {
        path: entry
        for path, entry in digest(folder).items()
        if "__pycache__" not in path.split("/") and not path.endswith((".pyc", ".pyo"))
    }


def test_the_skills_land_in_claude_and_agents_and_a_second_run_changes_no_file(tmp_path):
    repo = checkout(tmp_path, fixture_skills(tmp_path / "source", ("kvb-quality-alpha", "kvb-quality-beta")))
    home = tmp_path / "home"
    home.mkdir()
    first = install(repo, home, "skills")
    assert first.returncode == 0, first.stderr
    for root in ROOTS:
        installed = sorted(path.name for path in (home / root).iterdir())
        assert installed == ["kvb-quality-alpha", "kvb-quality-beta"]
        for name in installed:
            assert digest(home / root / name) == without_caches(repo / "skills" / name)
    before = {root: digest(home / root) for root in ROOTS}
    unchanged = stamps(home)
    second = install(repo, home, "skills")
    assert second.returncode == 0, second.stderr
    assert {root: digest(home / root) for root in ROOTS} == before
    assert stamps(home) == unchanged
    assert not (home / ".codex").exists()


def test_codex_gets_the_skills_only_when_its_folder_exists(tmp_path):
    repo = checkout(tmp_path, fixture_skills(tmp_path / "source", ("kvb-quality-alpha",)))
    home = tmp_path / "home"
    (home / ".codex").mkdir(parents=True)
    result = install(repo, home, "skills")
    assert result.returncode == 0, result.stderr
    assert digest(home / CODEX) == digest(home / ROOTS[0])


def test_a_changed_skill_is_replaced_a_dropped_one_removed_and_foreign_skills_kept(tmp_path):
    repo = checkout(tmp_path, fixture_skills(tmp_path / "source", ("kvb-quality-alpha", "kvb-quality-beta")))
    home = tmp_path / "home"
    foreign = home / ROOTS[0] / "kvb-org-foreign"
    foreign.mkdir(parents=True)
    (foreign / "SKILL.md").write_text(SKILL.format(name="kvb-org-foreign"), encoding="utf-8")
    assert install(repo, home, "skills").returncode == 0
    (repo / "skills" / "kvb-quality-alpha" / "notes.md").write_text("new\n", encoding="utf-8")
    shutil.rmtree(repo / "skills" / "kvb-quality-beta")
    result = install(repo, home, "skills")
    assert result.returncode == 0, result.stderr
    for root in ROOTS:
        assert sorted(path.name for path in (home / root).iterdir() if path.name.startswith("kvb-quality-")) == [
            "kvb-quality-alpha"
        ]
        assert digest(home / root / "kvb-quality-alpha") == without_caches(repo / "skills" / "kvb-quality-alpha")
    assert [path.name for path in foreign.iterdir()] == ["SKILL.md"]
    assert (foreign / "SKILL.md").read_text(encoding="utf-8") == SKILL.format(name="kvb-org-foreign")


def test_the_repository_skills_install_with_their_frontmatter_names(tmp_path):
    repo = checkout(tmp_path, ROOT / "skills")
    home = tmp_path / "home"
    home.mkdir()
    first = install(repo, home, "skills")
    assert first.returncode == 0, first.stderr
    for root in ROOTS:
        assert (home / root / "kvb-quality-score" / "SKILL.md").is_file()
    unchanged = stamps(home)
    second = install(repo, home, "skills")
    assert second.returncode == 0, second.stderr
    assert stamps(home) == unchanged


@pytest.mark.parametrize(("home", "step"), [("relative-home", "skills"), ("/", "unknown")])
def test_a_relative_home_or_an_unknown_step_exits_2(tmp_path, home, step):
    repo = checkout(tmp_path, fixture_skills(tmp_path / "source", ("kvb-quality-alpha",)))
    result = install(repo, Path(home), step)
    assert result.returncode == 2, result.stderr


def test_a_checkout_without_skills_exits_2_and_installs_nothing(tmp_path):
    (tmp_path / "source" / "skills").mkdir(parents=True)
    repo = checkout(tmp_path, tmp_path / "source" / "skills")
    home = tmp_path / "home"
    home.mkdir()
    result = install(repo, home, "skills")
    assert result.returncode == 2, result.stderr
    assert list(home.iterdir()) == []


def test_the_python_step_installs_the_package_behind_kvb_quality_python(tmp_path):
    repo = with_package(checkout(tmp_path, fixture_skills(tmp_path / "source", ("kvb-quality-alpha",))))
    home = tmp_path / "home"
    home.mkdir()
    first = install(repo, home, "python")
    if first.returncode != 0 and OFFLINE in first.stdout + first.stderr:
        pytest.skip("pip needs the network for the build backend of pyproject.toml; PIP_FIND_LINKS naming a wheel folder runs it offline")
    assert first.returncode == 0, first.stderr
    probe = tmp_path / "probe.py"
    probe.write_text(
        "#!/usr/bin/env kvb-quality-python\n"
        "import sys\n"
        "import quality.agent.diff, quality.agent.nofollow, quality.agent.state\n"
        "print(sys.prefix)\n",
        encoding="utf-8",
    )
    probe.chmod(0o755)
    env = {"PATH": f"{home / LAUNCHER.parent}{os.pathsep}{os.environ['PATH']}", "HOME": str(home)}
    ran = subprocess.run([str(probe)], env=env, capture_output=True, text=True, check=False, timeout=60)
    assert ran.returncode == 0, ran.stderr
    assert ran.stdout.strip() == str(home / VENV)
    launcher = stamps(home / LAUNCHER.parent)
    second = install(repo, home, "python")
    assert second.returncode == 0, second.stderr
    assert stamps(home / LAUNCHER.parent) == launcher
