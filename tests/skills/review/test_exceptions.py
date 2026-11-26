import os
import subprocess
from pathlib import Path

import pytest

from tests.skills.review.support import EXCEPTIONS, run

COMMENT = "# Exception: the tool reads x"
IDENTITY = {
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.org",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.org",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
}


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, env={**os.environ, **IDENTITY}, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    git(tmp_path, "init", "-q")
    (tmp_path / "a.py").write_text(f"{COMMENT}\nx = 1\n", encoding="utf-8")
    git(tmp_path, "add", "a.py")
    git(tmp_path, "commit", "-q", "-m", "base")
    return tmp_path


def change(repo: Path, text: str) -> None:
    (repo / "a.py").write_text(f"{COMMENT}\nx = 1\n{text}\n", encoding="utf-8")
    git(repo, "add", "a.py")


def test_an_added_exception_comment_asks_for_confirmation(repo):
    change(repo, f"y = 2  {COMMENT}")
    result = run(EXCEPTIONS, repo, "--repo", str(repo), "--staged")
    assert result.returncode == 1
    assert result.stdout.splitlines()[0] == f"a.py:3: y = 2  {COMMENT}"
    assert "--confirm <path>:<line>" in result.stdout


def test_a_confirmed_comment_passes(repo):
    change(repo, COMMENT)
    result = run(EXCEPTIONS, repo, "--repo", str(repo), "--staged", "--confirm", "a.py:3")
    assert (result.returncode, result.stdout) == (0, "")


def test_code_and_an_old_comment_are_not_listed(repo):
    change(repo, 'raise Exception("x")')
    assert run(EXCEPTIONS, repo, "--repo", str(repo), "--staged").returncode == 0


def test_the_working_tree_against_a_base_is_read(repo):
    (repo / "a.py").write_text(f"{COMMENT}\nx = 1\n// Exception: y\n", encoding="utf-8")
    result = run(EXCEPTIONS, repo, "--repo", str(repo), "--base", "HEAD")
    assert (result.returncode, result.stdout.splitlines()[0]) == (1, "a.py:3: // Exception: y")


@pytest.mark.parametrize("argv", [["--staged", "--base", "HEAD"], []], ids=["two-modes", "no-mode"])
def test_a_usage_error_exits_2(repo, argv):
    assert run(EXCEPTIONS, repo, "--repo", str(repo), *argv).returncode == 2
