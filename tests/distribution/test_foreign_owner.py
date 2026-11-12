import os
import shutil
import subprocess

from quality.environment import trusted_worktree
from quality.repo import hardened_env
from tests.integration.support import Target, path_with, quality, rules_copy, write_shim

NOT_A_WORK_TREE = "not inside a git work tree"


def foreign_git(directory) -> str:
    """
    Args:
        directory: Directory for the shim.

    Returns:
        PATH with a git first that treats every repository as owned by
        another user.
    """
    write_shim(directory, "git", f'GIT_TEST_ASSUME_DIFFERENT_OWNER=1 exec {shutil.which("git")} "$@"')
    return path_with(directory)


def committed(tmp_path) -> Target:
    target = Target.create(tmp_path / "repo")
    target.write("a.py", "x = 1\n")
    target.write("sub/notes.txt", "x\n")
    target.commit()
    return target


def safe_directories(env: dict) -> list:
    count = int(env["GIT_CONFIG_COUNT"])
    return [env[f"GIT_CONFIG_VALUE_{index}"] for index in range(count) if env[f"GIT_CONFIG_KEY_{index}"] == "safe.directory"]


def test_the_shim_makes_git_refuse_a_foreign_repository(tmp_path):
    target = committed(tmp_path)
    env = hardened_env(foreign_git(tmp_path / "bin"), {}, None)
    argv = [str(tmp_path / "bin" / "git"), "rev-parse", "--show-toplevel"]
    result = subprocess.run(argv, cwd=target.path, env=env, capture_output=True, text=True, check=False)
    assert result.returncode != 0
    assert "dubious ownership" in result.stderr


def test_check_opens_a_foreign_checkout_at_its_root(tmp_path):
    target = committed(tmp_path)
    result = target.check("--all", path_value=foreign_git(tmp_path / "bin"))
    assert result.returncode == 0, result.stderr


def test_check_still_refuses_a_foreign_repository_above_the_directory(tmp_path):
    target = committed(tmp_path)
    rules = rules_copy(tmp_path / "rules")
    path_value = foreign_git(tmp_path / "bin")
    result = quality(target.path / "sub", "check", "--all", "--rules", str(rules), path_value=path_value)
    assert result.returncode == 2
    assert NOT_A_WORK_TREE in result.stderr


def test_only_the_work_tree_itself_is_trusted(tmp_path):
    target = committed(tmp_path)
    assert trusted_worktree(str(target.path)) == target.path.resolve()
    assert trusted_worktree(str(target.path / "sub")) is None
    assert trusted_worktree(str(tmp_path)) is None
    star = tmp_path / "*"
    (star / ".git").mkdir(parents=True)
    assert trusted_worktree(str(star)) is None
    env = hardened_env(os.environ["PATH"], {}, trusted_worktree(str(target.path)))
    assert safe_directories(env) == [str(target.path.resolve())]
    assert safe_directories(hardened_env(os.environ["PATH"], {}, None)) == []
