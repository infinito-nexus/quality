import subprocess

from tests.skills.score.support import (
    HANG,
    SCORE,
    SRC,
    environment,
    flags,
    git_env,
    run,
)

VALUES = {
    "fix": "95", "break": "3", "efficiency": "-", "speed": "-", "security": "100", "critical": "0",
    "legal": "100", "legal-blockers": "0", "architecture": "90",
}


def git(repo, env, *args):
    return subprocess.run(["git", *args], cwd=repo, env=env, capture_output=True, text=True, check=True, timeout=HANG).stdout


def test_a_message_block_comes_back_from_git_byte_for_byte(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    env = git_env(tmp_path)
    git(repo, env, "init", "-q", "-b", "main")
    done = run(SCORE, [*flags(VALUES), "--note", "architecture=1 new hit: clean.function-length", "--message-block"], repo, environment(tmp_path / "council", SRC))
    assert (done.returncode, done.stderr) == (3, "")
    assert "\n---\n" in done.stdout and "\n\n🚦 Gate: " in done.stdout
    git(repo, env, "commit", "-q", "--allow-empty", "-m", done.stdout)
    stored = git(repo, env, "cat-file", "commit", "HEAD").split("\n\n", 1)[1]
    assert stored == done.stdout