import os
import re
import subprocess
from pathlib import Path

import pytest

BENCH = Path(__file__).resolve().parents[2] / "scripts" / "bench.sh"
COMMIT_LINE = re.compile(r"^([0-9a-f]{40}) (\d+\.\d{3})s exit ([01])$")
P90_LINE = re.compile(r"^p90 (\d+\.\d{3})s over (\d+) commits, limit (\d+\.\d{3})s: (pass|fail)$")
STUB = (
    "#!/bin/sh\n"
    'staged="$(git diff --cached --name-only)"\n'
    'echo "$* $(git rev-parse HEAD) ${staged}" >>"${STUB_LOG}"\n'
    'case "${staged}" in slow*) sleep "${STUB_SLEEP}" ;; esac\n'
    "echo stub quality\n"
    'exit "${STUB_EXIT}"\n'
)
LOWERED_BAR_MS = "250"
SLOW_SECONDS = "0.5"


class Core:
    def __init__(self, path: Path):
        self.path = path
        self.commits = 0
        path.mkdir()
        self.git("init", "-q", "-b", "main")

    def git(self, *args: str) -> str:
        stamp = f"{1700000000 + self.commits} +0000"
        env = {
            "PATH": os.environ["PATH"],
            "HOME": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_AUTHOR_NAME": "bench",
            "GIT_AUTHOR_EMAIL": "bench@example.invalid",
            "GIT_COMMITTER_NAME": "bench",
            "GIT_COMMITTER_EMAIL": "bench@example.invalid",
            "GIT_AUTHOR_DATE": stamp,
            "GIT_COMMITTER_DATE": stamp,
        }
        done = subprocess.run(["git", *args], cwd=self.path, env=env, capture_output=True, text=True, check=True)
        return done.stdout.strip()

    def commit(self, name: str) -> str:
        (self.path / name).write_text(f"{name}\n", encoding="utf-8")
        self.git("add", "--", name)
        self.commits += 1
        self.git("commit", "-q", "-m", name)
        return self.git("rev-parse", "HEAD")


def bench(tmp_path: Path, argv: list, overrides: dict) -> subprocess.CompletedProcess:
    """
    Args:
        tmp_path: Test directory; its scratch/ is the bench's TMPDIR.
        argv: Arguments of bench.sh.
        overrides: BENCH_* and STUB_* variables of this run.

    Returns:
        The finished run.
    """
    scratch = tmp_path / "scratch"
    scratch.mkdir(exist_ok=True)
    stub = tmp_path / "quality"
    stub.write_text(STUB, encoding="utf-8")
    stub.chmod(0o755)
    env = {
        "PATH": os.environ["PATH"],
        "HOME": os.devnull,
        "TMPDIR": str(scratch),
        "STUB_LOG": str(tmp_path / "stub.log"),
        "STUB_SLEEP": "0",
        "STUB_EXIT": "0",
        **overrides,
    }
    return subprocess.run([str(BENCH), *argv], env=env, capture_output=True, text=True, check=False)


def replay(tmp_path: Path, names: list, overrides: dict) -> tuple:
    """
    Args:
        tmp_path: Test directory.
        names: File each commit after the root commit adds, oldest first.
        overrides: BENCH_* and STUB_* variables of this run.

    Returns:
        The checkout, its commits newest first as bench.sh replays them, and the run.
    """
    core = Core(tmp_path / "core")
    core.commit("root.txt")
    shas = [core.commit(name) for name in names][::-1]
    return core, shas, bench(tmp_path, [str(core.path), str(tmp_path / "quality")], overrides)


def p90_line(result: subprocess.CompletedProcess) -> tuple:
    match = P90_LINE.match(result.stdout.splitlines()[-1])
    assert match, result.stdout
    return match.groups()


def timed(result: subprocess.CompletedProcess) -> list:
    lines = result.stdout.splitlines()[:-1]
    matches = [COMMIT_LINE.match(line) for line in lines]
    assert all(matches), result.stdout
    return [(match.group(1), match.group(3)) for match in matches]


def scratch_left(tmp_path: Path) -> list:
    return sorted((tmp_path / "scratch").iterdir())


@pytest.mark.parametrize(
    ("argv", "named"),
    [([], "missing argument 1: the core checkout"), (["."], "missing argument 2: the quality binary")],
)
def test_missing_argument_is_named(tmp_path: Path, argv: list, named: str):
    result = bench(tmp_path, argv, {})
    assert result.returncode == 2
    assert named in result.stderr
    assert result.stdout == ""


def test_each_commit_is_timed_on_its_parent_with_its_diff_staged(tmp_path: Path):
    core, shas, result = replay(tmp_path, ["a.txt", "b.txt", "c.txt"], {"BENCH_COMMITS": "3"})
    assert result.returncode == 0, result.stderr
    assert timed(result) == [(sha, "0") for sha in shas]
    assert p90_line(result)[1:] == ("3", "1.000", "pass")
    logged = (tmp_path / "stub.log").read_text(encoding="utf-8").splitlines()
    parents = [core.git("rev-parse", f"{sha}^") for sha in shas]
    assert logged == [f"check --staged {parent} {name}" for parent, name in zip(parents, ["c.txt", "b.txt", "a.txt"])]
    assert core.git("status", "--porcelain") == ""
    assert core.git("rev-parse", "HEAD") == shas[0]
    assert core.git("worktree", "list", "--porcelain").count("worktree ") == 1
    assert scratch_left(tmp_path) == []


def test_merge_commits_are_not_replayed(tmp_path: Path):
    core = Core(tmp_path / "core")
    root = core.commit("root.txt")
    first = core.commit("a.txt")
    core.git("checkout", "-q", "-b", "side", root)
    second = core.commit("b.txt")
    core.git("checkout", "-q", "main")
    core.commits += 1
    core.git("merge", "-q", "--no-ff", "-m", "merge", "side")
    result = bench(tmp_path, [str(core.path), str(tmp_path / "quality")], {"BENCH_COMMITS": "2"})
    assert result.returncode == 0, result.stderr
    assert timed(result) == [(second, "0"), (first, "0")]


@pytest.mark.parametrize(("prefix", "verdict", "code"), [("fast", "pass", 0), ("slow", "fail", 1)])
def test_lowered_bar_fails_only_when_runs_are_slow(tmp_path: Path, prefix: str, verdict: str, code: int):
    names = [f"{prefix}-{index}.txt" for index in range(3)]
    overrides = {"BENCH_COMMITS": "3", "BENCH_LIMIT_MS": LOWERED_BAR_MS, "STUB_SLEEP": SLOW_SECONDS}
    _core, _shas, result = replay(tmp_path, names, overrides)
    assert result.returncode == code, result.stdout + result.stderr
    p90, count, limit, shown = p90_line(result)
    assert (count, limit, shown) == ("3", "0.250", verdict)
    assert (float(p90) >= float(SLOW_SECONDS)) == (code == 1)
    assert scratch_left(tmp_path) == []


@pytest.mark.parametrize(("slow", "code"), [(1, 0), (2, 1)])
def test_p90_lets_one_slow_commit_in_ten_pass(tmp_path: Path, slow: int, code: int):
    names = [f"slow-{index}.txt" if index < slow else f"fast-{index}.txt" for index in range(10)]
    overrides = {"BENCH_COMMITS": "10", "BENCH_LIMIT_MS": LOWERED_BAR_MS, "STUB_SLEEP": SLOW_SECONDS}
    _core, _shas, result = replay(tmp_path, names, overrides)
    assert result.returncode == code, result.stdout + result.stderr
    assert len(timed(result)) == 10


def test_findings_count_as_a_timed_run(tmp_path: Path):
    _core, shas, result = replay(tmp_path, ["a.txt"], {"BENCH_COMMITS": "1", "STUB_EXIT": "1"})
    assert result.returncode == 0, result.stderr
    assert timed(result) == [(shas[0], "1")]


def test_quality_error_aborts_with_its_output(tmp_path: Path):
    _core, shas, result = replay(tmp_path, ["a.txt"], {"BENCH_COMMITS": "1", "STUB_EXIT": "2"})
    assert result.returncode == 2
    assert f"quality exited 2 on {shas[0]}" in result.stderr
    assert "stub quality" in result.stderr
    assert scratch_left(tmp_path) == []


@pytest.mark.parametrize(("overrides", "wanted"), [({}, "43"), ({"BENCH_COMMITS": "2"}, "2")])
def test_too_few_commits_exit_2(tmp_path: Path, overrides: dict, wanted: str):
    _core, _shas, result = replay(tmp_path, ["a.txt"], overrides)
    assert result.returncode == 2
    assert f"fewer than {wanted} non-merge commits with a parent" in result.stderr
