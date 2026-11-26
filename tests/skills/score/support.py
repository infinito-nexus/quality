from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src"
SKILL = ROOT / "skills" / "kvb-quality-score"
SCRIPTS = SKILL / "scripts"
SCORE = SCRIPTS / "score.py"
BACKFILL = SCRIPTS / "backfill.py"
LABELS = SKILL / "labels.json"
STATE = SRC / "quality" / "agent" / "state.py"
NOFOLLOW = SRC / "quality" / "agent" / "nofollow.py"
JOURNAL_NAME = "scores.jsonl"
FIX = "install or update kvb-quality"
EPOCH = 1_760_000_000
HANG = 60
OLD_BLOCK = "🎯 Fix: 95 %\n💥 Break: 2 %\n💸 Cost: 97 %\n⏱️ Time: –\n🛡️ Security: 100 %\n🏆 Score: 96\n🚦 Gate: ✅ 90/5, cost and time <= 100, security 100 %"
NEW_BLOCK = "🎯 Fix: 92 %\n💥 Break: 3 %\n💸 Tokens: 110 %\n⏱️ Velocity: 90 %\n🛡️ Security: 100 %\n💰 Value: 1:20\n🧪 Coverage: 80 %\n🏆 Score: 81\n🚦 Gate: ⚠️ tokens 110 % > 100: ask the operator before the commit"
ESTIMATED_BLOCK = "🎯 Fix: 90 %\n💥 Break: 5 %\n💸 Tokens: new\n⏱️ Velocity: 130 %\n🛡️ Security: ~80 %\n🌡️ Heat: 5\n🧪 Coverage: 70 %\n🏆 Score: 52\n🚦 Gate: ⚠️ tokens new: ask the operator before the commit"
MALFORMED_BLOCK = "🎯 Fix: 95 %\n💥 Break: 2 %\n🏆 Score: high"
TRAILER = "Co-Authored-By: Test <test@example.org>"


def environment(council: Path, path: Path) -> dict[str, str]:
    """Args:
        council: the council root the scripts journal into.
        path: the directory holding the quality package the scripts import.

    Returns:
        The environment of a script run.
    """
    return {"PATH": os.environ["PATH"], "AGENTS_COUNCIL_ROOT": str(council), "PYTHONPATH": str(path)}


def git_env(home: Path) -> dict[str, str]:
    """Args:
        home: a scratch HOME, so no user or system git configuration applies.

    Returns:
        The environment for fixture git calls.
    """
    return {
        "PATH": os.path.dirname(shutil.which("git")),
        "HOME": str(home),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "Test",
        "GIT_AUTHOR_EMAIL": "test@example.org",
        "GIT_COMMITTER_NAME": "Test",
        "GIT_COMMITTER_EMAIL": "test@example.org",
    }


class TempCase(unittest.TestCase):
    """
    Attributes:
        tmp: a scratch directory per test.
        council: the council root below it.
        env: environment() of that root with SRC.
    """

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.council = self.tmp / "council"
        self.env = environment(self.council, SRC)


def flags(values: dict[str, str]) -> list[str]:
    return [item for key, value in values.items() for item in (f"--{key}", value)]


def run(script: Path, args: list[str], cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess:
    """Args:
        script: score.py or backfill.py.
        args: its arguments.
        cwd: the directory it runs in.
        env: environment() of the run.

    Returns:
        The finished run, its output as text.
    """
    return subprocess.run([sys.executable, "-B", str(script), *args], cwd=cwd, env=env, capture_output=True, text=True, check=False, timeout=HANG)


def module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    found = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(found)
    return found


def agent_tree(base: Path, modules: dict[str, str]) -> Path:
    """Args:
        base: a scratch directory.
        modules: file name below quality/agent to its text; no other module of
            quality.agent exists there.

    Returns:
        The directory to put on PYTHONPATH in place of src.
    """
    agent = base / "site" / "quality" / "agent"
    agent.mkdir(parents=True)
    (agent.parent / "__init__.py").write_text("", encoding="utf-8")
    (agent / "__init__.py").write_text("", encoding="utf-8")
    for name, text in modules.items():
        (agent / name).write_text(text, encoding="utf-8")
    return agent.parents[1]


def init_repo(repo: Path, branch: str, remote: str) -> None:
    """Args:
        repo: a missing directory, made a git repository with one empty commit.
        branch: its branch.
        remote: the URL of its origin remote.
    """
    repo.mkdir()
    env = git_env(repo.parent)
    for args in (("init", "-q", "-b", branch), ("remote", "add", "origin", remote), ("commit", "-q", "--allow-empty", "-m", "base")):
        subprocess.run(["git", *args], cwd=repo, env=env, capture_output=True, check=True)


class Fixture:
    """Args:
        base: a scratch directory for upstream.git, the work clone a and the clone b.
    """

    def __init__(self, base: Path) -> None:
        self.base = base
        self.env = git_env(base)
        self.upstream = base / "upstream.git"
        self.a = base / "a"
        self.b = base / "b"
        self.step = 0
        base.mkdir(parents=True)
        self.git(base, "init", "-q", "--bare", "-b", "main", str(self.upstream))
        self.a.mkdir()
        self.git(self.a, "init", "-q", "-b", "main")
        self.git(self.a, "remote", "add", "origin", str(self.upstream))
        self.old = self.commit("feat: old labels", OLD_BLOCK)
        self.git(self.a, "checkout", "-q", "-b", "feature/two")
        self.new = self.commit("feat: new labels", NEW_BLOCK)
        self.git(self.a, "checkout", "-q", "main")
        self.tick()
        self.git(self.a, "merge", "-q", "--no-ff", "-m", "Merge branch 'feature/two'", "feature/two")
        self.estimated = self.commit("fix: estimated", ESTIMATED_BLOCK)
        self.malformed = self.commit("chore: malformed", MALFORMED_BLOCK)
        self.plain = self.commit("docs: no block", "")
        self.git(self.a, "push", "-q", "origin", "main", "feature/two")
        self.git(base, "clone", "-q", str(self.upstream), str(self.b))

    def tick(self) -> None:
        self.step += 1
        stamp = f"{EPOCH + self.step * 3600} +0000"
        self.env["GIT_AUTHOR_DATE"] = stamp
        self.env["GIT_COMMITTER_DATE"] = stamp

    def git(self, cwd: Path, *args: str) -> str:
        return subprocess.run(["git", *args], cwd=cwd, env=self.env, capture_output=True, text=True, check=True).stdout.strip()

    def commit(self, subject: str, block: str) -> str:
        self.tick()
        messages = [item for part in (subject, block, TRAILER) if part for item in ("-m", part)]
        self.git(self.a, "commit", "-q", "--allow-empty", *messages)
        return self.git(self.a, "rev-parse", "HEAD")

    def time_of(self, sha: str) -> int:
        return int(self.git(self.a, "show", "-s", "--format=%ct", sha))


def backfill(council: Path, *args: str) -> subprocess.CompletedProcess:
    return run(BACKFILL, list(args), council.parent, environment(council, SRC))
