from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from tests.skills.score.support import (
    JOURNAL_NAME,
    ROOT,
    SCORE,
    SCRIPTS,
    TempCase,
    flags,
    git_env,
    init_repo,
    module,
    run,
)

REMOTES = (
    "git@github.com:org/repo.git",
    "github.com:org/repo.git",
    "GitHub.com:org/repo",
    "https://github.com/org/repo",
    "https://user@github.com:443/org/repo.git/",
    "ssh://git@github.com/org/repo.git",
)
BASE = {
    "fix": "95", "break": "2", "efficiency": "97", "speed": "-", "security": "100", "critical": "0",
    "legal": "100", "legal-blockers": "0", "architecture": "100",
}
BLOCK_LINES = 11
READERS = {"skills/kvb-quality-score/journal.md", "src/quality/agent/state.py"}
TEXT = {".py", ".sh", ".md", ".js", ".j2", ".json", ".yml"}
FIXTURE_REMOTE = "git@github.com:example/fixture.git"


def values(changed: dict[str, str]) -> list[str]:
    return flags({**BASE, **changed})


class JournalCase(TempCase):
    def score(self, *args: str, cwd: Path) -> subprocess.CompletedProcess:
        return run(SCORE, list(args), cwd, self.env)

    def rows(self) -> list[dict]:
        path = self.council / JOURNAL_NAME
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []

    def repo(self) -> Path:
        repo = self.tmp / "repo"
        init_repo(repo, "feature/journal", FIXTURE_REMOTE)
        return repo

    def assert_one_journal_line(self, done: subprocess.CompletedProcess, code: int) -> None:
        self.assertEqual(done.returncode, code)
        self.assertEqual(len(done.stderr.splitlines()), 1, done.stderr)
        self.assertTrue(done.stderr.startswith(f"score: journal {self.council / JOURNAL_NAME}: "), done.stderr)


class TestJournalPlace(unittest.TestCase):
    def setUp(self):
        self.journal = module(SCRIPTS / "journal.py", "kvb_quality_score_journal")

    def test_an_empty_council_root_means_the_durable_agents_default(self):
        with tempfile.TemporaryDirectory() as home:
            for value in ("", None):
                with self.subTest(value=value), mock.patch.dict(os.environ, {"HOME": home} if value is None else {"HOME": home, "AGENTS_COUNCIL_ROOT": value}):
                    os.environ.pop("XDG_STATE_HOME", None)
                    if value is None:
                        os.environ.pop("AGENTS_COUNCIL_ROOT", None)
                    self.assertEqual(self.journal.journal_path(), Path(home) / ".local" / "state" / "agents-shared" / JOURNAL_NAME)

    def test_ssh_scp_and_https_remotes_share_one_key(self):
        self.assertEqual({self.journal.identity(url) for url in REMOTES}, {"github.com/org/repo"})
        for url in ("/srv/git/repo.git", "./repo", "file:///srv/git/repo.git", None):
            with self.subTest(url=url):
                self.assertEqual(self.journal.identity(url), url)

    def test_a_missing_helper_module_is_named_and_never_a_missing_journal(self):
        with tempfile.TemporaryDirectory() as council, mock.patch.dict(sys.modules, {"quality.agent.nofollow": None}):
            path = Path(council) / JOURNAL_NAME
            with self.assertRaises(OSError) as raised:
                self.journal.known(path)
        self.assertNotIsInstance(raised.exception, FileNotFoundError)
        self.assertEqual(str(raised.exception), "helper quality.agent.nofollow unusable (ModuleNotFoundError): install or update kvb-quality")


class TestScoreJournal(JournalCase):
    def test_each_message_block_appends_exactly_one_row_with_the_journal_fields(self):
        repo = self.repo()
        before = int(time.time())
        first = self.score(*values({}), "--message-block", cwd=repo)
        second = self.score(*values({"security": "~80"}), "--message-block", "--value", "1:20", cwd=repo)
        self.assertEqual((first.returncode, second.returncode, first.stderr, second.stderr), (0, 3, "", ""))
        rows = self.rows()
        self.assertEqual(len(rows), 2)
        for row, done in zip(rows, (first, second)):
            self.assertEqual(list(row), ["time", "remote", "path", "branch", "sha", "values", "digest"])
            self.assertEqual((row["remote"], row["path"], row["branch"], row["sha"]), ("github.com/example/fixture", str(repo.resolve()), "feature/journal", None))
            self.assertEqual(row["digest"], hashlib.sha256(done.stdout.rstrip("\n").encode("utf-8")).hexdigest())
            self.assertLessEqual(before, row["time"])
            self.assertLessEqual(row["time"], int(time.time()))
        self.assertEqual(rows[0]["values"], {"fix": 95, "break": 2, "tokens": 97, "velocity": None, "security": 100, "score": 96})
        self.assertEqual(rows[1]["values"], {"fix": 95, "break": 2, "tokens": 97, "velocity": None, "security": 80, "score": 77})
        self.score(*values({}), cwd=repo)
        self.assertEqual(len(self.rows()), 2)

    def test_the_commit_table_of_a_commit_records_its_sha_and_commit_time_once_per_remote_and_sha(self):
        repo = self.repo()
        env = git_env(self.tmp)
        sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, env=env, capture_output=True, text=True, check=True).stdout.strip()
        stamp = int(subprocess.run(["git", "show", "-s", "--format=%ct", sha], cwd=repo, env=env, capture_output=True, text=True, check=True).stdout)
        self.score(*values({}), "--message-block", cwd=repo)
        for _ in range(2):
            done = self.score(*values({}), "--commit-table", str(repo), "--commit", sha[:7], cwd=self.tmp)
            self.assertEqual((done.returncode, done.stderr), (0, ""))
        rendered, committed = self.rows()
        self.assertEqual(committed, {**rendered, "time": stamp, "sha": sha})
        self.score(*values({"fix": "80"}), "--commit-table", str(repo), cwd=self.tmp)
        self.assertEqual(len(self.rows()), 2)
        self.council.joinpath(JOURNAL_NAME).unlink()
        self.council.rmdir()
        self.council.write_text("not a directory", encoding="utf-8")
        self.assert_one_journal_line(self.score(*values({"critical": "1"}), "--commit-table", str(repo), "--commit", sha, cwd=self.tmp), 4)

    def test_a_failed_append_prints_one_stderr_line_and_keeps_the_exit_code(self):
        self.council.write_text("not a directory", encoding="utf-8")
        for changed, code in (({}, 0), ({"efficiency": "120"}, 3), ({"break": "9"}, 1), ({"critical": "1"}, 4)):
            with self.subTest(values=changed):
                done = self.score(*values(changed), "--message-block", cwd=self.tmp)
                self.assert_one_journal_line(done, code)
                self.assertEqual(len(done.stdout.splitlines()), BLOCK_LINES)

    def test_a_deleted_working_directory_keeps_the_exit_code(self):
        gone = self.tmp / "gone"
        wrapper = "import os, subprocess, sys; os.chdir(sys.argv[1]); os.rmdir(sys.argv[1]); sys.exit(subprocess.run(sys.argv[2:]).returncode)"
        for changed, code in (({}, 0), ({"critical": "1"}, 4)):
            with self.subTest(values=changed):
                gone.mkdir(exist_ok=True)
                command = [sys.executable, "-B", "-c", wrapper, str(gone), sys.executable, "-B", str(SCORE), *values(changed), "--message-block"]
                done = subprocess.run(command, env=self.env, capture_output=True, text=True, check=False)
                self.assert_one_journal_line(done, code)
                self.assertEqual(len(done.stdout.splitlines()), BLOCK_LINES)

    def test_git_output_outside_utf8_keeps_the_exit_code_and_the_row(self):
        repo = self.repo()
        subprocess.run([b"git", b"remote", b"set-url", b"origin", b"https://example.org/caf\xe9.git"], cwd=repo, env=git_env(self.tmp), capture_output=True, check=True)
        done = self.score(*values({"critical": "1"}), "--message-block", cwd=repo)
        self.assertEqual((done.returncode, done.stderr), (4, ""))
        self.assertEqual(self.rows()[0]["remote"], "example.org/caf�")

    def test_a_new_journal_and_council_root_are_private(self):
        self.score(*values({}), "--message-block", cwd=self.tmp)
        self.assertEqual(stat.S_IMODE((self.council / JOURNAL_NAME).stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.council.stat().st_mode), 0o700)

    def test_no_gate_reads_the_journal(self):
        found = {
            str(path.relative_to(ROOT))
            for top in ("skills", "src")
            for path in (ROOT / top).rglob("*")
            if path.suffix in TEXT and path.is_file() and JOURNAL_NAME in path.read_text(encoding="utf-8", errors="replace")
        }
        self.assertLessEqual(found, READERS)
        pattern = re.compile(r"^from journal import|^import journal", re.MULTILINE)
        importers = {str(path.relative_to(ROOT)) for path in (ROOT / "skills").rglob("*.py") if pattern.search(path.read_text(encoding="utf-8"))}
        self.assertEqual(importers, {"skills/kvb-quality-score/scripts/score.py", "skills/kvb-quality-score/scripts/backfill.py"})
        self.council.mkdir()
        (self.council / JOURNAL_NAME).write_text('{"time": 1, "values": {"score": 0}}\n{broken\n', encoding="utf-8")
        self.assertEqual(self.score(*values({}), cwd=self.tmp).returncode, 0)


if __name__ == "__main__":
    unittest.main()
