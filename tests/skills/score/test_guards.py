from __future__ import annotations

import os
import subprocess
import unittest

from tests.skills.score.support import (
    FIX,
    HANG,
    JOURNAL_NAME,
    NOFOLLOW,
    SCORE,
    STATE,
    TempCase,
    agent_tree,
    environment,
    flags,
    git_env,
    init_repo,
    run,
)

BASE = {
    "fix": "95", "break": "2", "efficiency": "97", "speed": "-", "security": "100", "critical": "0",
    "legal": "100", "legal-blockers": "0", "architecture": "100",
}
BLOCK_LINES = 11


def values(changed: dict[str, str]) -> list[str]:
    return flags({**BASE, **changed})


class GuardCase(TempCase):
    def score(self, *args: str) -> subprocess.CompletedProcess:
        return run(SCORE, list(args), self.tmp, self.env)

    def assert_one_line(self, done: subprocess.CompletedProcess, code: int, start: str) -> None:
        self.assertEqual(done.returncode, code)
        self.assertEqual(len(done.stderr.splitlines()), 1, done.stderr)
        self.assertTrue(done.stderr.startswith(start), done.stderr)


class TestUnsafeJournal(GuardCase):
    def test_a_link_at_the_journal_is_not_followed(self):
        self.council.mkdir()
        target = self.tmp / "elsewhere"
        target.write_text("kept\n", encoding="utf-8")
        (self.council / JOURNAL_NAME).symlink_to(target)
        done = self.score(*values({"critical": "1"}), "--message-block")
        self.assert_one_line(done, 4, f"score: journal {self.council / JOURNAL_NAME}: ")
        self.assertEqual(target.read_text(encoding="utf-8"), "kept\n")

    def test_a_fifo_at_the_journal_does_not_block_the_exit_code(self):
        self.council.mkdir()
        os.mkfifo(self.council / JOURNAL_NAME)
        done = self.score(*values({"critical": "1"}), "--message-block")
        self.assert_one_line(done, 4, f"score: journal {self.council / JOURNAL_NAME}: ")

    def test_a_linked_council_root_is_refused(self):
        real = self.tmp / "worktree"
        real.mkdir()
        (real / ".git").write_text("gitdir: /elsewhere\n", encoding="utf-8")
        self.council.symlink_to(real)
        done = self.score(*values({"critical": "1"}), "--message-block")
        self.assert_one_line(done, 4, "score: journal ")
        self.assertEqual(sorted(path.name for path in real.iterdir()), [".git"])


class TestUnusableHelpers(GuardCase):
    def test_a_missing_or_broken_nofollow_module_is_named_in_the_one_stderr_line(self):
        state = STATE.read_text(encoding="utf-8")
        cases = {"ModuleNotFoundError": None, "AttributeError": "VERSION = 0\n", "SyntaxError": "def (:\n"}
        if os.geteuid() != 0:
            cases["PermissionError"] = NOFOLLOW.read_text(encoding="utf-8")
        for kind, text in cases.items():
            modules = {"state.py": state} if text is None else {"state.py": state, "nofollow.py": text}
            site = agent_tree(self.tmp / kind, modules)
            if kind == "PermissionError":
                (site / "quality" / "agent" / "nofollow.py").chmod(0)
            self.env = environment(self.council, site)
            for changed, code in (({}, 0), ({"critical": "1"}, 4)):
                with self.subTest(kind=kind, values=changed):
                    done = self.score(*values(changed), "--message-block")
                    self.assertEqual(done.returncode, code)
                    self.assertEqual(done.stderr, f"score: journal {self.council / JOURNAL_NAME}: helper quality.agent.nofollow unusable ({kind}): {FIX}\n")
                    self.assertEqual(len(done.stdout.splitlines()), BLOCK_LINES)
                    self.assertFalse(self.council.exists())

    def test_a_missing_state_module_is_named_in_the_one_stderr_line(self):
        self.env = environment(self.council, agent_tree(self.tmp, {"nofollow.py": NOFOLLOW.read_text(encoding="utf-8")}))
        for changed, code in (({}, 0), ({"critical": "1"}, 4)):
            with self.subTest(values=changed):
                done = self.score(*values(changed), "--message-block")
                self.assertEqual(done.returncode, code)
                self.assertEqual(done.stderr, f"score: journal: helper quality.agent.state unusable (ModuleNotFoundError): {FIX}\n")
                self.assertEqual(len(done.stdout.splitlines()), BLOCK_LINES)
                self.assertFalse(self.council.exists())


class TestUnreadableGit(GuardCase):
    def test_a_branch_or_commit_outside_utf8_keeps_the_score_exit(self):
        repo = self.tmp / "latin"
        env = git_env(self.tmp)
        subprocess.run(["git", "init", "-q", "-b", "caf\udce9", str(repo)], env=env, capture_output=True, check=True, timeout=HANG)
        subprocess.run(["git", "commit", "-q", "--allow-empty", "-m", "base"], cwd=repo, env=env, capture_output=True, check=True, timeout=HANG)
        for changed, code, unread in (({}, 0, 2), ({"critical": "1"}, 4, 4)):
            with self.subTest(values=changed):
                done = self.score(*values(changed), "--commit-table", str(repo))
                self.assertEqual((done.returncode, done.stderr), (code, ""))
                self.assertIn("🌿 Branch: caf�\n", done.stdout)
                failed = self.score(*values(changed), "--commit-table", str(repo), "--commit", "\udce9")
                self.assertEqual((failed.returncode, failed.stdout), (unread, ""))
                self.assert_one_line(failed, unread, "score: git show in ")

    def test_a_critical_finding_wins_over_a_commit_table_git_cannot_read(self):
        repo = self.tmp / "repo"
        init_repo(repo, "feature/journal", "git@github.com:example/fixture.git")
        plain = self.tmp / "plain"
        plain.mkdir()
        self.env["GIT_CEILING_DIRECTORIES"] = str(self.tmp)
        tables = {"non-git": (str(plain),), "deleted": (str(self.tmp / "deleted"),), "unknown commit": (str(repo), "--commit", "0" * 40)}
        for name, (target, *commit) in tables.items():
            for changed, code in (({}, 2), ({"fix": "80"}, 2), ({"critical": "1"}, 4), ({"fix": "80", "critical": "1"}, 4)):
                with self.subTest(table=name, values=changed):
                    done = self.score(*values(changed), "--commit-table", target, *commit)
                    self.assertEqual((done.returncode, done.stdout), (code, ""))
                    self.assert_one_line(done, code, "score: git ")


if __name__ == "__main__":
    unittest.main()
