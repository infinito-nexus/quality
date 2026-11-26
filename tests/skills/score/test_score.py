from __future__ import annotations

import subprocess
import sys
import unittest

from tests.skills.score.support import (
    HANG,
    SCORE,
    TempCase,
    flags,
    git_env,
    run,
)

PASS = "✅ gate: 90/5, tokens and velocity <= 100, security 100 %"
BASE = {"fix": "95", "break": "2", "efficiency": "100", "speed": "100", "security": "100", "critical": "0"}
HEADER = "| 🎯 Fix | 💥 Break | 💸 Tokens | ⏱️ Velocity | 🛡️ Security | 🏆 Score | Gate |"
ASK = ": ask the operator before the commit"
LEAD = ["🌿 Branch", "📊 Diff stat"]
ROW = "| 95 % | 2 % | 100 % | 100 % | 100 % | 93 | ✅ 90/5, tokens and velocity <= 100, security 100 % |"


class ScoreCase(TempCase):
    def _run(self, *args: str) -> subprocess.CompletedProcess:
        return run(SCORE, list(args), self.tmp, self.env)

    def _score(self, **values: str) -> tuple[list[str], int]:
        result = self._run(*flags({**BASE, **values}))
        self.assertEqual(result.stderr, "")
        return result.stdout.splitlines(), result.returncode


class TestScore(ScoreCase):
    def test_runs_under_python_isolated_mode_from_another_directory(self):
        result = subprocess.run(
            [sys.executable, "-I", "-B", str(SCORE), *flags(BASE)],
            cwd=self.tmp, env=self.env, capture_output=True, text=True, check=False, timeout=HANG,
        )
        self.assertEqual((result.returncode, result.stderr), (0, ""))
        self.assertEqual(result.stdout.splitlines()[1], PASS)

    def test_formula_and_line_format(self):
        self.assertEqual(
            self._score(fix="95", **{"break": "4"}),
            (["🎯 fix 95 % · 💥 break 4 % · 💸 tokens 100 % · ⏱️ velocity 100 % · 🛡️ security 100 % · 🏆 score 91",
              PASS], 0),
        )
        lines, code = self._score(efficiency="97", speed="-")
        self.assertEqual(
            lines[0], "🎯 fix 95 % · 💥 break 2 % · 💸 tokens 97 % · ⏱️ velocity – · 🛡️ security 100 % · 🏆 score 96"
        )
        self.assertEqual(code, 0)
        self.assertEqual(self._score(fix="92.5")[0][0].split(" · ")[0], "🎯 fix 92.5 %")

    def test_dash_values_count_as_100(self):
        lines, code = self._score(fix="92", efficiency="-", speed="-", **{"break": "3"})
        self.assertEqual(
            (lines, code),
            (["🎯 fix 92 % · 💥 break 3 % · 💸 tokens – · ⏱️ velocity – · 🛡️ security 100 % · 🏆 score 89", PASS], 0),
        )

    def test_security_multiplies_and_asks_below_100(self):
        lines, code = self._score(fix="100", efficiency="-", speed="-", security="75", **{"break": "0"})
        self.assertEqual(
            (lines, code),
            (["🎯 fix 100 % · 💥 break 0 % · 💸 tokens – · ⏱️ velocity – · 🛡️ security 75 % · 🏆 score 75",
              f"⚠️ gate: security 75 % < 100{ASK}"], 3),
        )
        lines, code = self._score(security="~80")
        self.assertIn("🛡️ security ~80 % · 🏆 score 74", lines[0])
        self.assertEqual((lines[1], code), (f"⚠️ gate: security ~80 % < 100{ASK}", 3))
        self.assertEqual(self._score(security="~100")[1], 0)

    def test_score_rounds_half_up(self):
        for values, total in (
            ({"fix": "94.5", "break": "0"}, 95),
            ({"fix": "90", "break": "5"}, 86),
            ({"fix": "91", "break": "5"}, 86),
            ({"fix": "97", "break": "0", "efficiency": "97"}, 100),
        ):
            with self.subTest(values=values):
                self.assertTrue(self._score(**values)[0][0].endswith(f"🏆 score {total}"))

    def test_score_is_capped(self):
        lines, code = self._score(fix="100", efficiency="50", speed="50", **{"break": "0"})
        self.assertTrue(lines[0].endswith("🏆 score 100"))
        self.assertEqual((lines[1], code), (PASS, 0))
        lines, code = self._score(fix="0", **{"break": "100"})
        self.assertTrue(lines[0].endswith("🏆 score 0"))
        self.assertEqual(code, 1)

    def test_boundaries_pass(self):
        self.assertEqual(self._score(fix="90", **{"break": "5"})[1], 0)

    def test_new_counts_as_100_in_the_score(self):
        lines, _ = self._score(efficiency="new", speed="-", **{"break": "0"})
        self.assertEqual(
            lines[0], "🎯 fix 95 % · 💥 break 0 % · 💸 tokens new · ⏱️ velocity – · 🛡️ security 100 % · 🏆 score 95"
        )


class TestGate(ScoreCase):
    def test_90_5_failures_exit_1(self):
        for values, verdict in (
            ({"fix": "89.5", "break": "1"}, "⛔ gate: fix 89.5 % < 90"),
            ({"break": "6"}, "⛔ gate: break 6 % > 5"),
            ({"fix": "80", "break": "10"}, "⛔ gate: fix 80 % < 90, break 10 % > 5"),
            (
                {"fix": "85", "efficiency": "150", "speed": "new", "security": "50"},
                f"⛔ gate: fix 85 % < 90; tokens 150 % > 100, velocity new, security 50 % < 100{ASK}",
            ),
        ):
            with self.subTest(values=values):
                lines, code = self._score(**values)
                self.assertEqual((lines[1], code), (verdict, 1))

    def test_costs_ask_the_operator_exit_3(self):
        for values, verdict in (
            ({"efficiency": "120"}, f"⚠️ gate: tokens 120 % > 100{ASK}"),
            ({"efficiency": "-", "speed": "130"}, f"⚠️ gate: velocity 130 % > 100{ASK}"),
            ({"efficiency": "100.5", "speed": "-"}, f"⚠️ gate: tokens 100.5 % > 100{ASK}"),
            ({"efficiency": "new", "speed": "-"}, f"⚠️ gate: tokens new{ASK}"),
            (
                {"efficiency": "120", "speed": "130", "security": "90"},
                f"⚠️ gate: tokens 120 % > 100, velocity 130 % > 100, security 90 % < 100{ASK}",
            ),
        ):
            with self.subTest(values=values):
                lines, code = self._score(**values)
                self.assertEqual((lines[1], code), (verdict, 3))

    def test_critical_finding_wins_exit_4(self):
        for values in (
            {"critical": "1", "security": "50"},
            {"critical": "2", "fix": "80", "break": "10", "efficiency": "150", "security": "0"},
        ):
            with self.subTest(values=values):
                lines, code = self._score(**values)
                self.assertEqual((lines[1], code), ("⛔ gate: critical security finding: do not commit", 4))

    def test_usage_errors_exit_2(self):
        bad = (
            ("fix", "101"), ("fix", "-1"), ("fix", "nan"), ("break", "x"), ("break", "-"),
            ("efficiency", "0"), ("efficiency", "-5"), ("efficiency", "abc"), ("speed", "inf"),
            ("security", "101"), ("security", "~"), ("security", "~x"), ("security", "-"),
            ("critical", "-1"), ("critical", "a"), ("critical", "1.5"),
        )
        for key, value in bad:
            with self.subTest(flag=key, value=value):
                result = self._run(*flags({**BASE, key: value}))
                self.assertEqual((result.returncode, result.stdout), (2, ""))
        for missing in ("security", "critical"):
            with self.subTest(missing=missing):
                values = {k: v for k, v in BASE.items() if k != missing}
                self.assertEqual(self._run(*flags(values)).returncode, 2)
        for extra in (
            ("--commit", "HEAD"),
            ("--table", "--commit-table", str(self.tmp)),
            ("--message-block", "--table"),
            ("--message-block", "--commit-table", str(self.tmp)),
            ("--value", "1:20"),
            ("--table", "--value", "1-20"),
            ("--table", "--value", "?:?"),
            ("--table", "--value", "a:b"),
            ("--table", "--value", ""),
        ):
            with self.subTest(extra=extra):
                self.assertEqual(self._run(*flags(BASE), *extra).returncode, 2)


class TestLayouts(ScoreCase):
    def test_table(self):
        result = self._run(*flags({**BASE, "efficiency": "97", "speed": "-"}), "--table")
        self.assertEqual(
            result.stdout.splitlines(),
            [
                HEADER,
                "| --- | --- | --- | --- | --- | --- | --- |",
                "| 95 % | 2 % | 97 % | – | 100 % | 96 | ✅ 90/5, tokens and velocity <= 100, security 100 % |",
            ],
        )
        self.assertEqual(result.returncode, 0)
        result = self._run(*flags({**BASE, "critical": "1"}), "--table")
        self.assertTrue(result.stdout.splitlines()[2].endswith("| ⛔ critical security finding: do not commit |"))
        self.assertEqual(result.returncode, 4)

    def test_message_block_lists_one_value_per_line(self):
        result = self._run(*flags({**BASE, "efficiency": "97", "speed": "-"}), "--message-block")
        self.assertEqual(
            (result.stdout.splitlines(), result.returncode),
            (
                [
                    "🎯 Fix: 95 %", "💥 Break: 2 %", "💸 Tokens: 97 %", "⏱️ Velocity: –", "🛡️ Security: 100 %",
                    "🏆 Score: 96", "🚦 Gate: ✅ 90/5, tokens and velocity <= 100, security 100 %",
                ],
                0,
            ),
        )
        result = self._run(*flags({**BASE, "security": "~80"}), "--message-block", "--value", "1:20")
        self.assertEqual(
            (result.stdout.splitlines(), result.returncode),
            (
                [
                    "🎯 Fix: 95 %", "💥 Break: 2 %", "💸 Tokens: 100 %", "⏱️ Velocity: 100 %", "🛡️ Security: ~80 %",
                    "💰 Value: 1:20", "🏆 Score: 74", f"🚦 Gate: ⚠️ security ~80 % < 100{ASK}",
                ],
                3,
            ),
        )

    def test_message_block_gate_matches_the_gate_line(self):
        for values, code in (
            ({}, 0),
            ({"break": "6"}, 1),
            ({"efficiency": "new"}, 3),
            ({"critical": "1"}, 4),
        ):
            with self.subTest(values=values):
                lines, line_code = self._score(**values)
                block = self._run(*flags({**BASE, **values}), "--message-block")
                self.assertEqual((block.returncode, line_code), (code, code))
                self.assertEqual(block.stdout.splitlines()[-1], "🚦 Gate: " + lines[1].replace(" gate: ", " ", 1))
                self.assertEqual(len(block.stdout.splitlines()), 7)

    def test_value_column_changes_neither_score_nor_gate(self):
        for value, verdict, code in (
            ("1:20", "✅ 90/5, tokens and velocity <= 100, security 100 %", 0),
            ("4.1:1", "✅ 90/5, tokens and velocity <= 100, security 100 %", 0),
            ("?", "⚠️ tokens 120 % > 100" + ASK, 3),
        ):
            with self.subTest(value=value):
                efficiency = "97" if code == 0 else "120"
                result = self._run(*flags({**BASE, "efficiency": efficiency, "speed": "-"}), "--table", "--value", value)
                score = "96" if code == 0 else "78"
                self.assertEqual(
                    result.stdout.splitlines(),
                    [
                        HEADER.replace("💸 Tokens |", "💸 Tokens | 💰 Value |"),
                        "|" + " --- |" * 8,
                        f"| 95 % | 2 % | {efficiency} % | {value} | – | 100 % | {score} | {verdict} |",
                    ],
                )
                self.assertEqual(result.returncode, code)


class TestCommitTable(ScoreCase):
    def setUp(self):
        super().setUp()
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        self.git_env = git_env(self.tmp)
        self.git("init", "-q", "-b", "main")
        (self.repo / "a.txt").write_text("one\n", encoding="utf-8")
        self.git("add", "a.txt")
        self.git("commit", "-qm", "base")
        (self.repo / "a.txt").write_text("two\n", encoding="utf-8")
        (self.repo / "b.txt").write_text("three\nfour\n", encoding="utf-8")
        self.git("add", "a.txt", "b.txt")
        self.worktree = ["", "📁 Worktree:", "", "```text", str(self.repo.resolve()), "```"]

    def git(self, *args: str) -> str:
        return subprocess.run(["git", *args], cwd=self.repo, env=self.git_env, capture_output=True, text=True, check=True).stdout.strip()

    def table(self, *args: str) -> subprocess.CompletedProcess:
        return run(SCORE, [*flags(BASE), "--commit-table", *args], self.repo, self.env)

    def test_the_staged_table_leads_with_branch_and_diff_stat(self):
        result = self.table(str(self.repo))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.splitlines(),
            ["| " + " | ".join(LEAD) + " " + HEADER, "|" + " --- |" * 9, "| main | 2 files +3/-1 " + ROW, *self.worktree],
        )

    def test_the_table_of_a_commit_shows_its_diff_stat_and_short_sha(self):
        self.git("commit", "-qm", "change")
        sha = self.git("rev-parse", "--short", "HEAD")
        lines = self.table(str(self.repo), "--commit", "HEAD").stdout.splitlines()
        self.assertEqual(lines[0], "| " + " | ".join([*LEAD, "🔖 Commit"]) + " " + HEADER)
        self.assertEqual(lines[2], f"| main | 2 files +3/-1 | {sha} " + ROW)
        self.assertEqual(lines[3:], self.worktree)

    def test_a_value_column_joins_the_table_of_a_commit(self):
        self.git("commit", "-qm", "change")
        sha = self.git("rev-parse", "--short", "HEAD")
        lines = self.table(str(self.repo), "--commit", "HEAD", "--value", "?").stdout.splitlines()
        self.assertEqual(lines[0], "| " + " | ".join([*LEAD, "🔖 Commit"]) + " " + HEADER.replace("💸 Tokens |", "💸 Tokens | 💰 Value |"))
        self.assertEqual(lines[2], f"| main | 2 files +3/-1 | {sha} " + ROW.replace("| 100 % |", "| 100 % | ? |", 1))

    def test_a_detached_head_and_a_directory_outside_git(self):
        self.git("commit", "-qm", "change")
        sha = self.git("rev-parse", "--short", "HEAD")
        self.git("checkout", "-q", "--detach", "HEAD")
        self.assertEqual(self.table(str(self.repo)).stdout.splitlines()[2], f"| detached at {sha} | 0 files +0/-0 " + ROW)
        self.assertEqual(self.table(str(self.tmp)).returncode, 2)


if __name__ == "__main__":
    unittest.main()
