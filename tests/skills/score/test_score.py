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

BASE = {
    "fix": "95", "break": "2", "efficiency": "100", "speed": "100", "security": "100", "critical": "0",
    "legal": "100", "legal-blockers": "0", "architecture": "100",
}
PASS = "🚦 Gate: ✅ 90/5, tokens and velocity <= 100, security, legal and architecture 100 %"
CLEAN = [
    "Metrics:", "🎯 Fix: 95 %", "💥 Break: 2 %", "💸 Tokens: 100 %", "⏱️ Velocity: 100 %", "🛡️ Security: 100 %",
    "⚖️ Legal: 100 %", "🏛️ Architecture: 100 %", "🏆 Score: 93", "", PASS,
]
DECISION_1 = {"fix": "95", "break": "3", "efficiency": "-", "speed": "-", "architecture": "90"}
DECISION_1_BLOCK = [
    "Metrics:", "🎯 Fix: 95 %", "💥 Break: 3 %", "💸 Tokens: –", "⏱️ Velocity: –", "🛡️ Security: 100 %",
    "⚖️ Legal: 100 %", "🏛️ Architecture: 90 % ¹", "🏆 Score: 83", "---", "¹ 1 new hit: clean.function-length",
    "", "🚦 Gate: ⚠️ ask: architecture 90 % < 100",
]
MARKS = set("⁰¹²³⁴⁵⁶⁷⁸⁹")
WIDTH = 30


def row(lines: list[str], name: str) -> str:
    return next(line for line in lines if line.startswith(name))


class ScoreCase(TempCase):
    def _run(self, *args: str) -> subprocess.CompletedProcess:
        return run(SCORE, list(args), self.tmp, self.env)

    def _score(self, *extra: str, **values: str) -> tuple[list[str], int]:
        result = self._run(*flags({**BASE, **values}), *extra)
        self.assertEqual(result.stderr, "")
        return result.stdout.splitlines(), result.returncode


class TestScore(ScoreCase):
    def test_runs_under_python_isolated_mode_from_another_directory(self):
        result = subprocess.run(
            [sys.executable, "-I", "-B", str(SCORE), *flags(BASE)],
            cwd=self.tmp, env=self.env, capture_output=True, text=True, check=False, timeout=HANG,
        )
        self.assertEqual((result.returncode, result.stderr), (0, ""))
        self.assertEqual(result.stdout.splitlines()[-1], PASS)

    def test_formula_and_value_format(self):
        lines, code = self._score(fix="95", **{"break": "4"})
        self.assertEqual((row(lines, "🏆"), code), ("🏆 Score: 91", 0))
        lines, code = self._score(efficiency="97", speed="-")
        self.assertEqual([row(lines, "💸"), row(lines, "⏱️"), row(lines, "🏆")], ["💸 Tokens: 97 %", "⏱️ Velocity: –", "🏆 Score: 96"])
        self.assertEqual(code, 0)
        self.assertEqual(row(self._score(fix="92.5")[0], "🎯"), "🎯 Fix: 92.5 %")

    def test_dash_values_count_as_100(self):
        lines, code = self._score(fix="92", efficiency="-", speed="-", **{"break": "3"})
        self.assertEqual((row(lines, "🏆"), lines[-1], code), ("🏆 Score: 89", PASS, 0))

    def test_security_multiplies_and_asks_below_100(self):
        lines, code = self._score(fix="100", efficiency="-", speed="-", security="75", **{"break": "0"})
        self.assertEqual((row(lines, "🏆"), lines[-1], code), ("🏆 Score: 75", "🚦 Gate: ⚠️ ask: security 75 % < 100", 3))
        lines, code = self._score(security="~80")
        self.assertEqual((row(lines, "🛡️"), row(lines, "🏆")), ("🛡️ Security: ~80 %", "🏆 Score: 74"))
        self.assertEqual((lines[-1], code), ("🚦 Gate: ⚠️ ask: security ~80 % < 100", 3))
        self.assertEqual(self._score(security="~100")[1], 0)

    def test_legal_multiplies_and_asks_below_100(self):
        lines, code = self._score(legal="90")
        self.assertEqual((row(lines, "⚖️"), row(lines, "🏆"), lines[-1], code), ("⚖️ Legal: 90 %", "🏆 Score: 84", "🚦 Gate: ⚠️ ask: legal 90 % < 100", 3))
        lines, code = self._score(legal="~100")
        self.assertEqual((row(lines, "⚖️"), lines[-1], code), ("⚖️ Legal: ~100 %", PASS, 0))
        self.assertEqual(self._score(legal="~75")[0][-1], "🚦 Gate: ⚠️ ask: legal ~75 % < 100")

    def test_architecture_multiplies_and_asks_below_100(self):
        lines, code = self._score(architecture="80")
        self.assertEqual((row(lines, "🏛️"), row(lines, "🏆"), lines[-1], code), ("🏛️ Architecture: 80 %", "🏆 Score: 74", "🚦 Gate: ⚠️ ask: architecture 80 % < 100", 3))

    def test_score_rounds_half_up(self):
        for values, total in (
            ({"fix": "94.5", "break": "0"}, 95),
            ({"fix": "90", "break": "5"}, 86),
            ({"fix": "91", "break": "5"}, 86),
            ({"fix": "97", "break": "0", "efficiency": "97"}, 100),
        ):
            with self.subTest(values=values):
                self.assertEqual(row(self._score(**values)[0], "🏆"), f"🏆 Score: {total}")

    def test_score_is_capped(self):
        lines, code = self._score(fix="100", efficiency="50", speed="50", **{"break": "0"})
        self.assertEqual((row(lines, "🏆"), lines[-1], code), ("🏆 Score: 100", PASS, 0))
        lines, code = self._score(fix="0", **{"break": "100"})
        self.assertEqual((row(lines, "🏆"), code), ("🏆 Score: 0", 1))

    def test_boundaries_pass(self):
        self.assertEqual(self._score(fix="90", **{"break": "5"})[1], 0)

    def test_new_counts_as_100_in_the_score(self):
        lines, _ = self._score(efficiency="new", speed="-", **{"break": "0"})
        self.assertEqual((row(lines, "💸"), row(lines, "🏆")), ("💸 Tokens: new", "🏆 Score: 95"))


class TestGate(ScoreCase):
    def test_90_5_failures_ask_and_exit_1(self):
        for values, verdict in (
            ({"fix": "89.5", "break": "1"}, "fix 89.5 % < 90"),
            ({"break": "6"}, "break 6 % > 5"),
            ({"fix": "80", "break": "10"}, "fix 80 % < 90, break 10 % > 5"),
            (
                {"fix": "85", "efficiency": "150", "speed": "new", "security": "50", "architecture": "90"},
                "fix 85 % < 90, tokens 150 % > 100, velocity new, security 50 % < 100, architecture 90 % < 100",
            ),
        ):
            with self.subTest(values=values):
                lines, code = self._score(**values)
                self.assertEqual((lines[-1], code), (f"🚦 Gate: ⚠️ ask: {verdict}", 1))

    def test_costs_ask_the_operator_exit_3(self):
        for values, verdict in (
            ({"efficiency": "120"}, "tokens 120 % > 100"),
            ({"efficiency": "-", "speed": "130"}, "velocity 130 % > 100"),
            ({"efficiency": "100.5", "speed": "-"}, "tokens 100.5 % > 100"),
            ({"efficiency": "new", "speed": "-"}, "tokens new"),
            (
                {"efficiency": "120", "speed": "130", "security": "90", "legal": "~75", "architecture": "90"},
                "tokens 120 % > 100, velocity 130 % > 100, security 90 % < 100, legal ~75 % < 100, architecture 90 % < 100",
            ),
        ):
            with self.subTest(values=values):
                lines, code = self._score(**values)
                self.assertEqual((lines[-1], code), (f"🚦 Gate: ⚠️ ask: {verdict}", 3))

    def test_a_critical_finding_or_a_legal_blocker_wins_exit_4(self):
        for values, verdict in (
            ({"critical": "1", "security": "50"}, "1 critical security finding"),
            ({"critical": "2", "fix": "80", "break": "10", "efficiency": "150", "security": "0"}, "2 critical security findings"),
            ({"legal-blockers": "1", "legal": "50"}, "1 legal blocker"),
            ({"critical": "1", "legal-blockers": "3", "fix": "80"}, "1 critical security finding, 3 legal blockers"),
        ):
            with self.subTest(values=values):
                lines, code = self._score(**values)
                self.assertEqual((lines[-1], code), (f"🚦 Gate: ⛔ do not commit: {verdict}", 4))

    def test_usage_errors_exit_2(self):
        bad = (
            ("fix", "101"), ("fix", "-1"), ("fix", "nan"), ("break", "x"), ("break", "-"),
            ("efficiency", "0"), ("efficiency", "-5"), ("efficiency", "abc"), ("speed", "inf"),
            ("security", "101"), ("security", "~"), ("security", "~x"), ("security", "-"),
            ("critical", "-1"), ("critical", "a"), ("critical", "1.5"),
            ("legal", "101"), ("legal", "~x"), ("legal", "-"), ("legal-blockers", "-1"), ("legal-blockers", "a"),
            ("architecture", "101"), ("architecture", "~90"), ("architecture", "-"),
        )
        for key, value in bad:
            with self.subTest(flag=key, value=value):
                result = self._run(*flags({**BASE, key: value}))
                self.assertEqual((result.returncode, result.stdout), (2, ""))
        for missing in ("security", "critical", "legal", "legal-blockers", "architecture"):
            with self.subTest(missing=missing):
                values = {k: v for k, v in BASE.items() if k != missing}
                self.assertEqual(self._run(*flags(values)).returncode, 2)
        for extra in (
            ("--commit", "HEAD"),
            ("--table",),
            ("--message-block", "--commit-table", str(self.tmp)),
            ("--value", "1-20"),
            ("--value", "?:?"),
            ("--value", "a:b"),
            ("--value", ""),
            ("--note", "architecture"),
            ("--note", "nope=x"),
            ("--note", "value=x"),
            ("--note", "gate=x"),
            ("--note", "fix= "),
            ("--note", "fix=a\nb"),
            ("--note", "fix=a", "--note", "fix=b"),
        ):
            with self.subTest(extra=extra):
                self.assertEqual(self._run(*flags(BASE), *extra).returncode, 2)


class TestBlock(ScoreCase):
    def test_the_block_of_decision_1(self):
        lines, code = self._score("--note", "architecture=1 new hit: clean.function-length", **DECISION_1)
        self.assertEqual((lines, code), (DECISION_1_BLOCK, 3))

    def test_every_value_at_its_target_prints_no_rule_and_no_marker(self):
        lines, code = self._score()
        self.assertEqual((lines, code), (CLEAN, 0))
        self.assertNotIn("---", lines)
        self.assertFalse(MARKS & set("".join(lines)))

    def test_markers_follow_the_line_order_of_the_block(self):
        lines, code = self._score("--note", "architecture=1 new hit: clean.complexity", "--note", "fix=reproduced, not live", fix="92", architecture="90")
        self.assertEqual(
            (lines, code),
            (
                [
                    "Metrics:", "🎯 Fix: 92 % ¹", "💥 Break: 2 %", "💸 Tokens: 100 %", "⏱️ Velocity: 100 %", "🛡️ Security: 100 %",
                    "⚖️ Legal: 100 %", "🏛️ Architecture: 90 % ²", "🏆 Score: 81", "---", "¹ reproduced, not live",
                    "² 1 new hit: clean.complexity", "", "🚦 Gate: ⚠️ ask: architecture 90 % < 100",
                ],
                3,
            ),
        )

    def test_a_critical_finding_keeps_the_block_and_stops_at_the_gate(self):
        lines, code = self._score(critical="1", security="50")
        self.assertEqual((lines[:-1], lines[-1], code), ([*CLEAN[:5], "🛡️ Security: 50 %", *CLEAN[6:8], "🏆 Score: 47", ""], "🚦 Gate: ⛔ do not commit: 1 critical security finding", 4))

    def test_no_line_above_the_rule_is_wider_than_30_characters(self):
        for extra, values in (
            (("--note", "architecture=x", "--note", "legal=y"), {"fix": "92.25", "break": "4.75", "efficiency": "100.5", "speed": "new", "security": "~99.5", "legal": "~99.5", "architecture": "99.5"}),
            (("--value", "12.5:3", "--note", "tokens=z"), {}),
        ):
            with self.subTest(extra=extra):
                lines, _ = self._score(*extra, **values)
                top = lines[: lines.index("---")]
                self.assertEqual([line for line in top if len(line) > WIDTH], [])

    def test_the_value_line_follows_security_and_changes_neither_score_nor_gate(self):
        for value in ("1:20", "4.1:1", "?"):
            with self.subTest(value=value):
                lines, code = self._score("--value", value, efficiency="120")
                plain, plain_code = self._score(efficiency="120")
                self.assertEqual(lines, [*plain[:6], f"💰 Value: {value}", *plain[6:]])
                self.assertEqual(code, plain_code)

    def test_the_message_block_prints_the_same_text(self):
        for values in ({}, {"break": "6"}, {"efficiency": "new"}, {"critical": "1"}, {"legal-blockers": "1"}):
            with self.subTest(values=values):
                shown = self._run(*flags({**BASE, **values}))
                block = self._run(*flags({**BASE, **values}), "--message-block")
                self.assertEqual((block.stdout, block.returncode), (shown.stdout, shown.returncode))


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
        self.worktree = f"📁 Worktree: {self.repo.resolve()}"

    def git(self, *args: str) -> str:
        return subprocess.run(["git", *args], cwd=self.repo, env=self.git_env, capture_output=True, text=True, check=True).stdout.strip()

    def table(self, *args: str) -> subprocess.CompletedProcess:
        return run(SCORE, [*flags(BASE), "--commit-table", *args], self.repo, self.env)

    def test_the_staged_table_leads_with_worktree_branch_and_diff_stat(self):
        result = self.table(str(self.repo))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), [self.worktree, "🌿 Branch: main", "📊 Diff stat: 2 files +3/-1", *CLEAN])

    def test_the_table_of_a_commit_shows_its_diff_stat_and_short_sha(self):
        self.git("commit", "-qm", "change")
        sha = self.git("rev-parse", "--short", "HEAD")
        lines = self.table(str(self.repo), "--commit", "HEAD").stdout.splitlines()
        self.assertEqual(lines, [self.worktree, "🌿 Branch: main", "📊 Diff stat: 2 files +3/-1", f"🔖 Commit: {sha}", *CLEAN])

    def test_a_value_line_joins_the_table_of_a_commit(self):
        self.git("commit", "-qm", "change")
        lines = self.table(str(self.repo), "--commit", "HEAD", "--value", "?").stdout.splitlines()
        self.assertEqual(lines[4:], [*CLEAN[:6], "💰 Value: ?", *CLEAN[6:]])

    def test_a_detached_head_and_a_directory_outside_git(self):
        self.git("commit", "-qm", "change")
        sha = self.git("rev-parse", "--short", "HEAD")
        self.git("checkout", "-q", "--detach", "HEAD")
        self.assertEqual(self.table(str(self.repo)).stdout.splitlines()[1:3], [f"🌿 Branch: detached at {sha}", "📊 Diff stat: 0 files +0/-0"])
        self.assertEqual(self.table(str(self.tmp)).returncode, 2)


if __name__ == "__main__":
    unittest.main()
