from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.skills.gitcase import GitCase

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "skills" / "kvb-quality-performance" / "scripts" / "measure.py"
SPEC = importlib.util.spec_from_file_location("measure_under_test", SCRIPT)
measure = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(measure)
CHEAP = "print('cheap')\n"
COSTLY = "data = list(range(2_000_000))\nprint(sum(data))\n"
LINE = re.compile(
    r"^💸 tokens (?P<mark>~?)(?P<efficiency>\d+) % \(cpu \d+\.\d\d→\d+\.\d\d s, ram \d+\.\d→\d+\.\d MB\) · "
    r"⏱️ velocity (?P<speed_mark>~?)(?P<speed>\d+) % \((?P<basis>wall|cpu) \d+\.\d\d→\d+\.\d\d s\)(?P<tail>.*)$"
)


class Ticks:
    def __init__(self, busy: int):
        self.busy = busy
        self.calls = 0

    def __call__(self) -> tuple[int, int]:
        self.calls += 1
        return self.calls * self.busy, self.calls * 100


class TestMeasure(GitCase, unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.repo = self.base / "repo"
        self.repo.mkdir()
        self.env = {
            "PATH": os.environ["PATH"],
            "HOME": str(self.base),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": "Test",
            "GIT_AUTHOR_EMAIL": "test@example.org",
            "GIT_COMMITTER_NAME": "Test",
            "GIT_COMMITTER_EMAIL": "test@example.org",
        }
        self.git("init", "-q", "-b", "main")
        self.write({"pkg/work.py": COSTLY})
        self.commit({})
        self.leftovers = set(Path(tempfile.gettempdir()).glob("kvb-measure-*"))

    def work(self, *flags: str, **patched) -> tuple[int, str, str, int]:
        return self.measured("--base", "HEAD", *flags, "--", sys.executable, "work.py", **patched)

    def measured(self, *args: str, ticks=None, cwd: Path | None = None) -> tuple[int, str, str, int]:
        out, err = io.StringIO(), io.StringIO()
        with (
            mock.patch.dict(os.environ, self.env, clear=True),
            mock.patch.object(measure, "cpu_ticks", ticks if ticks is not None else Ticks(0)),
            mock.patch.object(measure, "SAMPLE_SECONDS", 0),
            mock.patch.object(measure, "sample", wraps=measure.sample) as samples,
            contextlib.chdir(cwd if cwd is not None else self.repo / "pkg"),
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(err),
        ):
            try:
                code = measure.main(list(args))
            except SystemExit as stop:
                code = stop.code
        return code, out.getvalue(), err.getvalue(), samples.call_count

    def line(self, out: str) -> re.Match:
        match = LINE.match(out.strip())
        self.assertIsNotNone(match, out)
        return match

    def assertCleanedUp(self):
        trees = [line for line in self.git("worktree", "list", "--porcelain").splitlines() if line.startswith("worktree ")]
        self.assertEqual(trees, [f"worktree {self.repo.resolve()}"])
        self.assertLessEqual(set(Path(tempfile.gettempdir()).glob("kvb-measure-*")), self.leftovers)

    def test_a_malformed_label_file_exits_2_before_any_run(self):
        labels = self.base / "labels.json"
        labels.write_text(json.dumps({"metrics": {"tokens": {"emoji": "💸", "label": "Tokens"}}}), encoding="utf-8")
        with mock.patch.object(measure, "LABELS", labels):
            code, out, err, samples = self.work()
        self.assertEqual((code, out, samples), (2, "", 0))
        self.assertEqual(len(err.splitlines()), 1, err)
        self.assertTrue(err.startswith(f"measure: labels {labels}: "), err)

    def cheap_line(self, **patched) -> re.Match:
        self.write({"pkg/work.py": CHEAP})
        code, out, err, samples = self.work(**patched)
        self.assertEqual((code, samples), (0, 2), err)
        return self.line(out)

    def test_cheaper_head_stops_after_one_run_each(self):
        match = self.cheap_line()
        self.assertEqual((match["mark"], match["speed_mark"], match["basis"], match["tail"]), ("", "", "wall", ""))
        self.assertLess(int(match["efficiency"]), 100)
        self.assertLess(int(match["speed"]), 100)
        self.assertCleanedUp()

    def test_costlier_head_takes_the_mean_of_5_and_exits_3(self):
        self.write({"pkg/work.py": CHEAP})
        self.commit({})
        self.write({"pkg/work.py": COSTLY})
        code, out, err, samples = self.work()
        self.assertEqual((code, samples), (3, 10), err)
        match = self.line(out)
        self.assertEqual((match["basis"], match["tail"]), ("wall", " · mean of 5"))
        self.assertGreater(int(match["efficiency"]), 100)
        self.assertGreater(int(match["speed"]), 100)
        code, out, _, _ = self.work("--json")
        found = json.loads(out)
        self.assertEqual((code, found["runs"], found["estimated"], found["other_load"]), (3, 5, False, 0))
        self.assertGreater(found["head"]["ram"], found["base"]["ram"])
        self.assertCleanedUp()

    def test_other_load_over_30_makes_an_estimate_from_cpu_time(self):
        match = self.cheap_line(ticks=Ticks(50))
        self.assertEqual(
            (match["mark"], match["speed_mark"], match["basis"], match["tail"]),
            ("~", "~", "cpu", " (estimated: other load 50 %)"),
        )
        _, out, _, _ = self.work("--json", ticks=Ticks(50))
        found = json.loads(out)
        self.assertEqual((found["estimated"], found["other_load"]), (True, 50))
        self.assertEqual(found["speed"], round(measure.ratio(found["head"]["cpu"], found["base"]["cpu"]) * 100))
        _, out, _, _ = self.work("--json", ticks=Ticks(30))
        self.assertEqual({k: json.loads(out)[k] for k in ("estimated", "other_load")}, {"estimated": False, "other_load": 30})
        self.assertCleanedUp()

    def test_unreadable_load_is_an_estimate(self):
        self.write({"pkg/work.py": CHEAP})
        code, out, err, _ = self.work(ticks=lambda: None)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.line(out)["tail"], " (estimated: other load unknown)")

    @unittest.skipUnless(measure.PROC_STAT.is_file(), "no /proc/stat on this platform")
    def test_proc_stat_yields_busy_and_total_jiffies(self):
        busy, total = measure.cpu_ticks()
        self.assertLessEqual(0, busy)
        self.assertLessEqual(busy, total)

    def test_failing_command_names_the_tree_and_exits_2(self):
        self.write({"pkg/work.py": "import sys\nsys.exit('broken here')\n"})
        code, out, err, _ = self.work()
        self.assertEqual((code, out), (2, ""))
        self.assertIn("exited 1 in the head tree", err)
        self.assertIn("broken here", err)
        self.assertCleanedUp()

    def test_usage_errors_exit_2(self):
        for args in (
            ("--base", "HEAD", sys.executable, "work.py"),
            ("--base", "HEAD", "--"),
            ("--base", "HEAD", "--runs", "1", "--", sys.executable, "work.py"),
            ("--base", "nope", "--", sys.executable, "work.py"),
            ("--", sys.executable, "work.py"),
        ):
            with self.subTest(args=args):
                self.assertEqual(self.measured(*args)[0], 2)
        self.assertCleanedUp()

    def test_missing_directory_at_base_exits_2(self):
        self.write({"new/work.py": CHEAP})
        code, _, err, _ = self.work(cwd=self.repo / "new")
        self.assertEqual(code, 2)
        self.assertIn("new does not exist at HEAD", err)
        self.assertCleanedUp()


if __name__ == "__main__":
    unittest.main()
