import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

from . import support


class TestScoring(support.SecurityCase):
    def test_changed_and_untracked_files_are_weighted(self):
        self.write("app.py", f"print(1)\ntoken = '{support.PLACEHOLDER}'  # MARK-HIGH\n")
        self.write("new.py", "a = 1  # MARK-LOW\nb = 2\nc = 3  # MARK-MEDIUM\nd = 4  # MARK-INFO\n")
        (self.repo / "gone.py").unlink()
        (self.repo / "link.py").symlink_to(self.repo / "old.py")
        result = self.scan(env=self.env)
        self.assertEqual(
            result.stdout,
            "🛡️ security 63 % critical 0 (medusa: 4 findings in 2 files: high app.py:2, medium new.py:3, low new.py:1, "
            "info new.py:4)\n",
        )
        self.assertEqual(result.returncode, 3, result.stderr)
        argv = json.loads((self.bin / "argv.json").read_text(encoding="utf-8"))
        self.assertEqual(
            [argv[0], *argv[2:4], argv[4], *argv[6:]],
            ["scan", "--format", "json", "-o", "--no-cache", "--workers", str(support.launch().host_workers())],
        )
        result = self.scan("--json", env=self.env)
        self.assertNotIn(support.PLACEHOLDER, result.stdout + result.stderr)
        found = json.loads(result.stdout)
        self.assertEqual(
            {k: found[k] for k in ("security", "files", "critical", "high", "medium", "low", "info")},
            {"security": 63, "files": 2, "critical": 0, "high": 1, "medium": 1, "low": 1, "info": 1},
        )
        self.assertEqual(
            found["findings"][0],
            {
                "severity": "high", "rule": "FAKE-HIGH", "path": "app.py", "line": 2,
                "sha1": hashlib.sha1(f"token = '{support.PLACEHOLDER}'  # MARK-HIGH".encode()).hexdigest(),
                "context": hashlib.sha1(f"print(1)\ntoken = '{support.PLACEHOLDER}'  # MARK-HIGH".encode()).hexdigest(),
            },
        )
        self.assertEqual(found["accepted"], [])
        home = Path((self.bin / "home.txt").read_text(encoding="utf-8"))
        self.assertNotEqual(home, self.base)
        self.assertTrue(home.name == "home" and home.parent.name.startswith("kvb-security-"), home)

    def test_stderr_names_the_medusa_that_ran_and_where_it_came_from(self):
        self.write("app.py", "print(2)\n")
        result = self.scan(env=self.env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"security: medusa {self.medusa} from PATH\n", result.stderr)

    def test_critical_exits_1_and_floors_at_0(self):
        self.write("app.py", "a  # MARK-CRITICAL\nb  # MARK-CRITICAL\nc  # MARK-CRITICAL\n")
        result = self.scan(env=self.env)
        self.assertTrue(result.stdout.startswith("🛡️ security 0 % critical 3 (medusa: 3 findings in 1 file: critical app.py:1, "))
        self.assertEqual(result.returncode, 1)

    def test_more_than_five_locations_are_cut(self):
        self.write("app.py", "".join(f"v{n}  # MARK-LOW\n" for n in range(7)))
        result = self.scan(env=self.env)
        self.assertEqual(
            result.stdout,
            "🛡️ security 86 % critical 0 (medusa: 7 findings in 1 file: low app.py:1, low app.py:2, low app.py:3, "
            "low app.py:4, low app.py:5, +2 more)\n",
        )
        self.assertEqual(result.returncode, 3)

    def test_clean_and_empty_changes_are_100(self):
        result = self.scan(env=self.env)
        self.assertEqual((result.stdout, result.returncode), ("🛡️ security 100 % critical 0 (medusa: 0 findings in 0 files)\n", 0))
        self.assertFalse((self.bin / "argv.json").exists())
        self.write("app.py", "print(2)\n")
        result = self.scan(env=self.env)
        self.assertEqual((result.stdout, result.returncode), ("🛡️ security 100 % critical 0 (medusa: 0 findings in 1 file)\n", 0))

    def test_missing_medusa_asks_for_a_review_by_hand(self):
        if shutil.which("medusa", path=support.GIT_DIR):
            self.skipTest("a real medusa sits next to git")
        self.write("app.py", "print(2)\n")
        result = self.scan(env={**self.env, "PATH": support.GIT_DIR})
        self.assertEqual((result.stdout, result.returncode), (f"🛡️ security – (medusa missing: {support.HAND})\n", 4))
        result = self.scan("--json", env={**self.env, "PATH": support.GIT_DIR})
        self.assertEqual(json.loads(result.stdout), {"security": None, "problem": "medusa missing"})

    def test_unreadable_report_asks_for_a_review_by_hand(self):
        self.write("app.py", "print(2)\n")
        result = self.scan(env={**self.env, "FAKE_MEDUSA_SHAPE": "other"})
        self.assertEqual(result.returncode, 4)
        self.assertRegex(result.stdout, r"^🛡️ security – \(medusa report unreadable: .*holds no findings list")

    def test_usage_errors_exit_2(self):
        result = subprocess.run(
            [sys.executable, str(support.SECURITY), "--repo", str(self.repo), "--base", "nope"],
            env=self.env, capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 2)
        result = subprocess.run(
            [sys.executable, str(support.SECURITY), "--repo", str(self.base / "absent"), "--base", "HEAD"],
            env=self.env, capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 2)
