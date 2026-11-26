import json
import shutil

from . import support


class TestCoverage(support.SecurityCase):
    def test_a_file_medusa_never_covers_is_named_with_its_limit_and_never_cached(self):
        argv = self.bin / "argv.json"
        folder = self.base / "council" / "security-cache"
        never = "medusa never covers this diff, nothing cached"
        big = "x = 1  # MARK-CRITICAL\n" + "#" * (2 * 1024 * 1024) + "\n"
        cases = (
            ({"big.json": big}, {}, f"{never}: big.json has {len(big)} bytes, over medusa's 2097152 byte file limit", False),
            ({"long.py": "x\n" * 50_000 + "y = 1  # MARK-CRITICAL\n"}, {},
             f"{never}: long.py has 50002 lines, over medusa's 50000 line regex limit", False),
            ({"cr.py": "x\r" * 50_000 + "y = 1  # MARK-CRITICAL\r"}, {},
             f"{never}: cr.py has 50002 lines, over medusa's 50000 line regex limit", False),
            ({"new.py": "x = 1  # MARK-CRITICAL\n"}, {"FAKE_MEDUSA_LOSE": "new.py"},
             f"{never}: medusa took up 1 of 2 files its rules take up", True),
            ({}, {"FAKE_MEDUSA_STDOUT": "⚠️  Skipped TREE/app.py (3 MB exceeds 2 MB limit)\n"},
             f"{never}: Skipped app.py (3 MB exceeds 2 MB limit)", True),
        )
        self.write("app.py", "print(2)\n")
        for files, extra, problem, ran in cases:
            with self.subTest(problem=problem):
                argv.unlink(missing_ok=True)
                for name, text in files.items():
                    self.write(name, text)
                result = self.scan(env={**self.env, **extra})
                self.assertEqual((result.stdout, result.returncode), (f"🛡️ security – ({problem}: {support.HAND})\n", 4))
                self.assertEqual(argv.exists(), ran)
                self.assertEqual(list(folder.glob("*.json")), [])
                for name in files:
                    (self.repo / name).unlink()

    def test_a_type_medusa_never_scans_is_listed_and_the_rest_scored(self):
        argv = self.bin / "argv.json"
        self.write("tpl.conf.j2", "token  # MARK-CRITICAL\n")
        never = "medusa never covers this diff, nothing cached"
        result = self.scan(env=self.env)
        self.assertEqual((result.stdout, result.returncode), (
            f"🛡️ security – ({never}: medusa scans none of its files, not covered: tpl.conf.j2: {support.HAND})\n", 4,
        ))
        self.assertFalse(argv.exists())
        self.write("app.py", "print(1)\nx = 1  # MARK-HIGH\n")
        scored = ("🛡️ security 75 % critical 0 (medusa: 1 finding in 1 file: high app.py:2; not covered: tpl.conf.j2)\n", 3)
        result = self.scan(env=self.env)
        self.assertEqual((result.stdout, result.returncode), scored)
        argv.unlink()
        result = self.scan(env=self.env)
        self.assertEqual((result.stdout, result.returncode), scored)
        self.assertFalse(argv.exists())
        found = json.loads(self.scan("--json", env=self.env).stdout)
        self.assertEqual((found["files"], found["not_covered"]), (1, ["tpl.conf.j2"]))
        self.medusa.write_text(support.FAKE.format(shebang="/usr/bin/env -S python -E"), encoding="utf-8")
        result = self.scan(env=self.env)
        self.assertEqual((result.stdout, result.returncode), scored)
        self.assertTrue(argv.exists())
        (self.package / "scanners" / "base.py").unlink()
        result = self.scan(env=self.env)
        unread = f"{never}: medusa's own types, exclusions and limits are unreadable from its source: {support.HAND}"
        self.assertEqual((result.stdout, result.returncode), (f"🛡️ security – ({unread})\n", 4))

    def test_a_file_behind_a_symlinked_folder_is_never_copied(self):
        self.write("dir/a.py", "x = 1\n")
        self.git("add", "-A")
        self.git("commit", "-qm", "dir")
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "a.py").write_text("secret = 1  # MARK-CRITICAL\n", encoding="utf-8")
        shutil.rmtree(self.repo / "dir")
        (self.repo / "dir").symlink_to(outside)
        self.write("app.py", "print(1)\nx = 1  # MARK-LOW\n")
        found = json.loads(self.scan("--json", env=self.env).stdout)
        self.assertEqual(([(f["path"], f["severity"]) for f in found["findings"]], found["files"]), ([("app.py", "low")], 1))

    def test_a_file_a_path_exclusion_drops_is_scanned_and_named_at_its_repository_path(self):
        self.write("app.py", "print(1)\nx = 1  # MARK-HIGH\n")
        self.write("utils/env/run.py", "y = 1  # MARK-LOW\n")
        self.write("environ.py", "z = 1  # MARK-LOW\n")
        self.write("build/lib.min.js", "a  // MARK-CRITICAL\n")
        found = json.loads(self.scan("--json", env=self.env).stdout)
        self.assertEqual(
            sorted((f["path"], f["line"], f["severity"]) for f in found["findings"]),
            [("app.py", 2, "high"), ("environ.py", 1, "low"), ("utils/env/run.py", 1, "low")],
        )
        self.assertEqual((found["files"], found["not_covered"]), (3, ["build/lib.min.js"]))
        sha1 = next(f["sha1"] for f in found["findings"] if f["path"] == "utils/env/run.py")
        accepted = self.accept("--rule", "FAKE-LOW", "--path", "utils/env/run.py", "--sha1", sha1, "--reason", "fixture")
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        again = json.loads(self.scan("--json", env=self.env).stdout)
        self.assertEqual(sorted(f["path"] for f in again["findings"]), ["app.py", "environ.py"])

    def test_medusa_limits_come_from_its_source(self):
        mark = "y = 1  # MARK-CRITICAL\n"
        cases = (
            (("64", "50_000"), ("64", "50000"), "wide.py", "#" * 70 + "\n" + mark,
             "wide.py has 94 bytes, over medusa's 64 byte file limit"),
            (("2 * 1024", "100"), ("2048", "100"), "tall.py", "\n" * 120 + mark,
             "tall.py has 122 lines, over medusa's 100 line regex limit"),
        )
        for (size, lines), (fake_size, fake_lines), name, text, problem in cases:
            with self.subTest(problem=problem):
                self.limits(size, lines, support.KNOB_TIMEOUT)
                self.write(name, text)
                fake = {"FAKE_MEDUSA_FILE_LIMIT": fake_size, "FAKE_MEDUSA_LINE_LIMIT": fake_lines}
                result = self.scan(env={**self.env, **fake})
                self.assertEqual(
                    (result.stdout, result.returncode),
                    (f"🛡️ security – (medusa never covers this diff, nothing cached: {problem}: {support.HAND})\n", 4),
                )
                (self.repo / name).unlink()
