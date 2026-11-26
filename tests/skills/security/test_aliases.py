import hashlib
import json

from . import support


class TestAliases(support.SecurityCase):
    def test_mjs_and_cjs_files_medusa_skips_are_scanned_and_reported_at_their_repository_path(self):
        line = "run(request.query)  // MARK-HIGH"
        self.write("tool.mjs", f"import run from 'run';\n{line}\n")
        result = self.scan(env=self.env)
        self.assertEqual(
            (result.stdout, result.returncode),
            ("🛡️ security 75 % critical 0 (medusa: 1 finding in 1 file: high tool.mjs:2)\n", 3),
        )
        sha1 = hashlib.sha1(line.encode()).hexdigest()
        result = self.accept(
            "--rule", "FAKE-HIGH", "--path", "tool.mjs", "--sha1", sha1, "--line", "2", "--reason", "fixture"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.write("tool.mjs.js", "a  // MARK-MEDIUM\n")
        self.write("lib.CJS", "b  // MARK-LOW\n")
        result = self.scan(env=self.env)
        self.assertEqual(
            (result.stdout, result.returncode),
            ("🛡️ security 88 % critical 0 (medusa: 2 findings, 1 accepted in 3 files: medium tool.mjs.js:1, low lib.CJS:1)\n", 3),
        )

    def test_a_folder_named_like_the_alias_keeps_both_paths_apart(self):
        self.write("tool.mjs", "a  // MARK-HIGH\n")
        self.write("tool.mjs.js/inner.py", "b  # MARK-LOW\n")
        result = self.scan(env=self.env)
        self.assertEqual(
            (result.stdout, result.returncode),
            ("🛡️ security 73 % critical 0 (medusa: 2 findings in 2 files: high tool.mjs:1, low tool.mjs.js/inner.py:1)\n", 3),
        )

    def test_the_cache_keeps_the_repository_path_of_an_aliased_file(self):
        text = "a  // MARK-HIGH\n"
        self.write("tool.mjs", text)
        first = json.loads(self.scan("--json", env=self.env).stdout)
        (self.repo / "tool.mjs").unlink()
        self.write("tool.mjs.js", text)
        second = json.loads(self.scan("--json", env=self.env).stdout)
        self.assertEqual([f["path"] for f in first["findings"] + second["findings"]], ["tool.mjs", "tool.mjs.js"])

    def test_a_nested_mjs_file_is_reported_at_its_nested_path(self):
        self.write("a/b/tool.mjs", "a  // MARK-MEDIUM\n")
        result = self.scan(env=self.env)
        self.assertEqual(
            (result.stdout, result.returncode),
            ("🛡️ security 90 % critical 0 (medusa: 1 finding in 1 file: medium a/b/tool.mjs:1)\n", 3),
        )

    def test_an_mjs_file_name_without_room_for_the_alias_is_scanned_under_a_short_one(self):
        name = "t" * 250 + ".mjs"
        self.write(name, "a  // MARK-LOW\n")
        found = json.loads(self.scan("--json", env=self.env).stdout)
        self.assertEqual((found["files"], [(f["path"], f["line"]) for f in found["findings"]]), (1, [(name, 1)]))

    def test_an_mjs_only_diff_scores_from_a_real_scan_and_only_a_complete_run_is_cached(self):
        argv = self.bin / "argv.json"
        folder = self.base / "council" / "security-cache"
        self.write("tool.mjs", "a  // MARK-HIGH\n")
        rerun = "medusa run incomplete, nothing cached, rerun once the host is idle"
        timeout = "1 scanner error(s)/timeout(s) during scan: JavaScriptScanner (1)"
        cases = (
            ({"FAKE_MEDUSA_STDOUT": f"⚠️  {timeout}\n"}, f"{rerun}: {timeout}"),
            ({"FAKE_MEDUSA_FILE_LIMIT": "4"}, f"{rerun}: medusa counted 0 of 2 lines"),
        )
        for extra, problem in cases:
            with self.subTest(problem=problem):
                argv.unlink(missing_ok=True)
                result = self.scan(env={**self.env, **extra})
                self.assertEqual((result.stdout, result.returncode), (f"🛡️ security – ({problem}: {support.HAND})\n", 4))
                self.assertTrue(argv.exists())
                self.assertEqual(list(folder.glob("*.json")), [])
        scored = ("🛡️ security 75 % critical 0 (medusa: 1 finding in 1 file: high tool.mjs:1)\n", 3)
        argv.unlink()
        result = self.scan(env=self.env)
        self.assertEqual((result.stdout, result.returncode), scored)
        self.assertTrue(argv.exists())
        self.assertEqual(len(list(folder.glob("*.json"))), 1)
        argv.unlink()
        result = self.scan(env=self.env)
        self.assertEqual((result.stdout, result.returncode), scored)
        self.assertFalse(argv.exists())
