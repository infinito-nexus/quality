import json
import os

from . import support


class TestCache(support.SecurityCase):
    def test_a_rescan_of_unchanged_files_reads_the_cache_and_any_edit_runs_medusa_again(self):
        self.write("app.py", "print(1)\nx = 1  # MARK-HIGH\n")
        argv = self.bin / "argv.json"
        first = self.scan("--json", env=self.env)
        self.assertTrue(argv.exists())
        argv.unlink()
        again = self.scan("--json", env=self.env)
        self.assertEqual((again.stdout, again.returncode), (first.stdout, first.returncode))
        self.assertFalse(argv.exists())
        self.assertEqual(len(list((self.base / "council" / "security-cache").glob("*.json"))), 1)
        self.write("app.py", "print(1)\nx = 2  # MARK-HIGH\n")
        edited = self.scan("--json", env=self.env)
        self.assertTrue(argv.exists())
        self.assertNotEqual(json.loads(edited.stdout)["findings"][0]["sha1"], json.loads(first.stdout)["findings"][0]["sha1"])
        argv.unlink()
        (self.repo / "app.py").chmod(0o755)
        self.scan(env=self.env)
        self.assertTrue(argv.exists())
        argv.unlink()
        medusa = self.bin / "medusa"
        os.utime(medusa, ns=(medusa.stat().st_atime_ns, medusa.stat().st_mtime_ns + 1))
        self.scan(env=self.env)
        self.assertTrue(argv.exists())
        argv.unlink()
        self.scan(env={**self.env, "MEDUSA_TRACE_RULES": "1"})
        self.assertTrue(argv.exists())

    def test_an_expired_tampered_or_shared_cache_runs_medusa(self):
        self.write("app.py", "print(2)\n")
        argv = self.bin / "argv.json"
        folder = self.base / "council" / "security-cache"
        self.scan(env=self.env)
        [entry] = folder.glob("*.json")
        os.utime(entry, (0, 0))
        argv.unlink()
        self.scan(env=self.env)
        self.assertTrue(argv.exists())
        self.assertEqual(list(folder.glob("*.json")), [entry])
        self.assertGreater(entry.stat().st_mtime, 0)
        entry.write_text('[{"severity": "none"}]', encoding="utf-8")
        argv.unlink()
        result = self.scan(env=self.env)
        self.assertTrue(argv.exists())
        self.assertEqual(result.stdout, "🛡️ security 100 % critical 0 (medusa: 0 findings in 1 file)\n")
        folder.chmod(0o777)
        entry.unlink()
        argv.unlink()
        self.scan(env=self.env)
        self.assertTrue(argv.exists())
        self.assertEqual(list(folder.glob("*.json")), [])

    def test_an_incomplete_run_is_never_cached_and_never_scored(self):
        self.write("app.py", "print(2)\n")
        argv = self.bin / "argv.json"
        folder = self.base / "council" / "security-cache"
        warn = "⚠️  "
        rerun = "medusa run incomplete, nothing cached, rerun once the host is idle"
        cases = (
            ({"FAKE_MEDUSA_STDOUT": f"Found 1 scannable files\n{warn}1 scanner error(s)/timeout(s) during scan: "
              "OWASPLLMScanner (1)\n"}, f"{rerun}: 1 scanner error(s)/timeout(s) during scan: OWASPLLMScanner (1)"),
            ({"FAKE_MEDUSA_STDOUT": f"{warn}1 director(ies) could not be read and were skipped (e.g. TREE/locked)\n"},
             f"{rerun}: 1 director(ies) could not be read and were skipped (e.g. locked)"),
            ({"FAKE_MEDUSA_EXIT": "3"}, f"{rerun}: medusa exit 3"),
            ({"FAKE_MEDUSA_FILE_LIMIT": "4"}, f"{rerun}: medusa counted 0 of 2 lines"),
            ({"FAKE_MEDUSA_SHAPE": "nocounts"},
             ("medusa report unreadable: medusa-scan-20261104-120000.json holds no files_scanned and lines_scanned "
              "counts (medusa exit 0)")),
        )
        for extra, problem in cases:
            with self.subTest(problem=problem):
                result = self.scan(env={**self.env, **extra})
                self.assertEqual((result.stdout, result.returncode), (f"🛡️ security – ({problem}: {support.HAND})\n", 4))
                self.assertEqual(list(folder.glob("*.json")), [])
        result = self.scan("--json", env={**self.env, "FAKE_MEDUSA_EXIT": "3"})
        self.assertEqual(json.loads(result.stdout), {"security": None, "problem": f"{rerun}: medusa exit 3"})
        argv.unlink()
        complete = self.scan(env=self.env)
        self.assertEqual((complete.stdout, complete.returncode), ("🛡️ security 100 % critical 0 (medusa: 0 findings in 1 file)\n", 0))
        self.assertTrue(argv.exists())
        self.assertEqual(len(list(folder.glob("*.json"))), 1)
        argv.unlink()
        again = self.scan(env=self.env)
        self.assertEqual((again.stdout, again.returncode), (complete.stdout, complete.returncode))
        self.assertFalse(argv.exists())

    def test_the_cache_key_holds_the_timeout_medusa_got_not_the_callers(self):
        self.write("app.py", "print(2)\n")
        argv = self.bin / "argv.json"
        self.scan(env={**self.env, "MEDUSA_SCANNER_TIMEOUT": "5"})
        argv.unlink()
        self.scan(env={**self.env, "MEDUSA_SCANNER_TIMEOUT": "6"})
        self.assertFalse(argv.exists())
        self.scan("--timeout", "7", env=self.env)
        self.assertTrue(argv.exists())
