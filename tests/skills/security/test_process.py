import os
import signal
import subprocess
import sys
import time

from . import support


class TestProcess(support.SecurityCase):
    def test_the_scanner_timeout_reaches_medusa_in_place_of_the_callers_and_takes_whole_seconds_only(self):
        knob = self.bin / "timeout.txt"
        cases = (((), str(support.launch().TIMEOUT)), (("--timeout", "86400"), "86400"))
        for number, (extra, handed) in enumerate(cases, 2):
            with self.subTest(handed=handed):
                self.write("app.py", f"print({number})\n")
                result = self.scan(*extra, env={**self.env, "MEDUSA_SCANNER_TIMEOUT": "5"})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(knob.read_text(encoding="utf-8"), handed)
        for flag in ("--timeout", "--deadline"):
            for value in ("0", "-1", "1.5", "x", "86401"):
                with self.subTest(flag=flag, value=value):
                    result = self.scan(flag, value, env=self.env)
                    self.assertEqual(result.returncode, 2)
                    self.assertIn(f"want whole seconds from 1 to 86400, got {value!r}", result.stderr)

    def test_a_scanner_fault_claims_no_cause_medusa_cannot_tell_apart(self):
        self.write("app.py", "print(2)\n")
        timed = "1 scanner error(s)/timeout(s) during scan: ModelAttackScanner (1)"
        unread = "1 director(ies) could not be read and were skipped (e.g. locked)"
        capped = (
            "a scanner crashed or hit medusa's fixed 2 s cap (medusa counts both together): rerun when idle; "
            "if it repeats, give medusa the MEDUSA_SCANNER_TIMEOUT knob"
        )
        erred = "scanner error (no scanner reached the 2 s cap): rerun when idle"
        rerun = "rerun once the host is idle"
        cases = (
            ("2", "2.2", timed, capped),
            ("2", "0", timed, erred),
            ("2", "2.2", unread, rerun),
            ("config.scanner_timeout()", "2.2", timed, rerun),
        )
        for timeout, sleep, line, advice in cases:
            with self.subTest(timeout=timeout, sleep=sleep, line=line):
                self.limits(support.SIZE, support.LINES, timeout)
                result = self.scan(env={**self.env, "FAKE_MEDUSA_STDOUT": f"⚠️  {line}\n", "FAKE_MEDUSA_SLEEP": sleep})
                problem = f"medusa run incomplete, nothing cached, {advice}: {line}"
                self.assertEqual((result.stdout, result.returncode), (f"🛡️ security – ({problem}: {support.HAND})\n", 4))

    def test_a_medusa_run_past_the_deadline_takes_its_whole_group_and_names_the_flag_to_raise(self):
        self.write("app.py", "print(2)\n")
        start = time.monotonic()
        result = self.scan("--deadline", "1", env={**self.env, "FAKE_MEDUSA_SLEEP": "30", "FAKE_MEDUSA_CHILD": "1"})
        self.assertLess(time.monotonic() - start, 8)
        problem = (
            "medusa run incomplete, nothing cached, medusa ran past its 1 s --deadline: "
            "rerun it in the background with --deadline raised, up to 86400"
        )
        self.assertEqual((result.stdout, result.returncode), (f"🛡️ security – ({problem}: {support.HAND})\n", 4))
        self.assertTrue(all(support.gone(pid, support.WAIT) for pid in self.started(support.MARKERS)))
        self.assertEqual(list((self.base / "council" / "security-cache").glob("*.json")), [])

    def test_a_stop_signal_to_security_py_takes_medusa_and_its_child_along(self):
        self.write("app.py", "print(2)\n")
        env = {**self.env, "FAKE_MEDUSA_SLEEP": "30", "FAKE_MEDUSA_CHILD": "1"}
        for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGKILL):
            with self.subTest(signal=number.name):
                for name in support.MARKERS:
                    (self.bin / name).unlink(missing_ok=True)
                security = subprocess.Popen(
                    [sys.executable, str(support.SECURITY), "--repo", str(self.repo), "--base", "HEAD"], cwd=self.base,
                    env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
                )
                medusa, child = self.started(support.MARKERS)
                os.killpg(security.pid, number)
                self.assertEqual(security.wait(timeout=20), -number)
                self.assertTrue(support.gone(medusa, support.WAIT))
                if number != signal.SIGKILL:
                    self.assertTrue(support.gone(child, support.WAIT))

    def test_signals_the_caller_ignores_stay_ignored_and_the_scan_scores(self):
        self.write("app.py", "print(2)\n")
        ignored = (signal.SIGHUP, signal.SIGINT)
        previous = {number: signal.signal(number, signal.SIG_IGN) for number in ignored}
        try:
            security = subprocess.Popen(
                [sys.executable, str(support.SECURITY), "--repo", str(self.repo), "--base", "HEAD"], cwd=self.base,
                env={**self.env, "FAKE_MEDUSA_SLEEP": "2"}, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, start_new_session=True,
            )
        finally:
            for number, handler in previous.items():
                signal.signal(number, handler)
        self.started(("pid.txt",))
        for number in ignored:
            os.killpg(security.pid, number)
        out, _ = security.communicate(timeout=20)
        self.assertEqual((out, security.returncode), ("🛡️ security 100 % critical 0 (medusa: 0 findings in 1 file)\n", 0))

    def test_a_libc_without_prctl_only_loses_the_parent_death_signal(self):
        self.write("app.py", "print(2)\n")
        wrap = (
            "import ctypes, os, runpy, sys; ctypes.CDLL = lambda *args, **kwargs: object(); "
            "sys.argv = sys.argv[1:]; sys.path.insert(0, os.path.dirname(sys.argv[0])); "
            "runpy.run_path(sys.argv[0], run_name='__main__')"
        )
        result = subprocess.run(
            [sys.executable, "-c", wrap, str(support.SECURITY), "--repo", str(self.repo), "--base", "HEAD"],
            cwd=self.base, env=self.env, capture_output=True, text=True, check=False,
        )
        self.assertEqual(
            (result.stdout, result.returncode), ("🛡️ security 100 % critical 0 (medusa: 0 findings in 1 file)\n", 0), result.stderr,
        )
