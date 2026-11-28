import hashlib
import json

from . import support


class TestAccepted(support.SecurityCase):
    def test_accepted_false_positive_leaves_the_score_until_its_line_changes(self):
        line = "x = compute()  # MARK-CRITICAL"
        self.write("app.py", f"print(1)\n{line}\n")
        sha1 = hashlib.sha1(line.encode()).hexdigest()
        result = self.accept("--rule", "FAKE-CRITICAL", "--path", "app.py", "--sha1", sha1, "--reason", "fixture marker")
        self.assertEqual(result.returncode, 0, result.stderr)
        listing = self.base / "council" / "security-accepted.jsonl"
        row = json.loads(listing.read_text(encoding="utf-8"))
        self.assertEqual(
            {k: row[k] for k in ("rule", "path", "sha1", "reason", "repo")},
            {"rule": "FAKE-CRITICAL", "path": "app.py", "sha1": sha1, "reason": "fixture marker",
             "repo": str(self.repo.resolve())},
        )
        result = self.scan(env=self.env)
        self.assertEqual(
            (result.stdout, result.returncode),
            ("🛡️ security 100 % critical 0 (medusa: 0 findings, 1 accepted in 1 file)\n", 0),
        )
        accepted = json.loads(self.scan("--json", env=self.env).stdout)["accepted"]
        self.assertEqual([(a["rule"], a["path"], a["line"]) for a in accepted], [("FAKE-CRITICAL", "app.py", 2)])
        self.write("app.py", "print(1)\nx = compute(2)  # MARK-CRITICAL\n")
        result = self.scan(env=self.env)
        self.assertEqual(
            (result.stdout, result.returncode),
            ("🛡️ security 50 % critical 1 (medusa: 1 finding in 1 file: critical app.py:2)\n", 1),
        )

    def test_one_acceptance_never_hides_an_identical_line_elsewhere(self):
        twin = "x = fetch(url)  # MARK-HIGH"
        self.write("app.py", f"print(1)\n{twin}\ny = 2\n{twin}\n")
        sha1 = hashlib.sha1(twin.encode()).hexdigest()
        both = ("🛡️ security 50 % critical 0 (medusa: 2 findings in 1 file: high app.py:2, high app.py:4)\n", 3)
        listing = self.base / "council" / "security-accepted.jsonl"
        listing.parent.mkdir(parents=True)
        listing.write_text(json.dumps({"rule": "FAKE-HIGH", "path": "app.py", "sha1": sha1}) + "\n", encoding="utf-8")
        result = self.scan(env=self.env)
        self.assertEqual((result.stdout, result.returncode), both)
        listing.unlink()
        refused = self.accept("--rule", "FAKE-HIGH", "--path", "app.py", "--sha1", sha1, "--reason", "fixture")
        self.assertEqual(refused.returncode, 2)
        self.assertIn("the line occurs 2 times in app.py; name the reviewed one with --line", refused.stderr)
        self.assertFalse(listing.exists())
        wrong = self.accept("--rule", "FAKE-HIGH", "--path", "app.py", "--sha1", sha1, "--line", "3", "--reason", "fixture")
        self.assertEqual(wrong.returncode, 2)
        self.assertIn("--sha1 is not the sha1 of line 3 of app.py", wrong.stderr)
        named = self.accept("--rule", "FAKE-HIGH", "--path", "app.py", "--sha1", sha1, "--line", "4", "--reason", "fixture")
        self.assertEqual(named.returncode, 0, named.stderr)
        result = self.scan(env=self.env)
        self.assertEqual(
            (result.stdout, result.returncode),
            ("🛡️ security 75 % critical 0 (medusa: 1 finding, 1 accepted in 1 file: high app.py:2)\n", 3),
        )
        self.write("app.py", f"print(1)\n{twin}\ny = 3\n{twin}\n")
        result = self.scan(env=self.env)
        self.assertEqual((result.stdout, result.returncode), both)

    def test_kept_rows_count_and_broken_rows_stop(self):
        line = "y = other()  # MARK-HIGH"
        self.write("app.py", f"{line}\n")
        kept = self.base / ".local" / "state" / "agents-council" / "security-accepted.jsonl"
        kept.parent.mkdir(parents=True)
        sha1 = hashlib.sha1(line.encode()).hexdigest()
        kept.write_text(json.dumps({"rule": "FAKE-HIGH", "path": "app.py", "sha1": sha1}) + "\n", encoding="utf-8")
        result = self.scan(env=self.env)
        self.assertEqual(result.stdout, "🛡️ security 100 % critical 0 (medusa: 0 findings, 1 accepted in 1 file)\n")
        kept.write_text('{"rule": "FAKE-HIGH"}\n', encoding="utf-8")
        result = self.scan(env=self.env)
        self.assertEqual(result.returncode, 2)
        self.assertIn("security-accepted.jsonl:1: want a JSON row with rule, path and sha1", result.stderr)
        result = self.accept("--rule", "R", "--path", "app.py", "--sha1", "XYZ", "--reason", "r")
        self.assertEqual(result.returncode, 2)
        self.assertIn("--sha1 must be 40 lowercase hex digits", result.stderr)

    def test_a_file_level_finding_is_accepted_by_the_sha1_of_its_file_until_the_file_changes(self):
        text = "FROM debian  # MARK-FILE\n"
        self.write("Dockerfile", text)
        sha1 = hashlib.sha1(text.encode()).hexdigest()
        self.assertEqual(json.loads(self.scan("--json", env=self.env).stdout)["findings"][0]["sha1"], sha1)
        result = self.accept("--rule", "FAKE-FILE", "--path", "Dockerfile", "--sha1", sha1, "--reason", "fixture")
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.scan(env=self.env)
        self.assertEqual(result.stdout, "🛡️ security 100 % critical 0 (medusa: 0 findings, 1 accepted in 1 file)\n")
        self.write("Dockerfile", text + "USER app\n")
        self.assertEqual(self.scan(env=self.env).returncode, 3)

    def test_a_sha1_of_no_line_and_not_of_the_file_is_never_accepted(self):
        self.write("app.py", "print(1)\n")
        future = hashlib.sha1(b"eval(x)  # MARK-HIGH").hexdigest()
        result = self.accept("--rule", "FAKE-HIGH", "--path", "app.py", "--sha1", future, "--reason", "fixture")
        self.assertEqual(result.returncode, 2)
        self.assertIn("names no line of app.py and is not the sha1 of the whole file", result.stderr)

    def test_one_accept_takes_every_rule_of_a_line(self):
        line = "z = both()  # MARK-HIGH MARK-LOW"
        self.write("app.py", f"{line}\n")
        sha1 = hashlib.sha1(line.encode()).hexdigest()
        result = self.accept(
            "--rule", "FAKE-HIGH", "--rule", "FAKE-LOW", "--path", "app.py", "--sha1", sha1, "--reason", "fixture"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("accepted FAKE-HIGH, FAKE-LOW app.py", result.stdout)
        result = self.scan(env=self.env)
        self.assertEqual(result.stdout, "🛡️ security 100 % critical 0 (medusa: 0 findings, 2 accepted in 1 file)\n")
