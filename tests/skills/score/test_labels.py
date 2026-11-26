from __future__ import annotations

import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path

from tests.skills.score.support import (
    LABELS,
    SCORE,
    SCRIPTS,
    SKILL,
    TempCase,
    flags,
    run,
)

FORMER = re.compile(r"💸 Cost|⏱️ Time|(?i:💸 cost|⏱️ time|\bcost (?:and|or) time\b|\bcost, time\b)")
OLD = re.compile(r"cost|time", re.IGNORECASE)
BASE = {
    "fix": "95", "break": "2", "efficiency": "97", "speed": "-", "security": "100", "critical": "0",
    "legal": "100", "legal-blockers": "0", "architecture": "100",
}
VARIANTS = (
    {},
    {"efficiency": "120", "speed": "130"},
    {"efficiency": "new", "speed": "new", "security": "~90"},
    {"fix": "80", "break": "10", "efficiency": "150"},
    {"critical": "1"},
)
LAYOUTS = ((), ("--message-block",))


class LabelCase(TempCase):
    def score(self, script: Path, *args: str) -> subprocess.CompletedProcess:
        return run(script, list(args), self.tmp, self.env)

    def copy_skill(self, labels: str) -> Path:
        """Args:
            labels: the text of the copied labels.json.

        Returns:
            The copied score.py, beside the copied journal.py.
        """
        scripts = self.tmp / "skills" / "kvb-quality-score" / "scripts"
        scripts.mkdir(parents=True)
        for name in ("score.py", "journal.py"):
            shutil.copy(SCRIPTS / name, scripts / name)
        (scripts.parent / "labels.json").write_text(labels, encoding="utf-8")
        return scripts / "score.py"


class TestScoreLabels(LabelCase):
    def test_every_layout_prints_tokens_and_velocity_never_cost_or_time(self):
        for values in VARIANTS:
            for layout in LAYOUTS:
                with self.subTest(values=values, layout=layout):
                    out = self.score(SCORE, *flags({**BASE, **values}), *layout).stdout
                    for label in ("💸 Tokens: ", "⏱️ Velocity: "):
                        self.assertIn(label, out)
                    self.assertIsNone(OLD.search(out), out)

    def test_no_skill_text_names_the_former_labels(self):
        found = [
            f"{path.relative_to(SKILL)}:{number}"
            for path in sorted(SKILL.rglob("*"))
            if path.is_file() and path.suffix != ".pyc"
            for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1)
            if FORMER.search(line)
        ]
        self.assertEqual(found, [])
        labels = json.loads(LABELS.read_text(encoding="utf-8"))["metrics"]
        self.assertEqual({key: metric["former"] for key, metric in labels.items() if metric["former"]}, {"tokens": ["Cost", "Efficiency"], "velocity": ["Time", "Speed"]})
        self.assertEqual((labels["tokens"]["emoji"], labels["velocity"]["emoji"]), ("💸", "⏱️"))

    def test_a_label_changed_in_a_temporary_label_file_shows_in_every_layout(self):
        labels = json.loads(LABELS.read_text(encoding="utf-8"))
        labels["metrics"]["tokens"]["label"] = "Pennies"
        labels["metrics"]["velocity"].update(emoji="🐢", label="Pace")
        labels["extras"]["legal"]["label"] = "Licence"
        script = self.copy_skill(json.dumps(labels, ensure_ascii=False))
        for layout in LAYOUTS:
            with self.subTest(layout=layout):
                block = self.score(script, *flags(BASE), *layout, "--value", "1:2").stdout.splitlines()
                self.assertEqual(block[3:8], ["💸 Pennies: 97 %", "🐢 Pace: –", "🛡️ Security: 100 %", "💰 Value: 1:2", "⚖️ Licence: 100 %"])
                self.assertEqual(block[-1], "🚦 Gate: ✅ 90/5, pennies and pace <= 100, security, licence and architecture 100 %")

    def test_a_malformed_label_file_exits_2_or_4_with_one_stderr_line_in_every_layout(self):
        labels = json.loads(LABELS.read_text(encoding="utf-8"))
        broken = [
            "{broken",
            json.dumps({"metrics": [], "extras": {}}),
            json.dumps({**labels, "metrics": {key: value for key, value in labels["metrics"].items() if key != "velocity"}}),
            json.dumps({**labels, "metrics": {**labels["metrics"], "fix": {"emoji": 1, "label": "Fix", "former": []}}}),
            json.dumps({**labels, "extras": {key: value for key, value in labels["extras"].items() if key != "architecture"}}),
        ]
        script = self.copy_skill("{}")
        cases = [(index, text, layout, critical, code) for index, text in enumerate(broken) for layout in LAYOUTS for critical, code in (("0", 2), ("1", 4))]
        for index, text, layout, critical, code in cases:
            (script.parents[1] / "labels.json").write_text(text, encoding="utf-8")
            with self.subTest(labels=index, layout=layout, critical=critical):
                done = self.score(script, *flags({**BASE, "critical": critical}), *layout)
                self.assertEqual((done.returncode, done.stdout), (code, ""))
                self.assertEqual(len(done.stderr.splitlines()), 1, done.stderr)
                self.assertTrue(done.stderr.startswith("score: labels "), done.stderr)


if __name__ == "__main__":
    unittest.main()
