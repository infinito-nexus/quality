import importlib.util
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ROLE = ROOT / "ansible" / "roles" / "web-app-cst-quality-check"
SCRIPT = ROLE / "files" / "python" / "script.py"
FAKE = Path(__file__).with_name("fake_container.py")
DEV_CONFIG = ROOT / "service" / "dev" / "config.json"
FINDING = {"rule": "r", "path": "p", "line": 1, "severity": "high", "summary": "s", "value": None, "commit": None, "lens": None}
REPORT = {
    "findings": [FINDING],
    "ignored": [],
    "nocheck": [],
    "unchecked": [],
    "notes": [],
    "incomplete": [],
    "parse_incomplete": [],
    "architecture": None,
}


def load_launcher():
    """
    Returns:
        The launcher script imported as the module `launcher`.
    """
    if "launcher" in sys.modules:
        return sys.modules["launcher"]
    spec = importlib.util.spec_from_file_location("launcher", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules["launcher"] = module
    spec.loader.exec_module(module)
    return module


def ident(number):
    return f"{number:032x}"


class Harness:
    def __init__(self, tmp_path):
        self.root = tmp_path
        self.state = tmp_path / "state"
        for name in ("spool", "reports", "claimed"):
            (self.state / name).mkdir(parents=True)
        self.calls = tmp_path / "calls.jsonl"
        self.behaviour = {"info": json.dumps({"runc": {}}) + "\n", "containers": [], "steps": {}}
        self.step(fetch=(0, "0123abc\n"), prepare=(0, ""), scan=(0, json.dumps(REPORT)), database=(0, ""))
        self.config = json.loads(DEV_CONFIG.read_text(encoding="utf-8"))
        behaviour = str(tmp_path / "behaviour.json")
        self.config.update(state_dir=str(self.state), jobs_dir=str(tmp_path / "jobs"))
        self.config.update(container=[sys.executable, str(FAKE), behaviour, str(self.calls)])
        self.config["database"]["dir"] = str(tmp_path / "db")

    def step(self, **steps):
        for name, (code, stdout) in steps.items():
            self.behaviour["steps"][name] = {"exit": code, "stdout": stdout}

    def submit(self, number, job, tier=2, age=0):  # nocheck: clean.default-value -- a fresh job of the lowest tier unless a queue test varies them
        """
        Args:
            number: Job number, turned into its 32-digit id.
            job: Job object, or raw text for a malformed job file.
            tier: Index into the launcher's TIERS; 2 (anonymous) by default, the tier that needs no account.
            age: Seconds the job file is backdated; 0 by default, a job that just arrived.
        """
        path = self.state / "spool" / f"{tier}-{ident(number)}.json"
        path.write_text(job if isinstance(job, str) else json.dumps(job), encoding="utf-8")
        os.utime(path, (time.time() - age, time.time() - age))
        return path

    def run(self):
        (self.root / "behaviour.json").write_text(json.dumps(self.behaviour), encoding="utf-8")
        (self.root / "config.json").write_text(json.dumps(self.config), encoding="utf-8")
        return load_launcher().main(["launcher", str(self.root / "config.json")])

    def report(self, number):
        path = self.state / "reports" / f"{ident(number)}.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None

    def calls_made(self):
        if not self.calls.exists():
            return []
        return [json.loads(line) for line in self.calls.read_text(encoding="utf-8").splitlines()]

    def runs(self):
        return [call for call in self.calls_made() if call["argv"][0] == "run"]
