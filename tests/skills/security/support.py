import contextlib
import importlib.util
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import ModuleType

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = REPO_ROOT / "skills" / "kvb-quality-security" / "scripts"
SECURITY = SCRIPTS / "security.py"
SOURCE = REPO_ROOT / "src"
GIT_DIR = os.path.dirname(shutil.which("git"))
PLACEHOLDER = "placeholder-value-never-shown"
FAKE = """#!{shebang}
import json, os, pathlib, subprocess, sys, time
args = sys.argv[1:]
pathlib.Path(__file__).with_name("argv.json").write_text(json.dumps(args))
pathlib.Path(__file__).with_name("home.txt").write_text(os.environ["HOME"])
pathlib.Path(__file__).with_name("timeout.txt").write_text(os.environ.get("MEDUSA_SCANNER_TIMEOUT", "unset"))
if os.environ.get("FAKE_MEDUSA_CHILD"):
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    pathlib.Path(__file__).with_name("child.txt").write_text(str(child.pid))
pathlib.Path(__file__).with_name("pid.txt").write_text(str(os.getpid()))
time.sleep(float(os.environ.get("FAKE_MEDUSA_SLEEP", "0")))
pathlib.Path(os.environ["HOME"], ".medusa").mkdir()
target, out = pathlib.Path(args[1]), pathlib.Path(args[args.index("-o") + 1])
out.mkdir(parents=True)
limit = int(os.environ.get("FAKE_MEDUSA_FILE_LIMIT", str(2 * 1024 * 1024)))
findings, taken, counted = [], 0, 0
for path in sorted(p for p in target.rglob("*") if p.is_file()):
    if path.suffix.lower() not in (".py", ".json", ".js") and not path.name.startswith("Dockerfile"):
        continue
    if path.name == os.environ.get("FAKE_MEDUSA_LOSE") or any(p in str(path.relative_to(target)) for p in ("build", "env")):
        continue
    taken += 1
    if path.stat().st_size > limit:
        continue
    counted += path.read_bytes().count(b"\\n") + 1
    cut = int(os.environ.get("FAKE_MEDUSA_LINE_LIMIT", "50000"))
    for number, text in enumerate(path.read_text().split("\\n")[:cut], 1):
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if "MARK-" + severity in text:
                findings.append({{
                    "severity": severity, "rule_id": "FAKE-" + severity, "file": str(path), "line": number,
                    "code": text,
                }})
        if "MARK-FILE" in text:
            findings.append({{"severity": "MEDIUM", "rule_id": "FAKE-FILE", "file": str(path), "line": None}})
if not taken:
    print("No files found to scan")
    sys.exit(0)
report = {{"findings": findings, "scan_summary": {{"files_scanned": taken, "lines_scanned": counted}}}}
if os.environ.get("FAKE_MEDUSA_SHAPE") == "other":
    report = {{"issues": findings}}
if os.environ.get("FAKE_MEDUSA_SHAPE") == "nocounts":
    report = {{"findings": findings, "scan_summary": {{"files_scanned": taken}}}}
(out / "medusa-scan-20261104-120000.json").write_text(json.dumps(report))
sys.stdout.write(os.environ.get("FAKE_MEDUSA_STDOUT", "").replace("TREE", str(target)))
sys.exit(int(os.environ.get("FAKE_MEDUSA_EXIT", "0")))
"""
BASE = "class RuleBasedScanner:\n    MAX_RULE_SCAN_LINES = {lines}\n"
CONFIG = """@dataclass
class MedusaConfig:
    exclude_paths: List[str] = field(default_factory=lambda: ["build/", "env/"])
    exclude_files: List[str] = field(default_factory=lambda: ["*.min.js"])
"""
PARALLEL = """MAX_SCAN_FILE_SIZE = {size}
PER_SCANNER_TIMEOUT = {timeout}


class MedusaParallelScanner:
    FILE_SCANNERS = {{".py": "python", ".json": "json", ".js": "javascript"}}

    def find_scannable_files(self):
        special_exact_names: Set[str] = {{"mcp.json"}}
        special_prefixes = ("Dockerfile", ".env")
        env_suffix = ".env"
        ai_context_dir_names: Set[str] = {{".claude"}}
"""
SIZE = "2 * 1024 * 1024"
LINES = "50_000"
KNOB_TIMEOUT = 'int(os.environ.get("MEDUSA_SCANNER_TIMEOUT") or 60)'
HAND = "review trust boundaries, secrets and injection in the diff by hand, then pass --security '~<n>' to kvb-quality-score"
MARKERS = ("pid.txt", "child.txt")
WAIT = 5.0
START_SECONDS = 20


def gone(pid: int, wait: float) -> bool:
    """
    Args:
        pid: the process to watch.
        wait: seconds to wait for it to end.

    Returns:
        Whether the process is gone or a zombie within wait seconds.
    """
    until = time.monotonic() + wait
    while True:
        try:
            state = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8").rsplit(")", 1)[1].split()[0]
        except OSError:
            return True
        if state in "ZX":
            return True
        if time.monotonic() >= until:
            return False
        time.sleep(0.05)


def ended(pids: list[int]) -> None:
    for pid in pids:
        if not gone(pid, 0):
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)


def launch() -> ModuleType:
    """
    Returns:
        launch.py of the skill under a name of its own, so a module of the
        same name elsewhere never stands in for it; it imports no sibling.
    """
    spec = importlib.util.spec_from_file_location("kvb_quality_security_launch", SCRIPTS / "launch.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SecurityCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        venv = self.base / "venv"
        self.bin = venv / "bin"
        self.bin.mkdir(parents=True)
        real = Path(sys.executable).resolve()
        (self.bin / "python").symlink_to(real)
        (venv / "pyvenv.cfg").write_text(f"home = {real.parent}\ninclude-system-site-packages = false\n", encoding="utf-8")
        version = f"python{sys.version_info.major}.{sys.version_info.minor}"
        self.package = venv / "lib" / version / "site-packages" / "medusa"
        self.limits(SIZE, LINES, KNOB_TIMEOUT)
        (self.package / "__init__.py").write_text("", encoding="utf-8")
        (self.package / "config.py").write_text(CONFIG, encoding="utf-8")
        self.medusa = self.bin / "medusa"
        self.medusa.write_text(FAKE.format(shebang=f"{self.bin / 'python'} -E"), encoding="utf-8")
        self.medusa.chmod(0o755)
        self.repo = self.base / "repo"
        self.repo.mkdir()
        self.env = {
            "PATH": f"{self.bin}:{GIT_DIR}",
            "HOME": str(self.base),
            "PYTHONPATH": str(SOURCE),
            "PYTHONDONTWRITEBYTECODE": "1",
            "AGENTS_COUNCIL_ROOT": str(self.base / "council"),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": "Test",
            "GIT_AUTHOR_EMAIL": "test@example.org",
            "GIT_COMMITTER_NAME": "Test",
            "GIT_COMMITTER_EMAIL": "test@example.org",
        }
        self.git("init", "-q", "-b", "main")
        self.write("app.py", "print(1)\n")
        self.write("old.py", "x = 1  # MARK-CRITICAL\n")
        self.write("gone.py", "y = 2  # MARK-HIGH\n")
        self.git("add", "-A")
        self.git("commit", "-qm", "base")

    def limits(self, size: str, lines: str, timeout: str) -> None:
        """
        Args:
            size: the expression the fake medusa assigns MAX_SCAN_FILE_SIZE.
            lines: the expression it assigns MAX_RULE_SCAN_LINES.
            timeout: the expression it assigns PER_SCANNER_TIMEOUT.
        """
        parallel = PARALLEL.format(size=size, timeout=timeout)
        for name, text in (("core/parallel.py", parallel), ("scanners/base.py", BASE.format(lines=lines))):
            (self.package / name).parent.mkdir(parents=True, exist_ok=True)
            (self.package / name).write_text(text, encoding="utf-8")

    def git(self, *args: str) -> None:
        subprocess.run(["git", *args], cwd=self.repo, env=self.env, capture_output=True, check=True)

    def started(self, names: tuple[str, ...]) -> list[int]:
        """
        Args:
            names: the files the fake medusa writes its own pid or its
                child's to.

        Returns:
            Those pids, once all are written; all are killed on cleanup.
        """
        markers = [self.bin / name for name in names]
        until = time.monotonic() + START_SECONDS
        while not all(m.exists() and m.read_text(encoding="utf-8") for m in markers) and time.monotonic() < until:
            time.sleep(0.05)
        pids = [int(m.read_text(encoding="utf-8")) for m in markers]
        self.addCleanup(ended, pids)
        return pids

    def write(self, path: str, text: str) -> None:
        (self.repo / path).parent.mkdir(parents=True, exist_ok=True)
        (self.repo / path).write_text(text, encoding="utf-8")

    def scan(self, *extra: str, env: dict[str, str]) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(SECURITY), "--repo", str(self.repo), "--base", "HEAD", *extra],
            cwd=self.base, env=env, capture_output=True, text=True, check=False,
        )

    def accept(self, *flags: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(SECURITY), "accept", "--repo", str(self.repo), *flags],
            cwd=self.base, env=self.env, capture_output=True, text=True, check=False,
        )
