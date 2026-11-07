import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
RULES = ROOT / "rules"
RESERVED = ("tools.yml", "limits.yml", "kinds.yml")
AUTHOR_NAME = "QualityAuthorCanary"
AUTHOR_EMAIL = "quality-author-canary@example.invalid"
# Exception: -I keeps the target's directory off sys.path. `python -m quality`
# from the target would import a planted yaml.py before any check runs.
LAUNCHER = (
    "import sys\n"
    f"sys.path.insert(0, {str(SRC)!r})\n"
    "from quality.cli import main\n"
    "sys.exit(main(sys.argv[1:]))\n"
)


def git_env() -> dict:
    return {
        "PATH": os.environ["PATH"],
        "HOME": os.devnull,
        "TMPDIR": tempfile.gettempdir(),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_AUTHOR_NAME": AUTHOR_NAME,
        "GIT_AUTHOR_EMAIL": AUTHOR_EMAIL,
        "GIT_COMMITTER_NAME": AUTHOR_NAME,
        "GIT_COMMITTER_EMAIL": AUTHOR_EMAIL,
    }


def git(cwd: Path, *args: str, tolerate_failure: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        env=git_env(),
        capture_output=True,
        text=True,
        check=not tolerate_failure,
    )


def raw_tool(cwd: Path, *argv: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        argv,
        cwd=cwd,
        env={**git_env(), "RUFF_NO_CACHE": "true", "PYTHONDONTWRITEBYTECODE": "1"},
        capture_output=True,
        text=True,
        errors="replace",
        check=False,
    )


def launcher_argv(*args: str) -> list:
    # Exception: -I also ignores PYTHONDONTWRITEBYTECODE, so -B keeps the
    # source tree free of bytecode.
    return [sys.executable, "-I", "-B", "-c", LAUNCHER, *args]


def quality(cwd: Path, *args: str, path_value: str | None = None) -> subprocess.CompletedProcess:
    env = {
        "PATH": path_value if path_value is not None else os.environ["PATH"],
        "TMPDIR": tempfile.gettempdir(),
    }
    return subprocess.run(
        launcher_argv(*args),
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


class Target:
    def __init__(self, path: Path):
        self.path = path

    @classmethod
    def create(cls, path: Path) -> "Target":
        path.mkdir(parents=True)
        git(path, "init", "-q", "-b", "main")
        return cls(path)

    def write(self, relative: str, text: str) -> None:
        destination = self.path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding="utf-8")

    def git(self, *args: str, tolerate_failure: bool = False) -> subprocess.CompletedProcess:
        return git(self.path, *args, tolerate_failure=tolerate_failure)

    def stage(self) -> None:
        self.git("add", "-A")

    def commit(self, message: str = "") -> str:
        self.stage()
        self.git("commit", "-q", "--allow-empty", "--allow-empty-message", "-m", message)
        return self.git("rev-parse", "HEAD").stdout.strip()

    def check(self, *args: str, path_value: str | None = None) -> subprocess.CompletedProcess:
        return quality(self.path, "check", *args, path_value=path_value)

    def judge(self, mode: str, *args: str) -> subprocess.CompletedProcess:
        flags = ("--staged",) if mode == "staged" else ("--base", "main")
        return self.check(*flags, *args)

    def advance(self, mode: str) -> None:
        self.stage()
        if mode == "base":
            self.git("commit", "-q", "--allow-empty-message", "-m", "")

    def start_feature(self, mode: str) -> None:
        self.commit()
        if mode == "base":
            self.git("checkout", "-q", "-b", "feature")


def report(result: subprocess.CompletedProcess) -> dict:
    assert result.returncode in (0, 1, 2), result.stderr
    return json.loads(result.stdout)


def rule_ids(result: subprocess.CompletedProcess) -> list:
    return [finding["rule"] for finding in report(result)["findings"]]


def catalogue() -> list:
    rules = []
    for path in sorted(RULES.glob("*.yml")):
        if path.name not in RESERVED:
            rules += yaml.safe_load(path.read_text(encoding="utf-8")) or []
    return rules


def tools() -> dict:
    return yaml.safe_load((RULES / "tools.yml").read_text(encoding="utf-8"))


def rule_for(code: str) -> str:
    for rule in catalogue():
        enforcer = rule["enforcer"]
        for settings in enforcer.values() if isinstance(enforcer, dict) else ():
            if code in settings.get("codes", ()) or code in settings.get("always_reported", ()):
                return rule["id"]
    raise AssertionError(f"no rule enforces {code}")


def pending_tools() -> list:
    return sorted(
        {
            settings["tool"]
            for rule in catalogue()
            if rule.get("pending")
            for settings in rule["enforcer"].values()
        }
    )


def needs_gitleaks() -> None:
    if shutil.which("gitleaks") is None or "gitleaks" not in tools():
        pytest.skip(
            "needs gitleaks: decision 14 names it as the secret scanner, it is not "
            "installed, and phase C adds its adapter and canary"
        )


def rules_copy(destination: Path) -> Path:
    shutil.copytree(RULES, destination)
    return destination


def rules_without_pending(destination: Path) -> Path:
    rules_copy(destination)
    for path in sorted(destination.glob("*.yml")):
        if path.name not in RESERVED:
            kept = [rule for rule in yaml.safe_load(path.read_text()) if not rule.get("pending")]
            path.write_text(yaml.safe_dump(kept), encoding="utf-8")
    return destination


def edit_yaml(path: Path, change) -> None:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    change(document)
    path.write_text(yaml.safe_dump(document), encoding="utf-8")


def add_rules(directory: Path, rules: list) -> None:
    (directory / "fixture.yml").write_text(yaml.safe_dump(rules), encoding="utf-8")


def write_shim(directory: Path, name: str, body: str) -> None:
    directory.mkdir(exist_ok=True)
    shim = directory / name
    shim.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    shim.chmod(0o755)


def path_with(directory: Path) -> str:
    return f"{directory}{os.pathsep}{os.environ['PATH']}"


def path_without(directory: Path, missing: str) -> str:
    directory.mkdir()
    for name in ("git", *tools()):
        if name != missing:
            (directory / name).symlink_to(shutil.which(name))
    return str(directory)


def branchy(name: str, count: int) -> str:
    body = "".join(f"    if a == {index}:\n        return {index}\n" for index in range(count))
    return f"def {name}(a):\n{body}    return -1\n"


def write_every_kind(target: Target) -> None:
    target.write("pkg/__init__.py", "")
    target.write("pkg/code.py", "import os  # noqa\n\n\n" + branchy("branchy", 12))
    target.write("run.sh", "#!/bin/bash\necho $1\n")
    target.write(
        ".github/workflows/w.yml",
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: echo ${{ undefined.thing }}\n",
    )


EVERY_KIND_RULES = {
    "coding.unused-import",
    "coding.shell-lint",
    "coding.workflow-lint",
    "clean.complexity",
    "clean.tool-pragma",
}
