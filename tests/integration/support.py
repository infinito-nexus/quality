import atexit
import functools
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

from quality.adapters.base import thread_environment

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
RULES = ROOT / "rules"
RESERVED = ("tools.yml", "limits.yml", "kinds.yml", "comments.yml")
TEST_CACHE = Path(tempfile.gettempdir()) / "quality-test-cache"
TEST_DB = TEST_CACHE / "quality" / "db"
NO_BUNDLE_CACHE = Path(tempfile.gettempdir()) / "quality-test-no-bundle"
TOOL_THREADS = 1
DEEP_TOOLS = ("jscpd", "osv-scanner", "semgrep", "trivy")
VULNERABLE_PIN = "requests==2.19.0\n"
AUTHOR_NAME = "QualityAuthorCanary"
AUTHOR_EMAIL = "quality-author-canary@example.invalid"
SECRET = "ghp_" + "8fK2mQ7xL4pN9sV1" + "tB6yR3wZ0cH5jD2gA7eU"
SECRET_ENV_LINE = f"GITHUB_TOKEN={SECRET}\n"
UNTAGGED_DOCKERFILE = "FROM debian\n"
RAW_GITLEAKS = ("--no-banner", "--report-format", "json", "--report-path", "-")
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
        env={
            **git_env(),
            **thread_environment(TOOL_THREADS),
            "RUFF_NO_CACHE": "true",
            "PYTHONDONTWRITEBYTECODE": "1",
        },
        capture_output=True,
        text=True,
        errors="replace",
        check=False,
    )


def launcher_argv(*args: str) -> list:
    return [sys.executable, "-I", "-B", "-c", LAUNCHER, *args]


def quality(
    cwd: Path, *args: str, path_value: str | None = None, extra_env: dict | None = None
) -> subprocess.CompletedProcess:
    """
    Args:
        cwd: Directory quality runs in.
        args: Command line after the program name.
        path_value: PATH, or None for the caller's.
        extra_env: Variables added to or replacing PATH, TMPDIR and XDG_CACHE_HOME,
            or None. XDG_CACHE_HOME names a directory without a bundle, so the
            deep tier exits 2 unless a test brings the shared test bundle.

    Returns:
        The finished process.
    """
    env = {
        "PATH": path_value if path_value is not None else os.environ["PATH"],
        "TMPDIR": tempfile.gettempdir(),
        "XDG_CACHE_HOME": str(NO_BUNDLE_CACHE),
        **(extra_env or {}),
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
    def __init__(self, path: Path, deep: bool = False):
        """
        Args:
            path: Work tree of the repository.
            deep: True checks with the packaged rule data and the shared test
                bundle; False with the fast tier only and no bundle, unless a
                check passes its own --rules.
        """
        self.path = path
        self.deep = deep

    @classmethod
    def create(cls, path: Path, deep: bool = False) -> "Target":
        path.mkdir(parents=True)
        git(path, "init", "-q", "-b", "main")
        return cls(path, deep)

    def rule_args(self, args: tuple) -> tuple:
        if self.deep or "--rules" in args:
            return ()
        return ("--rules", str(fast_rules()))

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

    def check(
        self, *args: str, path_value: str | None = None, extra_env: dict | None = None
    ) -> subprocess.CompletedProcess:
        cache = TEST_CACHE if self.deep else NO_BUNDLE_CACHE
        env = {"XDG_CACHE_HOME": str(cache), **(extra_env or {})}
        argv = ("check", *args, "--threads", str(TOOL_THREADS), *self.rule_args(args))
        return quality(self.path, *argv, path_value=path_value, extra_env=env)

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


def keep_rules(destination: Path, keep) -> None:
    for path in sorted(destination.glob("*.yml")):
        if path.name not in RESERVED:
            kept = [rule for rule in yaml.safe_load(path.read_text()) or [] if keep(rule)]
            path.write_text(yaml.safe_dump(kept), encoding="utf-8")


def rules_copy(destination: Path, deep: bool = False) -> Path:
    """
    Args:
        destination: Directory for the copy of the rule data.
        deep: True keeps the deep tier, which needs the shared test bundle.

    Returns:
        The copy.
    """
    shutil.copytree(RULES, destination)
    if not deep:
        keep_rules(destination, lambda rule: rule.get("tier") != "deep")
    return destination


@functools.cache
def fast_rules() -> Path:
    """
    Returns:
        The one copy of the fast-tier rule data of this test process, which
        every target without --rules of its own reads and no test writes.
    """
    scratch = Path(tempfile.mkdtemp(prefix="quality-fast-rules-"))
    atexit.register(shutil.rmtree, scratch, True)
    return rules_copy(scratch / "rules")


def rules_without_pending(destination: Path, deep: bool = False) -> Path:
    rules_copy(destination, deep)
    keep_rules(destination, lambda rule: not rule.get("pending"))
    return destination


def rules_without_tool(destination: Path, tool: str) -> Path:
    rules_copy(destination)
    for path in sorted(destination.glob("*.yml")):
        if path.name not in RESERVED:
            kept = []
            for rule in yaml.safe_load(path.read_text()):
                enforcer = rule["enforcer"]
                if isinstance(enforcer, dict):
                    rule["enforcer"] = {
                        kind: settings
                        for kind, settings in enforcer.items()
                        if settings.get("tool") != tool
                    }
                if rule["enforcer"]:
                    kept.append(rule)
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


def rules_with_enforcers(destination: Path, rule_id: str, keep: set) -> Path:
    """
    Args:
        destination: Directory for the copy of the rule data.
        rule_id: Rule whose enforcers are reduced.
        keep: Enforcer keys that stay.

    Returns:
        The copy, so one tool's findings can be told from another's. An
        enforcer another rule shares through a YAML alias goes there too.
    """
    rules_copy(destination, True)
    for path in sorted(destination.glob("*.yml")):
        if path.name not in RESERVED:
            rules = yaml.safe_load(path.read_text(encoding="utf-8")) or []
            dropped = {
                id(settings)
                for rule in rules
                if rule["id"] == rule_id
                for key, settings in rule["enforcer"].items()
                if key not in keep
            }
            drop_enforcers(rules, dropped)
            path.write_text(yaml.safe_dump(rules), encoding="utf-8")
    return destination


def drop_enforcers(rules: list, dropped: set) -> None:
    """
    Args:
        rules: Rules of one file, changed in place.
        dropped: Identities of the enforcer settings to remove from every rule.
    """
    for rule in rules:
        if isinstance(rule["enforcer"], dict):
            rule["enforcer"] = {key: value for key, value in rule["enforcer"].items() if id(value) not in dropped}


def branchy(name: str, count: int) -> str:
    body = "".join(f"    if a == {index}:\n        return {index}\n" for index in range(count))
    return f"def {name}(a):\n{body}    return -1\n"


def write_every_kind(target: Target) -> None:
    target.write("pkg/__init__.py", "")
    target.write("pkg/code.py", "import os  # noqa\n\nbreakpoint()\n\n\n" + branchy("branchy", 12))
    target.write("pkg/copy.py", branchy("copied", 12))
    target.write("run.sh", "#!/bin/bash\necho $1\n")
    target.write("web/app.js", "new Function(location.hash)();\n")
    target.write("requirements.txt", VULNERABLE_PIN)
    target.write(
        ".github/workflows/w.yml",
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: echo ${{ undefined.thing }}\n",
    )
    target.write("Dockerfile", UNTAGGED_DOCKERFILE)
    target.write(".env", SECRET_ENV_LINE)


EVERY_KIND_RULES = {
    "coding.unused-import",
    "coding.shell-lint",
    "coding.workflow-lint",
    "coding.dockerfile",
    "coding.structural",
    "clean.complexity",
    "clean.tool-pragma",
    "security.secret",
}
DEEP_KIND_RULES = {
    "clean.clones",
    "security.static-analysis",
    "security.vulnerable-dependency",
}


def coverage(cwd: Path, *args: str, path_value: str | None = None) -> dict:
    result = quality(cwd, "coverage", "--json", *args, path_value=path_value)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def findings_of_rule(result: subprocess.CompletedProcess, rule: str) -> list:
    return sorted(
        (item["path"], item["line"]) for item in report(result)["findings"] if item["rule"] == rule
    )
