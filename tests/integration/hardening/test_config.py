import os
import shutil
import subprocess
import tarfile
import tempfile

import pytest

from tests.integration.hardening.support import F401, canary_script
from tests.integration.support import (
    EVERY_KIND_RULES,
    RAW_GITLEAKS,
    RULES,
    SECRET_ENV_LINE,
    UNTAGGED_DOCKERFILE,
    branchy,
    git,
    launcher_argv,
    raw_tool,
    report,
    rule_ids,
    write_every_kind,
)

GITLEAKS_WITHOUT_RULES = 'title = "planted"\n'
HADOLINT_IGNORING = "ignored:\n  - DL3006\n"


def findings_of(result) -> list:
    return sorted(
        (item["rule"], item["path"], item["line"], item["value"])
        for item in report(result)["findings"]
    )


def test_repo_config_ignored(target):
    target.write(
        "a.py",
        "import os  # noqa\n\n\n" + branchy("branchy", 12),
    )
    target.write("b.py", "import sys\n")
    target.write("c.py", "breakpoint()\n")
    target.write("s.sh", "#!/bin/bash\necho $1\n")
    target.write(
        ".github/workflows/w.yml",
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: echo ${{ undefined.thing }}\n",
    )
    target.write("Dockerfile", UNTAGGED_DOCKERFILE)
    target.write(".env", SECRET_ENV_LINE)
    target.write("LICENSE", "Permission is hereby granted, free of charge, to any person obtaining a copy\n")
    target.commit()
    plain = findings_without_folder_size(target.check("--all", "--json"))
    assert EVERY_KIND_RULES <= {item[0] for item in plain}
    target.write(".shellcheckrc", "disable=all\n")
    ignore_all = "paths:\n  '**':\n    ignore:\n      - '.*'\n"
    target.write(".github/actionlint.yaml", ignore_all)
    target.write("actionlint.yaml", ignore_all)
    target.write("whitelizard.txt", "branchy\n")
    target.write(".ignore", "*\n")
    target.write(
        "pyproject.toml",
        '[tool.ruff]\nexclude = ["*"]\n[tool.ruff.lint.per-file-ignores]\n"*" = ["ALL"]\n',
    )
    target.write(".gitleaks.toml", GITLEAKS_WITHOUT_RULES)
    target.write(".gitleaksignore", ".env:github-pat:1\n")
    target.write(".hadolint.yaml", HADOLINT_IGNORING)
    target.write(".hadolint.yml", HADOLINT_IGNORING)
    target.write("sgconfig.yml", 'ruleDirs: []\nlanguageGlobs:\n  rust: ["*.py"]\n')
    target.commit()
    assert findings_without_folder_size(target.check("--all", "--json")) == plain
    assert_config_changes_the_raw_tools(target)
    assert_secret_config_changes_raw_gitleaks(target)


def findings_without_folder_size(result) -> list:
    return [item for item in findings_of(result) if item[0] != "clean.folder-items"]


def test_tool_environment_ignored(target, tmp_path):
    write_every_kind(target)
    target.commit()
    plain = findings_of(target.check("--all", "--json"))
    assert {"coding.dockerfile", "security.secret"} <= {item[0] for item in plain}
    planted = tmp_path / "planted"
    planted.mkdir()
    (planted / "gitleaks.toml").write_text(GITLEAKS_WITHOUT_RULES, encoding="utf-8")
    (planted / "hadolint.yaml").write_text(HADOLINT_IGNORING, encoding="utf-8")
    hostile = {
        "GITLEAKS_CONFIG": str(planted / "gitleaks.toml"),
        "GITLEAKS_CONFIG_TOML": GITLEAKS_WITHOUT_RULES,
        "XDG_CONFIG_HOME": str(planted),
        "HOME": str(planted),
    }
    gitleaks = ("gitleaks", "dir", *RAW_GITLEAKS, "-i", str(planted), ".env")
    assert raw_tool(target.path, *gitleaks).stdout.strip() != "[]"
    assert raw_tool_with(target.path, hostile, *gitleaks).stdout.strip() == "[]"
    hadolint = ("hadolint", "--format", "json", "Dockerfile")
    assert raw_tool(target.path, *hadolint).stdout.strip() != "[]"
    assert raw_tool_with(target.path, hostile, *hadolint).stdout.strip() == "[]"
    result = subprocess.run(
        launcher_argv("check", "--all", "--json", *target.rule_args(())),
        cwd=target.path,
        env={"PATH": os.environ["PATH"], "TMPDIR": tempfile.gettempdir(), **hostile},
        capture_output=True,
        text=True,
        check=False,
    )
    assert findings_of(result) == plain


def raw_tool_with(cwd, extra: dict, *argv: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        argv,
        cwd=cwd,
        env={"PATH": os.environ["PATH"], **extra},
        capture_output=True,
        text=True,
        errors="replace",
        check=False,
    )


def assert_secret_config_changes_raw_gitleaks(target) -> None:
    assert raw_tool(target.path, "gitleaks", "dir", *RAW_GITLEAKS, ".").stdout.strip() == "[]"
    default = target.path.parent / "default.toml"
    default.write_text("[extend]\nuseDefault = true\n", encoding="utf-8")
    with_default = ("gitleaks", "dir", *RAW_GITLEAKS, "--config", str(default))
    assert raw_tool(target.path, *with_default, ".").stdout.strip() == "[]"
    elsewhere = target.path.parent / "no-ignore-file"
    elsewhere.mkdir()
    isolated = raw_tool(target.path, *with_default, "-i", str(elsewhere), ".env")
    assert isolated.stdout.strip() != "[]"
    assert raw_tool(target.path, "hadolint", "--format", "json", "Dockerfile").returncode == 0
    valid = target.path.parent / "hadolint.yaml"
    valid.write_text("ignored: []\n", encoding="utf-8")
    plain_hadolint = raw_tool(target.path, "hadolint", "--config", str(valid), "Dockerfile")
    assert plain_hadolint.returncode == 1


def assert_config_changes_the_raw_tools(target) -> None:
    assert raw_tool(target.path, "ruff", "check", "--select", "F401", "b.py").returncode == 0
    isolated = raw_tool(target.path, "ruff", "check", "--isolated", "--select", "F401", "b.py")
    assert isolated.returncode == 1
    assert raw_tool(target.path, "shellcheck", "s.sh").returncode == 0
    assert raw_tool(target.path, "shellcheck", "--norc", "s.sh").returncode == 1
    workflow = ".github/workflows/w.yml"
    assert raw_tool(target.path, "actionlint", workflow).returncode == 0
    empty = target.path.parent / "empty.yaml"
    empty.touch()
    assert raw_tool(target.path, "actionlint", "-config-file", str(empty), workflow).returncode == 1
    whitelisted = raw_tool(target.path, "lizard", "-w", "-C", "10", "a.py")
    assert "branchy" not in whitelisted.stdout
    plain_lizard = raw_tool(target.path, "lizard", "-w", "-C", "10", "-W", str(empty), "a.py")
    assert "branchy" in plain_lizard.stdout
    assert raw_tool(target.path, "rg", "--no-config", "noqa").stdout == ""
    assert "noqa" in raw_tool(target.path, "rg", "--no-config", "--no-ignore", "noqa").stdout
    scan = ("ast-grep", "scan", "--rule", str(RULES / "ast-grep" / "script" / "python.yml"), "--json=stream")
    assert raw_tool(target.path, *scan, "--no-ignore", "dot", "c.py").stdout == ""
    config = target.path.parent / "own-sgconfig.yml"
    config.write_text('{"languageGlobs": {"python": ["*"]}}', encoding="utf-8")
    own = ("--config", str(config))
    assert "breakpoint" in raw_tool(target.path, *scan, *own, "--no-ignore", "dot", "c.py").stdout


PLANTED_SEMGREP = (
    "rules:\n  - id: planted\n    languages: [javascript]\n    severity: ERROR\n"
    "    message: planted\n    pattern: const $X = $Y;\n"
)


@pytest.mark.deep
def test_semgrep_reads_only_its_own_rules(target, tmp_path):
    target.write("app.js", "const run = new Function(location.hash); // nosemgrep\nrun();\n")
    target.write("ok.js", "const plain = 1;\n")
    target.commit()
    plain = findings_of(target.check("--all", "--json"))
    assert ("security.static-analysis", "app.js", 1, None) in plain
    target.write(".semgrep.yml", PLANTED_SEMGREP)
    target.write(".semgrepignore", "*.js\n")
    target.commit()
    home = tmp_path / "home"
    home.mkdir()
    hostile = {
        "HOME": str(home),
        "SEMGREP_RULES": str(target.path / ".semgrep.yml"),
        "SEMGREP_SEND_METRICS": "on",
        "SEMGREP_ENABLE_VERSION_CHECK": "1",
    }
    assert findings_of(target.check("--all", "--json", extra_env=hostile)) == plain
    assert list(home.iterdir()) == []
    raw_home = tmp_path / "raw-home"
    raw_home.mkdir()
    control = subprocess.run(
        ["semgrep", "scan", "--config", ".semgrep.yml", "--metrics=off", "--json", "ok.js"],
        cwd=target.path,
        env={"PATH": os.environ["PATH"], "HOME": str(raw_home), "SEMGREP_ENABLE_VERSION_CHECK": "0"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert "planted" in control.stdout
    assert (raw_home / ".semgrep").is_dir()


def test_tracked_gitignored_file_checked(target):
    target.write(".gitignore", "ignored.py\nvenv/\n")
    body = "import os  # noqa\n\n\n" + branchy("branchy", 12)
    target.write("ignored.py", body)
    target.write("venv/lib.py", body)
    target.git("add", "-f", "ignored.py", "venv/lib.py", ".gitignore")
    target.git("commit", "-q", "-m", "tracked despite ignore")
    result = target.check("--all", "--json")
    assert result.returncode == 1
    seen = {(item["rule"], item["path"]) for item in report(result)["findings"]}
    for path in ("ignored.py", "venv/lib.py"):
        assert ("coding.unused-import", path) in seen
        assert ("clean.tool-pragma", path) in seen
        assert ("clean.complexity", path) in seen
    control = raw_tool(
        target.path, "ruff", "check", "--isolated", "--select", "F401", "--respect-gitignore", "."
    )
    assert "ignored.py" not in control.stdout
    assert "venv/lib.py" not in control.stdout


def test_export_ignore_checked(target):
    target.write(".gitattributes", "a.py export-ignore\n")
    target.write("a.py", "import os\n")
    target.commit()
    result = target.check("--all", "--json")
    assert result.returncode == 1
    assert [item["path"] for item in report(result)["findings"]] == ["a.py"]
    archive = target.path.parent / "archive.tar"
    target.git("archive", "--format=tar", "-o", str(archive), "HEAD")
    with tarfile.open(archive) as handle:
        assert "a.py" not in handle.getnames()


def plant_git_canaries(target, canaries) -> dict:
    scripts = {}
    for name in ("fsmonitor", "smudge", "clean", "process", "external", "textconv", "hook"):
        script = canaries / f"{name}.sh"
        script.write_text(canary_script(canaries / f"fired-{name}"), encoding="utf-8")
        script.chmod(0o755)
        scripts[name] = str(script)
    target.git("config", "core.fsmonitor", scripts["fsmonitor"])
    target.git("config", "filter.x.smudge", scripts["smudge"])
    target.git("config", "filter.x.clean", scripts["clean"])
    target.git("config", "filter.y.process", scripts["process"])
    target.git("config", "diff.external", scripts["external"])
    target.git("config", "diff.z.textconv", scripts["textconv"])
    hooks = canaries / "hooks"
    hooks.mkdir()
    shutil.copy2(scripts["hook"], hooks / "post-index-change")
    target.git("config", "core.hooksPath", str(hooks))
    return scripts


def fired(canaries) -> list:
    return sorted(path.name for path in canaries.glob("fired-*"))


def test_git_config_not_executed(target, tmp_path):
    canaries = tmp_path / "canaries"
    canaries.mkdir()
    target.write(".gitattributes", "*.py filter=x diff=z\n*.txt filter=y\n")
    target.write("a.py", "import os\n")
    target.write("b.txt", "text\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    target.write("a.py", "import sys\n")
    target.commit()
    target.write("c.py", "import re\n")
    target.git("add", "c.py")
    plant_git_canaries(target, canaries)

    control_repo = tmp_path / "control"
    shutil.copytree(target.path, control_repo, symlinks=True)
    git(control_repo, "status", tolerate_failure=True)
    (control_repo / "a.py").unlink()
    git(control_repo, "checkout", "--", "a.py", tolerate_failure=True)
    (control_repo / "a.py").write_text("import json\n", encoding="utf-8")
    (control_repo / "b.txt").write_text("changed\n", encoding="utf-8")
    git(control_repo, "add", "a.py", "b.txt", tolerate_failure=True)
    git(control_repo, "diff", "HEAD~1", tolerate_failure=True)
    git(control_repo, "diff", "--no-ext-diff", "HEAD~1", tolerate_failure=True)
    assert fired(canaries) == [
        "fired-clean",
        "fired-external",
        "fired-fsmonitor",
        "fired-hook",
        "fired-process",
        "fired-smudge",
        "fired-textconv",
    ]
    for marker in canaries.glob("fired-*"):
        marker.unlink()

    for flags in (("--staged",), ("--base", "main"), ("--all",)):
        result = target.check(*flags, "--verbose")
        assert result.returncode == 1, result.stderr
        assert fired(canaries) == []


def test_replace_ref_not_honoured(target):
    target.write("a.py", "import os\n")
    target.commit()
    bad = target.git("rev-parse", "HEAD:a.py").stdout.strip()
    target.write("clean.py", "x = 1\n")
    target.git("add", "clean.py")
    good = target.git("rev-parse", ":clean.py").stdout.strip()
    target.git("replace", bad, good)
    assert target.git("cat-file", "blob", bad).stdout == "x = 1\n"
    assert rule_ids(target.check("--all", "--json")) == [F401]
