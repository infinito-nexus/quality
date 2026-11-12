import hashlib
import os
import shutil

import pytest

from quality.repo import Repo, hardened_env
from tests.integration.support import (
    DEEP_TOOLS,
    SECRET_ENV_LINE,
    UNTAGGED_DOCKERFILE,
    path_without,
    quality,
    raw_tool,
    report,
    rule_for,
    rule_ids,
    rules_without_pending,
    write_every_kind,
)

F401 = rule_for("F401")
LONG_FILE = "".join(f"value_{index} = {index}\n" for index in range(30))
FAST_TIER_TOOLS = ("quality: tool gitleaks:", "quality: tool hadolint:")


def index_digest(target) -> str:
    return hashlib.sha256((target.path / ".git/index").read_bytes()).hexdigest()


def test_staged_reads_index_text(target):
    target.write("a.py", "x = 1\n")
    target.commit()
    target.write("a.py", "x = 2\n")
    target.stage()
    target.write("a.py", "import os\n")
    result = target.check("--staged", "--json")
    assert result.returncode == 0
    assert rule_ids(result) == []
    target.write("a.py", "import os\n")
    target.stage()
    target.write("a.py", "x = 3\n")
    result = target.check("--staged", "--json")
    assert result.returncode == 1
    assert rule_ids(result) == [F401]


@pytest.mark.parametrize(
    "flags", [("--staged",), ("--base", "main"), ("--all",)], ids=["staged", "base", "all"]
)
def test_check_changes_nothing(target, flags):
    target.write("a.py", "import os\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    target.write("b.py", "import sys\n")
    target.commit()
    target.write("c.py", "import re\n")
    target.git("add", "c.py")
    target.write("dirty.py", "import json\n")
    before_status = target.git("status", "--porcelain").stdout
    before_index = index_digest(target)
    target.check(*flags)
    assert index_digest(target) == before_index
    assert target.git("status", "--porcelain").stdout == before_status


def test_staged_name_status(target):
    target.write("moved.py", LONG_FILE)
    target.write("mode.py", "x = 1\n")
    target.write("gone.py", "x = 1\n")
    target.commit()
    target.git("mv", "moved.py", "renamed.py")
    (target.path / "mode.py").chmod(0o755)
    target.git("rm", "-q", "gone.py")
    target.write("ü.py", "import os\n")
    target.stage()
    repo = Repo.open(
        str(target.path),
        hardened_env(os.environ["PATH"], os.environ),
        60,
        shutil.which("git"),
    )
    changes = {change.path: change for change in repo.staged_changes("HEAD")}
    assert changes["renamed.py"].status == "renamed"
    assert changes["renamed.py"].old_path == "moved.py"
    assert changes["mode.py"].status == "mode"
    assert changes["gone.py"].status == "deleted"
    assert changes["ü.py"].status == "added"
    assert changes["ü.py"].old_path == ""
    result = target.check("--staged", "--json")
    assert [finding["path"] for finding in report(result)["findings"]] == ["ü.py"]


def test_staged_full_index_context(target):
    target.write("helpers/__init__.py", "")
    target.write("helpers/util.py", "VALUE = 1\n")
    target.write("pkg/__init__.py", "")
    target.commit()
    source = "import os\n\nimport yaml\n\nfrom helpers import util\n\nprint(os, yaml, util)\n"
    target.write("pkg/new.py", source)
    target.stage()
    result = target.check("--staged", "--json")
    assert result.returncode == 0
    assert rule_ids(result) == []
    lone = target.path.parent / "lone"
    (lone / "pkg").mkdir(parents=True)
    (lone / "pkg/new.py").write_text(source, encoding="utf-8")
    control = raw_tool(
        lone,
        "ruff",
        "check",
        "--isolated",
        "--select",
        "I001,INP001",
        "--output-format",
        "concise",
        "pkg/new.py",
    )
    assert "I001" in control.stdout
    assert "INP001" in control.stdout


def test_base_uses_merge_base(target):
    target.write("a.py", "x = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    target.write("b.py", "y = 1\n")
    target.commit()
    target.git("checkout", "-q", "main")
    target.write("newer.py", "import os\n")
    target.commit()
    target.git("checkout", "-q", "feature")
    result = target.check("--base", "main", "--json")
    assert result.returncode == 0
    assert rule_ids(result) == []
    target.write("mine.py", "import sys\n")
    target.commit()
    result = target.check("--base", "main", "--json")
    assert result.returncode == 1
    assert [finding["path"] for finding in report(result)["findings"]] == ["mine.py"]


def test_all_reports_legacy(target):
    target.write("legacy.py", "import os\n")
    target.commit()
    result = target.check("--all", "--json")
    assert result.returncode == 1
    assert rule_ids(result) == [F401]


def test_merge_both_parents(target):
    target.write("x.py", "x = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    target.write("b.py", "import sys\n")
    target.commit()
    target.git("checkout", "-q", "main")
    target.write("a.py", "import os\n")
    target.commit()
    target.git("merge", "-q", "--no-commit", "--no-ff", "feature")
    result = target.check("--staged", "--json")
    assert result.returncode == 0
    assert rule_ids(result) == []
    target.write("c.py", "import re\n")
    target.stage()
    result = target.check("--staged", "--json")
    assert result.returncode == 1
    assert [finding["path"] for finding in report(result)["findings"]] == ["c.py"]


@pytest.mark.parametrize(
    "flags", [("--staged",), ("--base", "main"), ("--all",)], ids=["staged", "base", "all"]
)
def test_conflict_aborts(target, flags):
    target.write("a.py", "x = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    target.write("a.py", "x = 2\n")
    target.commit()
    target.git("checkout", "-q", "main")
    target.write("a.py", "x = 3\n")
    target.commit()
    target.git("merge", "-q", "feature", tolerate_failure=True)
    result = target.check(*flags)
    assert result.returncode == 2
    assert "conflict" in result.stderr


def test_exit_codes(target, tmp_path):
    target.write("a.py", "x = 1\n")
    target.commit()
    target.write("b.py", "y = 1\n")
    target.stage()
    assert target.check("--staged").returncode == 0
    assert target.check("--base", "main").returncode == 0
    reduced = rules_without_pending(tmp_path / "rules")
    assert target.check("--all", "--rules", str(reduced)).returncode == 0
    target.write("b.py", "import os\n")
    target.stage()
    assert target.check("--staged").returncode == 1
    assert target.check("--all", "--rules", str(reduced)).returncode == 1
    assert target.check("--staged", "--all").returncode == 2
    assert target.check().returncode == 2
    assert target.check("--nonsense").returncode == 2
    assert target.check("--base", "no-such-ref").returncode == 2
    assert target.check("--all", "--rules", str(tmp_path / "missing")).returncode == 2
    target.write(".qualityignore.yml", "- rule: x\n  reason: [\n")
    target.stage()
    broken = target.check("--staged")
    assert broken.returncode == 2
    assert ".qualityignore.yml" in broken.stderr
    target.git("rm", "-q", "--cached", ".qualityignore.yml")
    (target.path / ".qualityignore.yml").unlink()
    no_ruff = path_without(tmp_path / "bin", "ruff")
    missing = target.check("--staged", path_value=no_ruff)
    assert missing.returncode == 2
    assert "ruff" in missing.stderr


def test_exit_2_outside_a_repository(tmp_path):
    result = quality(tmp_path, "check", "--all")
    assert result.returncode == 2
    assert "git work tree" in result.stderr


def test_missing_tool_not_required_when_language_absent(target, tmp_path):
    target.write("run.sh", "#!/bin/bash\necho hi\n")
    target.stage()
    no_ruff = path_without(tmp_path / "bin", "ruff")
    assert target.check("--staged", path_value=no_ruff).returncode == 0


def test_staged_feeds_touched_files_only_to_gitleaks_and_hadolint(target):
    target.write("old/Dockerfile", UNTAGGED_DOCKERFILE)
    target.write("old.env", SECRET_ENV_LINE)
    target.commit()
    target.write("new/Dockerfile", UNTAGGED_DOCKERFILE)
    target.write("new.yml", "x: 1\n")
    target.stage()
    result = target.check("--staged", "--verbose")
    assert result.returncode == 1, result.stderr
    lines = [line for line in result.stderr.splitlines() if line.startswith(FAST_TIER_TOOLS)]
    assert sorted(lines) == [
        "quality: tool gitleaks: exit 0, files: new.yml new/Dockerfile",
        "quality: tool hadolint: exit 0, files: new/Dockerfile",
    ]
    every_file = "new.yml new/Dockerfile old.env old/Dockerfile"
    whole = target.check("--all", "--verbose")
    assert f"quality: tool gitleaks: exit 0, files: {every_file}" in whole.stderr


def tool_lines(result, tool: str) -> list:
    return [line for line in result.stderr.splitlines() if f"tool {tool}:" in line]


@pytest.mark.deep
def test_staged_runs_the_fast_tier_on_touched_files_only(target):
    target.write("untouched.py", "x = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    write_every_kind(target)
    target.stage()
    staged = target.check("--staged", "--verbose")
    assert staged.returncode == 1, staged.stderr
    for tool in DEEP_TOOLS:
        assert tool_lines(staged, tool) == []
    lizard = tool_lines(staged, "lizard")
    assert lizard
    assert all("untouched.py" not in line for line in lizard)
    assert all("pkg/code.py" in line for line in lizard)
    target.commit()
    for flags in (("--base", "main"), ("--all",)):
        deep = target.check(*flags, "--verbose")
        assert deep.returncode == 1, deep.stderr
        for tool in DEEP_TOOLS:
            assert tool_lines(deep, tool), tool


@pytest.mark.parametrize("name", ["a.py", "deploy", "compose.yml", "a.json"])
def test_missing_tool_fails_closed(target, tmp_path, name):
    target.write("notes.md", "# Notes\n")
    target.write("compose.yml.j2", "a: {{ a }}\n")
    target.stage()
    no_ast_grep = path_without(tmp_path / "bin", "ast-grep")
    assert target.check("--staged", path_value=no_ast_grep).returncode == 0
    target.write(name, "#!/bin/bash\ntrue\n" if name == "deploy" else "{}\n")
    target.stage()
    for flags in (("--staged",), ("--all",)):
        result = target.check(*flags, path_value=no_ast_grep)
        assert result.returncode == 2
        assert "missing tool: ast-grep" in result.stderr


def test_staged_ast_grep_receives_touched_files_only(target):
    target.write("a.py", "x = 1\n")
    target.write("b.py", "y = 1\n")
    target.write("c.sh", "#!/bin/bash\ntrue\n")
    target.commit()
    target.write("b.py", "y = 2\n")
    target.stage()
    result = target.check("--staged", "--verbose")
    assert result.returncode == 0, result.stderr
    lines = [line for line in result.stderr.splitlines() if "tool ast-grep:" in line]
    assert lines
    assert all(line.endswith("files: b.py") for line in lines), lines


def test_staged_on_unborn_head(target):
    target.write("a.py", "import os\n")
    target.stage()
    result = target.check("--staged", "--json")
    assert result.returncode == 1
    assert rule_ids(result) == [F401]
    target.write("a.py", "x = 1\n")
    target.stage()
    assert target.check("--staged").returncode == 0
