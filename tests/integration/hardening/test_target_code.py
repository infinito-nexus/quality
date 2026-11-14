import os
import shutil
import subprocess

import pytest

from tests.integration.hardening.support import F401, canary_script
from tests.integration.support import (
    DEEP_KIND_RULES,
    EVERY_KIND_RULES,
    RULES,
    add_rules,
    path_with,
    quality,
    raw_tool,
    rule_ids,
    rules_copy,
    tools,
    write_every_kind,
    write_shim,
)


def python_canary(marker) -> str:
    return f'import pathlib\n\npathlib.Path("{marker}").write_text("fired")\n'


def test_symlink_not_followed(target, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    secret_text = "QUALITYSYMLINKCANARY"
    (outside / "canary.py").write_text(
        f'T = "/tmp/{secret_text}"\nX = eval(input())\n', encoding="utf-8"
    )
    target.write("a.py", "import os\n")
    (target.path / "link.py").symlink_to(outside / "canary.py")
    (target.path / "linkdir").symlink_to(outside)
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    (target.path / "link2.py").symlink_to(outside / "canary.py")
    target.write("b.py", "import sys\n")
    target.commit()
    (target.path / "link3.py").symlink_to(outside / "canary.py")
    target.stage()

    control = raw_tool(
        target.path,
        "ruff",
        "check",
        "--isolated",
        "--select",
        "S108",
        "--output-format",
        "concise",
        "link.py",
    )
    assert secret_text in control.stdout

    for flags in (("--staged",), ("--base", "main"), ("--all",)):
        for output in (("--json",), (), ("--verbose",)):
            result = target.check(*flags, *output)
            assert secret_text not in result.stdout + result.stderr
            for line in [*result.stdout.splitlines(), *result.stderr.splitlines()]:
                if "link.py" in line or "linkdir" in line:
                    assert line.startswith("quality: tool gitleaks:"), line
    assert rule_ids(target.check("--all", "--json")) == [F401, F401]


def test_ignore_file_symlink_refused(target, tmp_path):
    outside = tmp_path / "outside.yml"
    outside.write_text("- rule: coding\n  reason: planted\n", encoding="utf-8")
    target.write("a.py", "import os\n")
    (target.path / ".qualityignore.yml").symlink_to(outside)
    target.commit()
    result = target.check("--all")
    assert result.returncode == 2
    assert ".qualityignore.yml" in result.stderr


def test_no_target_code_loaded(target, tmp_path):
    markers = tmp_path / "markers"
    markers.mkdir()
    planted = {
        ".quality/plugin.py": markers / "plugin",
        ".quality/__init__.py": markers / "plugin-init",
        "yaml.py": markers / "yaml",
        "pathspec.py": markers / "pathspec",
        "quality/__init__.py": markers / "quality",
        "rules.py": markers / "rules",
    }
    for name, marker in planted.items():
        target.write(name, python_canary(marker))
    target.write("a.py", "import os\n")
    target.commit()
    raw_tool(target.path, "python3", "-c", "import yaml")
    assert (markers / "yaml").exists()
    raw_tool(target.path, "python3", ".quality/plugin.py")
    assert (markers / "plugin").exists()
    for marker in markers.iterdir():
        marker.unlink()

    target.git("checkout", "-q", "-b", "feature")
    target.write("b.py", "import sys\n")
    target.commit()
    target.write("c.py", "import re\n")
    target.git("add", "c.py")
    for flags in (("--staged",), ("--base", "main"), ("--all",)):
        assert target.check(*flags).returncode == 1
    assert sorted(path.name for path in markers.iterdir()) == []


def universal_canaries(target, markers) -> None:
    target.write("conftest.py", python_canary(markers / "conftest"))
    target.write("setup.py", python_canary(markers / "setup"))
    target.write(
        "build.rs",
        f'fn main() {{ std::fs::write("{markers / "build-rs"}", "fired").unwrap(); }}\n',
    )
    target.write(
        "eslint.config.js",
        f'require("fs").writeFileSync("{markers / "eslint"}", "fired");\n',
    )
    target.write("phpstan.neon", "parameters:\n  bootstrapFiles:\n    - bootstrap.php\n")
    target.write("bootstrap.php", f'<?php file_put_contents("{markers / "phpstan"}", "fired");\n')


def adapter_named_canaries(target, markers) -> None:
    for tool, settings in tools().items():
        for name in settings["loads"]:
            if name.endswith(".py"):
                target.write(name, python_canary(markers / f"{tool}-{name.replace('/', '-')}"))
            else:
                target.write(name, "[[[ not valid in any format\n")


@pytest.mark.deep
def test_no_target_code_per_tool(target, tmp_path):
    markers = tmp_path / "markers"
    markers.mkdir()
    write_every_kind(target)
    universal_canaries(target, markers)
    adapter_named_canaries(target, markers)
    for tool in tools():
        target.write(tool, canary_script(markers / f"target-binary-{tool}"))
        (target.path / tool).chmod(0o755)
    target.commit()

    control = tmp_path / "control"
    control.mkdir()
    shutil.copy2(target.path / "conftest.py", control / "conftest.py")
    subprocess.run(
        ["python3", "-m", "pytest", "--co", "-q", "-p", "no:cacheprovider"],
        cwd=control,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        capture_output=True,
        check=False,
    )
    assert (markers / "conftest").exists()
    raw_tool(target.path, "python3", "setup.py")
    assert (markers / "setup").exists()
    if shutil.which("node"):
        shutil.copy2(target.path / "eslint.config.js", control / "eslint.config.js")
        raw_tool(control, "node", "eslint.config.js")
        assert (markers / "eslint").exists()
    for marker in markers.iterdir():
        marker.unlink()

    result = target.check("--all", "--verbose", "--json")
    assert result.returncode == 1, result.stderr
    for tool in tools():
        assert f"tool {tool}:" in result.stderr
    assert EVERY_KIND_RULES | DEEP_KIND_RULES <= set(rule_ids(result))
    assert sorted(path.name for path in markers.iterdir()) == []


def test_tool_inside_target_refused(target):
    write_every_kind(target)
    target.commit()
    planted = target.path / "bin"
    write_shim(planted, "ruff", 'echo "[]"')
    result = target.check("--all", path_value=path_with(planted))
    assert result.returncode == 2
    assert "ruff" in result.stderr


def test_git_inside_target_refused(target, tmp_path):
    target.write("sub/a.py", "import os\n")
    target.commit()
    canary = tmp_path / "git-ran"
    planted = target.path / "bin"
    write_shim(planted, "git", f'touch "{canary}"\nexit 1')
    for cwd in (target.path, target.path / "sub"):
        result = quality(cwd, "check", "--all", path_value=path_with(planted))
        assert result.returncode == 2
        assert "tool git resolves inside the target repository" in result.stderr
    assert not canary.exists()
    raw_tool(target.path, str(planted / "git"))
    assert canary.exists()


def test_relative_path_entry_ignored(target):
    target.write("a.py", "import os\n")
    target.commit()
    planted = target.path / "bin"
    write_shim(planted, "ruff", 'echo "[]"')
    result = target.check("--all", "--json", path_value=f"bin{os.pathsep}{os.environ['PATH']}")
    assert result.returncode == 1
    assert rule_ids(result) == [F401]


def test_tool_not_allowlisted(target, tmp_path):
    rules = rules_copy(tmp_path / "rules")
    add_rules(
        rules,
        [
            {
                "id": "coding.outside-allow-list",
                "severity": "low",
                "summary": "fixture",
                "enforcer": {"python": {"tool": "planted-tool"}},
            }
        ],
    )
    target.write("a.py", "x = 1\n")
    target.commit()
    for flags in (("--staged",), ("--all",)):
        result = target.check(*flags, "--rules", str(rules))
        assert result.returncode == 2
        assert "planted-tool" in result.stderr


def test_tools_list_names_neither_clippy_nor_cargo():
    result = subprocess.run(
        ["rg", "-n", "clippy|cargo", str(RULES / "tools.yml")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert result.stdout == ""
