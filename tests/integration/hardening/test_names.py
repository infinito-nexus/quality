import os

import pytest

from tests.integration.support import (
    SECRET_ENV_LINE,
    branchy,
    raw_tool,
    report,
    rule_ids,
)


def test_file_named_dash_fails_closed(target):
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.write("-", "#!/usr/bin/env python3\nX = eval(input())\n")
    target.stage()
    control = raw_tool(target.path, "ruff", "check", "--isolated", "--select", "S307", "--", "-")
    assert control.returncode == 0
    result = target.check("--staged")
    assert result.returncode == 2
    assert "unsafe path" in result.stderr


def test_dash_prefixed_file_names_reach_every_tool(target):
    target.write("-x.py", "import os  # noqa\n\n\n" + branchy("branchy", 12))
    target.write("-y.sh", "#!/bin/bash\necho $1\n")
    target.commit()
    result = target.check("--all", "--json")
    assert result.returncode == 1, result.stderr
    assert {
        "coding.unused-import",
        "coding.shell-lint",
        "clean.complexity",
        "clean.tool-pragma",
    } <= set(rule_ids(result))


def test_non_utf8_path_never_passes_silently(target):
    body = "import os  # noqa\nbreakpoint()\n\n\n" + branchy("branchy", 12)
    (target.path / os.fsdecode(b"caf\xe9.py")).write_text(body, encoding="utf-8")
    (target.path / os.fsdecode(b"caf\xe9.sh")).write_text(
        "#!/bin/bash\necho $1\n", encoding="utf-8"
    )
    target.commit()
    result = target.check("--all", "--json")
    assert result.returncode == 1, result.stderr
    assert {
        "coding.unused-import",
        "coding.structural",
        "clean.tool-pragma",
        "clean.complexity",
        "coding.shell-lint",
    } <= set(rule_ids(result))


CONTROL_LOCK = "x\ny/package-lock.json"


def test_a_changed_name_with_a_control_character_stops_the_check(target):
    target.write("app.py", "y = 2\n")
    target.write(CONTROL_LOCK, "{}\n")
    target.stage()
    staged = target.check("--staged")
    target.commit()
    for result in (staged, target.check("--all")):
        assert result.returncode == 2
        assert "control character: x\\ny/package-lock.json" in result.stderr


@pytest.mark.parametrize("later", ["delete", "rename"])
def test_a_control_character_name_any_commit_touched_stops_the_check(target, later):
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    target.write("x\ny.env", SECRET_ENV_LINE)
    target.commit()
    if later == "delete":
        (target.path / "x\ny.env").unlink()
    else:
        target.git("mv", "x\ny.env", "y.env")
    target.write("app.py", "y = 2\n")
    target.commit()
    result = target.check("--base", "main")
    assert result.returncode == 2
    assert "control character: x\\ny.env" in result.stderr


@pytest.mark.deep
def test_an_untouched_name_with_a_control_character_is_named_unchecked(target):
    target.write(CONTROL_LOCK, "{}\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    target.write("app.py", "y = 2\n")
    target.commit()
    result = target.check("--base", "main", "--json")
    assert result.returncode == 0, result.stderr
    reason = "has a control character in its name, which no file pattern of a rule matches"
    assert f"unchecked: {CONTROL_LOCK}: {reason}" in report(result)["notes"]


@pytest.mark.deep
def test_non_utf8_script_name_stops_the_deep_tier(target):
    (target.path / os.fsdecode(b"caf\xe9.js")).write_text("run();\n", encoding="utf-8")
    target.commit()
    result = target.check("--all")
    assert result.returncode == 2
    assert "cannot read a file whose name is not UTF-8" in result.stderr


def test_quote_in_file_name_fails_closed_for_lizard(target):
    target.write('a"b.py', branchy("branchy", 12))
    target.commit()
    result = target.check("--all")
    assert result.returncode == 2
    assert "lizard" in result.stderr
