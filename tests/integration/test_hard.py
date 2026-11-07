import pytest

from tests.integration.support import (
    AUTHOR_EMAIL,
    AUTHOR_NAME,
    add_rules,
    catalogue,
    edit_yaml,
    needs_gitleaks,
    raw_tool,
    report,
    rule_ids,
    rules_copy,
)

SECRET_RULE = "security.secret"
EVAL_RULE = "security.eval-exec"
PRAGMA_RULE = "clean.tool-pragma"
OVERSIZED_RULE = "security.oversized-code"
SECRET = "ghp_" + "8fK2mQ7xL4pN9sV1" + "tB6yR3wZ0cH5jD2gA7eU"
SECRET_LINE = f'TOKEN = "{SECRET}"\n'
COMMIT_MESSAGE_CANARY = "QualityMessageCanary"


def test_hard_new_secret(target):
    needs_gitleaks()
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.write("a.py", SECRET_LINE)
    target.stage()
    result = target.check("--staged", "--json")
    assert result.returncode == 1
    assert SECRET_RULE in rule_ids(result)


def test_hard_legacy_touched(target):
    needs_gitleaks()
    target.write("a.py", SECRET_LINE)
    target.commit()
    target.write("a.py", SECRET_LINE + "x = 1\n")
    target.stage()
    result = target.check("--staged", "--json")
    assert result.returncode == 1
    assert SECRET_RULE in rule_ids(result)


def test_hard_legacy_untouched(target):
    needs_gitleaks()
    target.write("a.py", SECRET_LINE)
    target.write("b.py", "x = 1\n")
    target.commit()
    target.write("b.py", "x = 2\n")
    target.stage()
    assert target.check("--staged").returncode == 0
    assert target.check("--all").returncode == 1


def test_hard_secret_in_range(target):
    needs_gitleaks()
    target.write("a.py", "x = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    target.write("a.py", SECRET_LINE)
    target.commit()
    target.write("a.py", "x = 1\n")
    target.commit()
    assert target.check("--base", "main").returncode == 1


def test_hard_eval_new(target):
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.write("a.py", "X = eval(input())\n")
    target.stage()
    result = target.check("--staged", "--json")
    assert result.returncode == 1
    assert rule_ids(result) == [EVAL_RULE]


def test_hard_eval_legacy_touched(target):
    target.write("a.py", "X = eval(input())\n")
    target.commit()
    target.write("a.py", "X = eval(input())\ny = 1\n")
    target.stage()
    result = target.check("--staged", "--json")
    assert result.returncode == 1
    assert rule_ids(result) == [EVAL_RULE]


def test_hard_eval_legacy_untouched(target):
    target.write("a.py", "X = eval(input())\n")
    target.write("b.py", "y = 1\n")
    target.commit()
    target.write("b.py", "y = 2\n")
    target.stage()
    assert target.check("--staged").returncode == 0
    assert target.check("--all").returncode == 1


def test_hard_eval_changed_in_range(target):
    target.write("a.py", "X = eval(input())\n")
    target.write("b.py", "y = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    target.write("b.py", "y = 2\n")
    target.commit()
    assert target.check("--base", "main").returncode == 0
    target.write("a.py", "X = eval(input())\nz = 1\n")
    target.commit()
    assert target.check("--base", "main").returncode == 1


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("subprocess.run(sys.argv[1], shell=True)", True),
        ('subprocess.run("ls", shell=True)', False),
        ("os.system(sys.argv[1])", True),
        ('os.system("ls")', False),
        ('requests.get("https://x", verify=False)', True),
    ],
)
def test_hard_shell_and_tls_rules(target, source, expected):
    target.write("seed.py", "x = 1\n")
    target.commit()
    header = "import os\nimport subprocess\nimport sys\n\nimport requests\n\n"
    target.write("a.py", f"{header}print(os, subprocess, sys, requests)\n{source}\n")
    target.stage()
    result = target.check("--staged", "--json")
    hard = [item for item in report(result)["findings"] if item["rule"].startswith("security.")]
    assert bool(hard) is expected


def test_hard_noqa_ignored(target):
    source = "X = eval(input())  # noqa: S307\n"
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.write("a.py", source)
    target.stage()
    result = target.check("--staged", "--json")
    assert result.returncode == 1
    assert EVAL_RULE in rule_ids(result)
    control = raw_tool(target.path, "ruff", "check", "--isolated", "--select", "S307", "a.py")
    assert control.returncode == 0


@pytest.mark.parametrize(
    ("name", "pragma_source"),
    [
        ("a.py", "x = 1  # noqa\n"),
        ("a.py", "x = 1  # NOQA\n"),
        ("a.py", "x = 1  # NoQa: E501\n"),
        ("a.py", "# ruff: noqa\nx = 1\n"),
        ("a.py", "# flake8: noqa\nx = 1\n"),
        ("a.py", "# ruff: disable[S307]\nx = 1\n"),
        ("s.sh", "#!/bin/bash\n# shellcheck disable=SC2086\necho hi\n"),
        ("a.py", "#lizard forgives\nx = 1\n"),
        ("a.py", "# ast-grep-ignore\nx = 1\n"),
    ],
    ids=[
        "noqa",
        "noqa-upper",
        "noqa-mixed",
        "ruff-file",
        "flake8-file",
        "ruff-disable",
        "shellcheck",
        "lizard",
        "ast-grep",
    ],
)
def test_pragma_added(target, name, pragma_source):
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.write(name, pragma_source)
    target.stage()
    result = target.check("--staged", "--json")
    assert result.returncode == 1
    assert PRAGMA_RULE in rule_ids(result)


def test_pragma_legacy_passes_and_string_is_no_pragma(target):
    target.write("a.py", "x = 1  # noqa\n")
    target.commit()
    target.write("a.py", "x = 1  # noqa\ny = 2\n")
    target.stage()
    assert target.check("--staged").returncode == 0
    target.write("b.py", 'z = "# noqa"\n')
    target.stage()
    assert target.check("--staged").returncode == 0


@pytest.mark.parametrize(
    ("name", "first_line"),
    [
        ("tool", "#!/usr/bin/env python3"),
        ("tool", "#!/usr/bin/python3.12"),
        ("tool", "#!/usr/bin/env -S python3 -u"),
        ("tool", "#!/usr/bin/env -Spython3"),
        ("tool", "#!/usr/bin/env -u NAME python3"),
        ("tool", "#! /usr/bin/python"),
        ("tool", "#!/usr/bin/pypy3"),
        ("tool.v2", "#!/usr/bin/env python3"),
        ("tool.txt", "#!/usr/bin/python3"),
    ],
    ids=[
        "env",
        "versioned",
        "env-S",
        "env-S-attached",
        "env-u",
        "blank-after-marker",
        "pypy",
        "unknown-suffix",
        "txt-suffix",
    ],
)
def test_hard_rule_reaches_every_python_interpreter_line(target, name, first_line):
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.write(name, f"{first_line}\nX = eval(input())\n")
    target.stage()
    result = target.check("--staged", "--json")
    assert result.returncode == 1
    assert EVAL_RULE in rule_ids(result)


def test_s603_and_s607_are_not_hard():
    for rule in catalogue():
        if rule.get("hard"):
            enforcer = rule["enforcer"]
            for settings in enforcer.values() if isinstance(enforcer, dict) else ():
                codes = settings.get("codes", ())
                assert "S603" not in codes
                assert "S607" not in codes


def history_rules(directory) -> None:
    add_rules(
        directory,
        [
            {
                "id": "security.fixture-token",
                "severity": "critical",
                "summary": "Fixture token",
                "hard": True,
                "history": True,
                "enforcer": {"python": {"tool": "rg", "pattern": "FIXTURETOKEN[0-9]+"}},
            }
        ],
    )


def test_history_rule_scans_every_commit_and_prints_only_the_sha(target, tmp_path):
    rules = rules_copy(tmp_path / "rules")
    history_rules(rules)
    target.write("a.py", "x = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    target.write("a.py", 'x = "FIXTURETOKEN123"\n')
    added = target.commit(COMMIT_MESSAGE_CANARY)
    target.write("a.py", "x = 1\n")
    target.commit("removed again")
    result = target.check("--base", "main", "--json", "--rules", str(rules))
    assert result.returncode == 1
    findings = report(result)["findings"]
    assert [(item["rule"], item["commit"]) for item in findings] == [
        ("security.fixture-token", added)
    ]
    for flags in (("--json",), ()):
        output = target.check("--base", "main", *flags, "--rules", str(rules))
        combined = output.stdout + output.stderr
        assert added in combined
        for canary in (AUTHOR_NAME, AUTHOR_EMAIL, COMMIT_MESSAGE_CANARY, "FIXTURETOKEN123"):
            assert canary not in combined
    log = target.git("log", "--format=%an %ae %s").stdout
    assert AUTHOR_NAME in log
    assert COMMIT_MESSAGE_CANARY in log


def test_history_rule_covers_a_merge_commit(target, tmp_path):
    rules = rules_copy(tmp_path / "rules")
    history_rules(rules)
    target.write("a.py", "x = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "side")
    target.write("b.py", "y = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature", "main")
    target.git("merge", "-q", "--no-commit", "--no-ff", "side")
    target.write("c.py", 'z = "FIXTURETOKEN123"\n')
    target.stage()
    target.git("commit", "-q", "-m", "evil merge")
    merge = target.git("rev-parse", "HEAD").stdout.strip()
    target.write("c.py", "z = 1\n")
    target.commit()
    result = target.check("--base", "main", "--json", "--rules", str(rules))
    assert result.returncode == 1
    assert [item["commit"] for item in report(result)["findings"]] == [merge]


def test_history_names_an_oversized_code_file_added_and_removed(target, tmp_path):
    rules = rules_copy(tmp_path / "rules")
    history_rules(rules)
    edit_yaml(rules / "limits.yml", lambda document: document.update(blob_max_bytes=128))
    target.write("a.py", "x = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    target.write("big.py", "# pad\n" * 30 + 'x = "FIXTURETOKEN123"\n')
    added = target.commit()
    target.git("rm", "-q", "big.py")
    target.commit()
    result = target.check("--base", "main", "--json", "--rules", str(rules))
    assert result.returncode == 1
    findings = report(result)["findings"]
    assert [(item["rule"], item["path"], item["commit"]) for item in findings] == [
        (OVERSIZED_RULE, "big.py", added)
    ]
