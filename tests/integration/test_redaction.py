import pytest

from tests.integration.support import (
    AUTHOR_EMAIL,
    AUTHOR_NAME,
    needs_gitleaks,
    raw_tool,
    report,
)

CANARY = "QUALITYREDACTCANARY"
OUTPUT_FLAGS = [(), ("--verbose",), ("--json",), ("--json", "--verbose")]
RUFF_FULL = ("ruff", "check", "--isolated", "--select", "ALL", "--output-format", "full")
RUFF_CONCISE = ("ruff", "check", "--isolated", "--select", "S108", "--output-format", "concise")
RUFF_UNDEFINED = ("ruff", "check", "--isolated", "--select", "F821", "--output-format", "concise")
CASES = {
    "unrelated_finding": ("a.py", f"import os  # {CANARY}\n", (*RUFF_FULL, "a.py")),
    "s108_string": ("a.py", f'T = "/tmp/{CANARY}"\n', (*RUFF_CONCISE, "a.py")),
    "unparsable": ("a.py", f'x = "{CANARY}\ndef (:\n', (*RUFF_FULL, "a.py")),
    "undefined_name": ("a.py", f"{CANARY}()\n", (*RUFF_UNDEFINED, "a.py")),
    "shell_finding": ("s.sh", f"#!/bin/bash\necho $1 {CANARY}\n", ("shellcheck", "s.sh")),
    "workflow_message": (
        ".github/workflows/w.yml",
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
        f"      - run: echo ${{{{ {CANARY}.x }}}}\n",
        ("actionlint", "-no-color", ".github/workflows/w.yml"),
    ),
}


@pytest.mark.parametrize("case", sorted(CASES))
def test_redaction_canary(target, case):
    name, source, control = CASES[case]
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.write(name, source)
    target.stage()
    unprotected = raw_tool(target.path, *control)
    assert CANARY in (unprotected.stdout + unprotected.stderr).upper()
    for mode_flags in (("--staged",), ("--all",)):
        for output_flags in OUTPUT_FLAGS:
            result = target.check(*mode_flags, *output_flags)
            assert result.returncode == 1, result.stderr
            assert CANARY not in (result.stdout + result.stderr).upper()


def test_redaction_canary_on_secret_line(target):
    needs_gitleaks()
    target.write("seed.py", "x = 1\n")
    target.commit()
    secret = "ghp_" + "8fK2mQ7xL4pN9sV1" + "tB6yR3wZ0cH5jD2gA7eU"
    target.write("a.py", f'TOKEN = "{secret}"  # {CANARY}\n')
    target.stage()
    for output_flags in OUTPUT_FLAGS:
        result = target.check("--staged", *output_flags)
        assert result.returncode == 1
        combined = result.stdout + result.stderr
        assert CANARY not in combined
        assert secret not in combined


def test_redaction_of_entity_and_metric_names(target):
    target.write("seed.py", "x = 1\n")
    target.commit()
    name = "quality_entity_canary"
    arguments = ", ".join(f"p{index}" for index in range(7))
    target.write("a.py", f"def {name}({arguments}):\n    return p0\n")
    target.stage()
    result = target.check("--staged", "--verbose")
    assert result.returncode == 1
    assert name not in result.stdout + result.stderr
    assert "clean.parameters" in result.stdout


def test_text_output_escapes_control_characters(target):
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    name = "x\n::error::forged\x1b[31m.py"
    target.write(name, "import os\n")
    target.write(
        ".qualityignore.yml",
        "- rule: coding.undefined-name\n  paths: [never.py]\n"
        '  reason: "r\\n::stop-commands::tok\\nquality: 0 finding(s)"\n',
    )
    target.commit()
    result = target.check("--base", "main", "--verbose")
    assert result.returncode == 1
    for stream in (result.stdout, result.stderr):
        assert "\x1b" not in stream
        assert not [line for line in stream.splitlines() if line.startswith("::")]
    assert "quality: 0 finding(s)" not in result.stdout.splitlines()
    assert result.stdout.splitlines()[-1] == "quality: 1 finding(s)"
    assert report(target.check("--base", "main", "--json"))["findings"][0]["path"] == name


def test_json_output_holds_only_ascii(target):
    target.write("seed.py", "x = 1\n")
    target.commit()
    name = "c\x9bd e.py"
    target.write(name, "import os\n")
    target.stage()
    result = target.check("--staged", "--json")
    assert result.stdout.isascii()
    assert report(result)["findings"][0]["path"] == name


def test_error_output_escapes_control_characters(target):
    target.write("a.py", "x = 1\n")
    target.write(
        ".qualityignore.yml",
        "- rule: coding.undefined-name\n  paths: [never.py]\n"
        '  reason: "r\\n::error::forged\\u001b[31m"\n',
    )
    target.commit()
    result = target.check("--all")
    assert result.returncode == 2
    assert result.stderr.startswith("quality: error: stale")
    assert "\x1b" not in result.stderr
    assert result.stderr.count("\n") == 1


def test_finding_fields(target):
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.write("a.py", "import os\n")
    target.stage()
    fields = {"rule", "path", "line", "severity", "summary", "value", "commit"}
    for flags in (("--staged",), ("--all",)):
        findings = report(target.check(*flags, "--json"))["findings"]
        assert findings
        for finding in findings:
            assert set(finding) == fields
    target.git("checkout", "-q", "-b", "feature")
    target.commit()
    findings = report(target.check("--base", "main", "--json"))["findings"]
    assert findings
    for finding in findings:
        assert set(finding) == fields


def test_no_author_data(target):
    needs_gitleaks()
    target.write("a.py", "x = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    secret = "ghp_" + "8fK2mQ7xL4pN9sV1" + "tB6yR3wZ0cH5jD2gA7eU"
    target.write("a.py", f'TOKEN = "{secret}"\n')
    added = target.commit("QualityMessageCanary")
    result = target.check("--base", "main", "--json")
    combined = result.stdout + result.stderr
    assert added in combined
    for canary in (AUTHOR_NAME, AUTHOR_EMAIL, "QualityMessageCanary"):
        assert canary not in combined


def test_json_lists_exclusions(target):
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.write(
        ".qualityignore.yml",
        "- rule: coding.undefined-name\n  paths: [a.py]\n  reason: fixture\n"
        "- rule: clean.complexity\n  reason: never applied\n",
    )
    target.write("a.py", "foo(1)\n")
    target.write("b.py", "bar(1)\n")
    target.write("c.py", f"import os  # nocheck: coding.unused-import -- legacy {CANARY}\n")
    target.stage()
    result = target.check("--staged", "--json")
    document = report(result)
    assert result.returncode == 1
    assert [item["path"] for item in document["findings"]] == ["b.py"]
    assert document["ignored"] == [
        {"rule": "coding.undefined-name", "paths": ["a.py"], "reason": "fixture"}
    ]
    assert document["nocheck"] == [{"path": "c.py", "line": 1, "rule": "coding.unused-import"}]
    assert CANARY not in result.stdout + result.stderr
