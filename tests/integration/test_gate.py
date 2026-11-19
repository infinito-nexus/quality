import pytest

from tests.integration.support import (
    add_rules,
    branchy,
    report,
    rule_for,
    rule_ids,
    rules_copy,
)

F401 = rule_for("F401")
F821 = rule_for("F821")
INP001 = rule_for("INP001")
FILLER = "".join(f"filler_{index} = {index}\n" for index in range(20))


def assert_clean(result) -> None:
    assert rule_ids(result) == []
    assert result.returncode == 0


def test_gate_deleted_last_use(target, mode):
    target.write("a.py", "import os\n\nprint(os.name)\n")
    target.start_feature(mode)
    target.write("a.py", "import os\n")
    target.advance(mode)
    result = target.judge(mode, "--json")
    assert result.returncode == 1
    assert rule_ids(result) == [F401]


def test_gate_inline_reformat(target, mode):
    target.write("a.py", "a = 1\nb = 2\nfoo(a,b)\n")
    target.start_feature(mode)
    target.write("a.py", "a = 1\nb = 2\nfoo(a, b)\n")
    target.advance(mode)
    assert_clean(target.judge(mode, "--json"))
    assert F821 in rule_ids(target.check("--all", "--json"))


def test_gate_multiline_reflow(target, mode):
    target.write("a.py", "a = 1\nb = 2\nfoo(a, b)\n")
    target.start_feature(mode)
    target.write("a.py", "a = 1\nb = 2\nfoo(\n    a,\n    b,\n)\n")
    target.advance(mode)
    assert_clean(target.judge(mode, "--json"))
    assert F821 in rule_ids(target.check("--all", "--json"))


def test_gate_identical_lines(target, mode):
    target.write("a.py", "foo(1)\n")
    target.start_feature(mode)
    target.write("a.py", "foo(1)\nfoo(1)\nfoo(1)\n")
    target.advance(mode)
    result = target.judge(mode, "--json")
    assert result.returncode == 1
    assert rule_ids(result) == [F821, F821]


def test_gate_rename_with_edit(target, mode):
    target.write("old.py", "foo(1)\n" + FILLER)
    target.start_feature(mode)
    target.git("mv", "old.py", "new.py")
    target.write("new.py", "foo(1)\n" + FILLER.replace("filler_3 = 3", "filler_3 = 33"))
    target.advance(mode)
    assert_clean(target.judge(mode, "--json"))


def test_gate_rename_with_reflow(target, mode):
    target.write("old.py", "foo(1, 2)\n" + FILLER)
    target.start_feature(mode)
    target.git("mv", "old.py", "new.py")
    target.write("new.py", "foo(\n    1,\n    2,\n)\n" + FILLER)
    target.advance(mode)
    assert_clean(target.judge(mode, "--json"))


def test_gate_move_between_files(target, mode):
    target.write("a.py", "x = 1\nfoo(1)\n")
    target.write("b.py", "y = 2\n")
    target.start_feature(mode)
    target.write("a.py", "x = 1\n")
    target.write("b.py", "y = 2\nfoo(1)\n")
    target.advance(mode)
    assert_clean(target.judge(mode, "--json"))


def test_gate_same_file_swap(target, mode):
    target.write("a.py", "foo(1)\n")
    target.start_feature(mode)
    target.write("a.py", "bar(1)\n")
    target.advance(mode)
    result = target.judge(mode, "--json")
    assert result.returncode == 1
    assert rule_ids(result) == [F821]


def test_gate_file_level_finding(target, mode):
    target.write("loose/c.py", "x = 1\n")
    target.write("pkg/__init__.py", "")
    target.start_feature(mode)
    target.write("loose/c.py", "x = 2\n")
    target.advance(mode)
    assert_clean(target.judge(mode, "--json"))
    target.write("other/d.py", "y = 1\n")
    target.advance(mode)
    result = target.judge(mode, "--json")
    assert result.returncode == 1
    findings = report(result)["findings"]
    assert [(item["rule"], item["path"], item["line"]) for item in findings] == [
        (INP001, "other/d.py", None)
    ]


def test_gate_new_rule_on_legacy(target, tmp_path):
    target.write("a.py", 'print("x")\n' + FILLER)
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    target.write("a.py", 'print("x")\n' + FILLER.replace("filler_3 = 3", "filler_3 = 33"))
    target.commit()
    rules = rules_copy(tmp_path / "rules")
    add_rules(
        rules,
        [
            {
                "id": "coding.print-call",
                "severity": "low",
                "summary": "print call",
                "enforcer": {"python": {"tool": "ruff", "codes": ["T201"]}},
            }
        ],
    )
    assert "coding.print-call" in rule_ids(target.check("--all", "--json", "--rules", str(rules)))
    assert_clean(target.check("--base", "main", "--json", "--rules", str(rules)))


def test_metric_growth(target, mode):
    target.write("a.py", branchy("f", 30))
    target.start_feature(mode)
    target.write("a.py", branchy("f", 200))
    target.advance(mode)
    result = target.judge(mode, "--json")
    assert result.returncode == 1
    complexity = [
        finding for finding in report(result)["findings"] if finding["rule"] == "clean.complexity"
    ]
    assert [(item["path"], item["value"]) for item in complexity] == [("a.py", 201)]


def test_metric_legacy_function_unchanged(target, mode):
    target.write("a.py", branchy("f", 30))
    target.start_feature(mode)
    target.write("a.py", "x = 1\n\n\n" + branchy("f", 30))
    target.advance(mode)
    assert_clean(target.judge(mode, "--json"))


def test_metric_legacy_unchanged(target):
    legacy = "".join(f"value_{index} = {index}\n" for index in range(800))
    target.write("big.py", legacy)
    target.write("small.py", "x = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    target.write("small.py", "x = 2\n")
    target.commit()
    assert_clean(target.check("--base", "main", "--json"))
    target.write("big.py", legacy.replace("value_7 = 7", "value_7 = 77"))
    target.commit()
    assert_clean(target.check("--base", "main", "--json"))
    target.write("big.py", legacy + "extra = 1\n")
    target.commit()
    result = target.check("--base", "main", "--json")
    assert result.returncode == 1
    assert [item["value"] for item in report(result)["findings"]] == [801]


def test_metric_new_entity(target, mode):
    target.write("seed.py", "x = 1\n")
    target.start_feature(mode)
    target.write("new.py", "".join(f"value_{index} = {index}\n" for index in range(501)))
    target.advance(mode)
    result = target.judge(mode, "--json")
    assert result.returncode == 1
    findings = report(result)["findings"]
    assert [(item["rule"], item["value"], item["line"]) for item in findings] == [
        ("clean.file-lines", 501, None)
    ]


def test_metric_limit_itself_passes(target, mode):
    target.write("seed.py", "x = 1\n")
    target.start_feature(mode)
    target.write("new.py", "".join(f"value_{index} = {index}\n" for index in range(500)))
    target.advance(mode)
    assert_clean(target.judge(mode, "--json"))


def architecture(result) -> tuple:
    document = report(result)
    return document["architecture"], [(item["rule"], item["lens"]) for item in document["findings"]]


def test_architecture_counts_a_function_the_change_pushes_over_the_limit(target, mode):
    target.write("a.py", branchy("f", 5))
    target.start_feature(mode)
    target.write("a.py", "import os\n\n\n" + branchy("f", 12))
    target.advance(mode)
    assert architecture(target.judge(mode, "--json")) == (
        90,
        [(F401, None), ("clean.complexity", "SRP")],
    )


def test_architecture_skips_a_function_over_the_limit_at_the_base(target, mode):
    target.write("a.py", branchy("f", 30))
    target.start_feature(mode)
    target.write("a.py", "x = 1\n\n\n" + branchy("f", 30))
    target.advance(mode)
    assert architecture(target.judge(mode, "--json")) == (100, [])
    assert architecture(target.check("--all", "--json")) == (
        None,
        [("clean.complexity", "SRP"), ("clean.function-length", "SRP")],
    )


def test_architecture_counts_a_file_the_change_pushes_past_the_line_limit(target, mode):
    lines = "".join(f"value_{index} = {index}\n" for index in range(500))
    legacy = "".join(f"legacy_{index} = {index}\n" for index in range(600))
    target.write("a.py", lines)
    target.write("legacy.py", legacy)
    target.start_feature(mode)
    target.write("a.py", lines + "extra = 1\n")
    target.write("legacy.py", legacy.replace("legacy_7 = 7", "legacy_7 = 77"))
    target.advance(mode)
    assert architecture(target.judge(mode, "--json")) == (75, [("clean.file-lines", "SRP")])


CLONED_JS = (
    "export function totals(rows) {\n"
    "  const first = rows[0] + rows[1] + rows[2] + rows[3];\n"
    "  const second = rows[4] * rows[5] - rows[6] * rows[7];\n"
    "  const third = rows[8] - rows[9] + rows[10] - rows[11];\n"
    "  return [first, second, third];\n"
    "}\n"
)
CLONE_FRAGMENTS = [("clean.clones", "DRY"), ("clean.clones", "DRY")]


@pytest.mark.deep
def test_architecture_counts_a_javascript_clone_the_change_adds(target):
    target.write("web/a.js", CLONED_JS)
    target.start_feature("base")
    target.write("web/b.js", CLONED_JS)
    target.advance("base")
    assert architecture(target.judge("base", "--json")) == (90, CLONE_FRAGMENTS)


@pytest.mark.deep
def test_architecture_skips_a_javascript_clone_at_the_base(target):
    target.write("web/a.js", CLONED_JS)
    target.write("web/b.js", CLONED_JS)
    target.start_feature("base")
    target.write("web/b.js", CLONED_JS + "export const marker = 1;\n")
    target.advance("base")
    assert architecture(target.judge("base", "--json")) == (100, [])
    assert architecture(target.check("--all", "--json")) == (None, CLONE_FRAGMENTS)
