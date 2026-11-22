from dataclasses import dataclass

from quality.gate import (
    Hit,
    baseline_of,
    fingerprint,
    merge_baselines,
    metric_hit,
    new_hits,
    normalise_message,
)
from quality.repo import parse_added_lines
from quality.ruledata import Rule


def make_rule(rule_id: str, metric: dict | None) -> Rule:
    return Rule(rule_id, "low", "summary", {}, False, metric, False, False, False, None, None, False, None, None, None)


PLAIN = make_rule("coding.fixture", None)
METRIC = make_rule("clean.fixture", {"limit": 10})


def plain_hit(path: str, source: str, message: str) -> Hit:
    return Hit(PLAIN, path, 1, message, source, None, "", None, False, frozenset(), ())


@dataclass(frozen=True)
class Case:
    head: list
    base: list
    renames: dict


def judge(case: Case) -> list:
    return new_hits(case.head, merge_baselines([baseline_of(case.base, case.renames)]), {})


def test_fingerprint_is_rule_and_source_without_path():
    first = plain_hit("a.py", "foo(a,b)", "m")
    second = plain_hit("b/c.py", "foo(a,b)", "other")
    assert fingerprint(first) == fingerprint(second)


def test_normalise_message_replaces_digits_and_paths():
    assert normalise_message("File `pkg/sub/mod.py` line 12") == "File `<path>` line 0"
    assert normalise_message("/srv/x/head/a.py:3") == "<path>"
    assert normalise_message("Undefined name `foo`") == "Undefined name `foo`"


def test_gate_requires_both_counts_to_rise():
    moved = plain_hit("b.py", "foo(1)", "m")
    assert judge(Case([moved], [plain_hit("a.py", "foo(1)", "m")], {})) == []
    reflowed = plain_hit("a.py", "foo(", "m")
    assert judge(Case([reflowed], [plain_hit("a.py", "foo(1)", "m")], {})) == []
    swapped = plain_hit("a.py", "bar(1)", "n")
    assert judge(Case([swapped], [plain_hit("a.py", "foo(1)", "m")], {})) == [swapped]


def test_gate_counts_identical_lines_as_a_multiset():
    copies = [plain_hit("a.py", "foo(1)", "m") for _ in range(3)]
    assert len(judge(Case(copies, [plain_hit("a.py", "foo(1)", "m")], {}))) == 2


def test_gate_maps_renames_for_the_per_file_count():
    reflowed = plain_hit("new.py", "foo(", "m")
    legacy = plain_hit("old.py", "foo(1)", "m")
    assert judge(Case([reflowed], [legacy], {"old.py": "new.py"})) == []
    assert judge(Case([reflowed], [legacy], {})) == [reflowed]


def test_merge_takes_the_maximum_of_both_parents():
    one = baseline_of([plain_hit("a.py", "x", "m")], {})
    two = baseline_of([plain_hit("b.py", "y", "n")], {})
    head = [plain_hit("a.py", "x", "m"), plain_hit("b.py", "y", "n")]
    assert new_hits(head, merge_baselines([one, two]), {}) == []
    assert new_hits(head, merge_baselines([one]), {}) == [head[1]]


def line_hit(path: str, line: int, source: str) -> Hit:
    return Hit(PLAIN, path, line, "m", source, None, "", None, False, frozenset(), ())


def gate_of(base: list, head: list, added: dict) -> list:
    return new_hits(head, merge_baselines([baseline_of(base, {})]), added)


def test_gate_reports_as_many_findings_as_both_rises_allow():
    legacy = line_hit("a.py", 9, "# shared")
    fresh = line_hit("a.py", 1, "# fresh")
    copy = line_hit("0.py", 1, "# shared")
    for added in ({}, {"a.py": {1}, "0.py": {1}}):
        assert gate_of([line_hit("a.py", 8, "# shared")], [legacy, fresh, copy], added) == [fresh, copy]
    moved, other, elsewhere = line_hit("x.py", 10, "s1"), line_hit("x.py", 5, "s2"), line_hit("y.py", 1, "s1")
    for added in ({}, {"x.py": {5, 10}}):
        assert gate_of([line_hit("x.py", 20, "s1")], [moved, other, elsewhere], added) == [elsewhere, other]


def test_gate_hands_a_rise_to_the_added_line_first():
    legacy = line_hit("a.py", 10, "# shared")
    fresh = line_hit("a.py", 1, "# shared")
    base = [line_hit("a.py", 9, "# shared")]
    assert gate_of(base, [legacy, fresh], {"a.py": {1}}) == [fresh]
    assert gate_of(base, [legacy, fresh], {}) == [legacy]


def test_gate_prefers_the_added_line_across_classes():
    base = [line_hit("z.py", 5, "# old"), line_hit("a.py", 9, "# shared")]
    edited, legacy, fresh = line_hit("z.py", 5, "# shared"), line_hit("a.py", 9, "# shared"), line_hit("a.py", 1, "# fresh")
    assert gate_of(base, [edited, legacy, fresh], {"z.py": {5}, "a.py": {1}}) == [fresh]
    assert gate_of(base, [edited, legacy, fresh], {}) == [legacy]


def test_gate_fills_added_lines_before_the_rest_of_a_class():
    base = [Hit(PLAIN, "c.py", 3, "n", "s1", None, "", None, False, frozenset(), ())]
    copy, legacy, other = line_hit("c.py", 2, "s1"), line_hit("c.py", 5, "s1"), line_hit("a.py", 5, "s1")
    assert gate_of(base, [copy, legacy, other], {"c.py": {2}, "a.py": {5}}) == [copy, other]


def test_metric_compare_growth_new_and_legacy():
    legacy = metric_hit(METRIC, "a.py", 1, 31, "f")
    grown = metric_hit(METRIC, "a.py", 1, 201, "f")
    assert judge(Case([grown], [legacy], {})) == [grown]
    assert judge(Case([legacy], [grown], {})) == []
    same = metric_hit(METRIC, "a.py", 9, 31, "f")
    assert judge(Case([same], [legacy], {})) == []
    fresh = metric_hit(METRIC, "a.py", 1, 11, "g")
    assert judge(Case([fresh], [legacy], {})) == [fresh]


def test_metric_compare_follows_renames_and_repeated_names():
    legacy = metric_hit(METRIC, "old.py", 1, 31, "f")
    moved = metric_hit(METRIC, "new.py", 1, 31, "f")
    assert judge(Case([moved], [legacy], {"old.py": "new.py"})) == []
    twice = [metric_hit(METRIC, "a.py", 1, 31, "f"), metric_hit(METRIC, "a.py", 9, 20, "f")]
    known = [metric_hit(METRIC, "a.py", 1, 31, "f")]
    assert judge(Case(twice, known, {})) == [twice[1]]


PATCH = b"\n".join(
    [
        b"diff --git a/a.py b/a.py",
        b"--- a/a.py",
        b"+++ b/a.py",
        b"@@ -3 +3,2 @@",
        b"--- a/lost.py",
        b"+++ b/lost.py",
        b"+kept",
        b"@@ -9,0 +11 @@",
        b"+tail",
        b"\\ No newline at end of file",
        b"diff --git a/my file.py b/my file.py",
        b"new file mode 100644",
        b"--- /dev/null",
        b"+++ b/my file.py\t",
        b"@@ -0,0 +1,2 @@",
        b"+one",
        b"+two",
        b'diff --git "a/t\\303\\244.py" "b/t\\303\\244.py"',
        b'--- "a/t\\303\\244.py"',
        b'+++ "b/t\\303\\244.py"',
        b"@@ -1 +1 @@",
        b"-x",
        b"+y",
        b"diff --git a/gone.py b/gone.py",
        b"deleted file mode 100644",
        b"--- a/gone.py",
        b"+++ /dev/null",
        b"@@ -1,2 +0,0 @@",
        b"-a",
        b"-b",
        b"",
    ]
)


def test_added_lines_read_hunk_content_as_content():
    assert parse_added_lines(PATCH) == {"a.py": {3, 4, 11}, "my file.py": {1, 2}}
