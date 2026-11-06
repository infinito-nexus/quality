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
from quality.ruledata import Rule


def make_rule(rule_id: str, metric: dict | None) -> Rule:
    return Rule(rule_id, "low", "summary", {}, False, metric, False, False, False, None, None)


PLAIN = make_rule("coding.fixture", None)
METRIC = make_rule("clean.fixture", {"limit": 10})


def plain_hit(path: str, source: str, message: str) -> Hit:
    return Hit(PLAIN, path, 1, message, source, None, "", None)


@dataclass(frozen=True)
class Case:
    head: list
    base: list
    renames: dict


def judge(case: Case) -> list:
    return new_hits(case.head, merge_baselines([baseline_of(case.base, case.renames)]))


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
    assert new_hits(head, merge_baselines([one, two])) == []
    assert new_hits(head, merge_baselines([one])) == [head[1]]


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
