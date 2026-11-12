from pathlib import Path

import pytest

from quality import QualityError
from quality.gate import Hit
from quality.ignorefile import audit_lines, parse, split_ignored, stale_names
from quality.ruledata import load, locate

DATA = load(locate(str(Path(__file__).resolve().parents[2] / "rules")))
HARD = "security.eval-exec"
SOFT = "coding.unused-import"


def rule_named(rule_id: str):
    return next(rule for rule in DATA.rules if rule.id == rule_id)


def hit(rule_id: str, path: str) -> Hit:
    return Hit(rule_named(rule_id), path, 1, "", "", None, "", None, False, frozenset())


def test_parse_absent_and_empty_files():
    assert parse(None, DATA) == []
    assert parse(b"", DATA) == []


def test_parse_entry_fields():
    entry = parse(f"- rule: {SOFT}\n  paths: [a.py]\n  reason: why\n".encode(), DATA)[0]
    assert entry.public() == {"rule": SOFT, "paths": ["a.py"], "reason": "why"}
    assert entry.covers(SOFT, "a.py")
    assert not entry.covers(SOFT, "b.py")


@pytest.mark.parametrize(
    "content",
    [
        b"rule: x\n",
        b"- just text\n",
        b"- rule: x\n",
        b"- rule: x\n  reason: ''\n",
        b"- reason: why\n",
        b"- rule: x\n  reason: why\n  extra: 1\n",
        b"- rule: x\n  reason: why\n  paths: a.py\n",
        b"- rule: x\n  reason: why\n  paths: []\n",
        b"- rule: x\n  reason: [\n",
    ],
)
def test_parse_rejects_schema_violations(content: bytes):
    with pytest.raises(QualityError):
        parse(content, DATA)


def test_parse_error_never_quotes_the_file():
    with pytest.raises(QualityError) as caught:
        parse(b"- rule: CANARY\n  reason: [CANARY\n", DATA)
    assert "CANARY" not in str(caught.value)


@pytest.mark.parametrize(
    "paths",
    [
        "",
        "\n  paths: ['**']",
        "\n  paths: ['src/**/x.py']",
        "\n  paths: ['*']",
        "\n  paths: ['/*']",
        "\n  paths: ['*.py']",
        "\n  paths: ['[a-z]*']",
        "\n  paths: ['?.py']",
        "\n  paths: ['*/a.py']",
        "\n  paths: ['\\\\*.py']",
        "\n  paths: ['!a.py']",
        "\n  paths: ['/']",
        "\n  paths: ['./*']",
        "\n  paths: ['../a.py']",
        "\n  paths: [a.py, '*.py']",
    ],
)
def test_parse_rejects_broad_hard_entries(paths: str):
    with pytest.raises(QualityError):
        parse(f"- rule: {HARD}\n  reason: why{paths}\n".encode(), DATA)


@pytest.mark.parametrize(
    "pattern", ["a.py", "src/a.py", "tests/fixtures/*", "/tests/*.py", "a!b.py"]
)
def test_parse_accepts_hard_entry_with_a_literal_first_segment(pattern: str):
    parse(f"- rule: {HARD}\n  reason: why\n  paths: ['{pattern}']\n".encode(), DATA)


def test_parse_rejects_group_holding_a_hard_rule_without_paths():
    with pytest.raises(QualityError):
        parse(b"- rule: security\n  reason: why\n", DATA)


def test_parse_accepts_hard_entry_with_specific_paths():
    entry = parse(f"- rule: {HARD}\n  reason: why\n  paths: [a.py]\n".encode(), DATA)[0]
    assert entry.covers(HARD, "a.py")


def test_group_entry_covers_its_members():
    entry = parse(b"- rule: coding\n  reason: why\n", DATA)[0]
    assert entry.covers(SOFT, "any.py")
    assert not entry.covers("clean.complexity", "any.py")
    assert not entry.covers("codingx.rule", "any.py")


def test_split_ignored_consults_the_side_of_each_rule():
    soft_only = parse(f"- rule: {SOFT}\n  reason: why\n".encode(), DATA)
    hard_only = parse(f"- rule: {HARD}\n  reason: why\n  paths: [a.py]\n".encode(), DATA)
    hits = [hit(SOFT, "a.py"), hit(HARD, "a.py")]
    kept, applied = split_ignored(hits, soft_only + hard_only, [])
    assert [item.rule.id for item in kept] == [HARD]
    assert applied == soft_only
    kept, applied = split_ignored(hits, [], soft_only + hard_only)
    assert [item.rule.id for item in kept] == [SOFT]
    assert applied == hard_only


def test_split_ignored_reads_a_parse_gap_entry_from_the_base_side():
    entries = parse(b"- rule: coding.parse-incomplete\n  reason: why\n  paths: [src/]\n", DATA)
    hits = [hit("coding.parse-incomplete", "src/gap.js")]
    assert split_ignored(hits, entries, []) == (hits, [])
    assert split_ignored(hits, [], entries) == ([], entries)


GAP = "security.partial-scan"
STATIC = "security.static-analysis"


@pytest.mark.parametrize(
    "paths",
    ["", "\n  paths: ['**/*.js']", "\n  paths: ['web/*.js']", "\n  paths: [web/]", "\n  paths: ['!a.js']",
     "\n  paths: [a.js, '*.js']"],
)
def test_parse_rejects_a_partial_scan_entry_without_literal_files(paths: str):
    with pytest.raises(QualityError, match="literal file paths"):
        parse(f"- rule: {GAP}\n  reason: why{paths}\n".encode(), DATA)


def test_only_an_entry_naming_the_very_file_waives_a_partial_scan():
    entries = parse(
        f"- rule: {GAP}\n  reason: why\n  paths: [app.js, /web/run.js]\n"
        "- rule: security\n  reason: why\n  paths: ['web/*']\n".encode(),
        DATA,
    )
    hits = [hit(GAP, "web/app.js"), hit(GAP, "web/run.js"), hit(STATIC, "web/app.js")]
    kept, applied = split_ignored(hits, entries, entries)
    assert [(item.rule.id, item.path) for item in kept] == [(GAP, "web/app.js")]
    assert applied == entries
    kept, applied = split_ignored(hits, entries, [])
    assert [(item.rule.id, item.path) for item in kept] == [(GAP, "web/app.js"), (GAP, "web/run.js")]


def test_a_partial_scan_entry_for_a_checked_file_without_its_finding_is_stale():
    entries = parse(f"- rule: {GAP}\n  reason: why\n  paths: [web/app.js]\n".encode(), DATA)
    assert stale_names(entries, [hit(GAP, "web/app.js")], {"web/app.js"}, {GAP}) == []
    assert stale_names(entries, [], {"web/other.js"}, {GAP}) == []
    assert stale_names(entries, [], {"web/app.js"}, set()) == []
    assert stale_names(entries, [hit(STATIC, "web/app.js")], {"web/app.js"}, {GAP}) == entries


def test_audit_lines_one_per_change():
    old = parse(
        b"- rule: a.one\n  reason: why\n- rule: a.two\n  reason: why\n",
        DATA,
    )
    new = parse(
        b"- rule: a.one\n  reason: changed\n- rule: a.three\n  reason: why\n",
        DATA,
    )
    lines = audit_lines(old, new)
    assert len(lines) == 3
    assert sum(" removed " in line for line in lines) == 1
    assert sum(" added " in line for line in lines) == 1
    assert sum(" changed " in line for line in lines) == 1
