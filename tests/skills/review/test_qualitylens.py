from types import SimpleNamespace

import pytest

from quality.gate import Hit
from quality.report import Legal
from quality.ruledata import load, locate
from tests.skills.review.support import module

qualitylens = module("qualitylens")
options = module("options")

DATA = load(locate(None))
SECRET_TOOL_TEXT = "tool text that stays in memory"


def rule(rule_id: str):
    return next(item for item in DATA.rules if item.id == rule_id)


def hit(rule_id: str, path: str, commit: str | None) -> Hit:
    return Hit(rule(rule_id), path, 3, SECRET_TOOL_TEXT, "", None, "", commit, False, frozenset(), ())


def request(*argv: str):
    return options.parse(["--repo", ".", "--json", *argv])


def change(tmp_path) -> object:
    return SimpleNamespace(repo=SimpleNamespace(root=str(tmp_path)), base="b" * 40)


@pytest.mark.parametrize(
    ("rule_id", "lens"),
    [("coding.unused-import", "quality"), ("legal.external-request", "legal"), ("clean.function-length", "architecture")],
)
def test_a_rule_belongs_to_the_lens_of_its_weight(rule_id, lens):
    assert qualitylens.lens_of(rule(rule_id)) == lens


def test_the_deep_tier_needs_a_database_and_a_base():
    assert qualitylens.deep_reason(request("--staged", "--db", "/db")) == qualitylens.STAGED_DEEP
    assert qualitylens.deep_reason(request("--base", "main")) == qualitylens.NO_DATABASE
    assert qualitylens.deep_reason(request("--base", "main", "--db", "/db")) is None


def test_without_the_deep_tier_a_diff_selects_the_fast_rules_only(tmp_path):
    fast = qualitylens.options_of(request("--base", "main"), change(tmp_path), DATA, False)
    assert fast.mode == "base"
    assert fast.ref == "b" * 40
    assert "coding.unused-import" in fast.selected
    assert "clean.clones" not in fast.selected
    assert qualitylens.options_of(request("--base", "main"), change(tmp_path), DATA, True).selected is None
    assert qualitylens.options_of(request("--staged"), change(tmp_path), DATA, False).selected is None
    assert qualitylens.options_of(request("--range", "a..b"), change(tmp_path), DATA, False).mode == "base"


def test_a_finding_carries_its_tier_blob_and_commit_but_never_the_tool_text():
    blobs = {("a.py", None): "1" * 40, ("a.py", "c" * 40): "2" * 40}
    current = qualitylens.finding_of(hit("coding.unused-import", "a.py", None), blobs)
    history = qualitylens.finding_of(hit("security.secret", "a.py", "c" * 40), blobs)
    assert (current["lens"], current["tier"], current["blob"], current["commit"]) == ("quality", "fast", "1" * 40, None)
    assert (history["blob"], history["commit"]) == ("2" * 40, "c" * 40)
    assert SECRET_TOOL_TEXT not in current["message"] + history["message"]


def test_scores_count_the_findings_left_and_mark_unchecked_licences():
    hits = [hit("clean.function-length", "a.py", None), hit("legal.external-request", "b.py", None)]
    clean = SimpleNamespace(legal=Legal(100, 0, 0))
    assert qualitylens.scores_of(clean, hits) == {"legal": 75, "architecture": 90}
    unchecked = SimpleNamespace(legal=Legal(100, 0, 1))
    assert qualitylens.scores_of(unchecked, [])["legal"] == "~100"
    whole = SimpleNamespace(legal=None)
    assert qualitylens.scores_of(whole, hits) == {"legal": None, "architecture": None}
