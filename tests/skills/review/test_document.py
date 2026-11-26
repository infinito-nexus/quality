import json

from tests.skills.review.support import finding, module

document = module("document")

VERSION = "quality 0.3.0 rules sha256:0123456789abcdef"


def quality(findings: list) -> object:
    return document.Result("quality", VERSION, findings, {}, None, None)


def test_the_document_holds_exactly_the_contract_keys():
    results = [quality([finding("a.py", 1)]), document.skipped("performance", "runs only with --measure"), *document.judgements()]
    built = document.assemble(results)
    assert list(built) == ["findings", "scores", "lenses", "ran", "skipped"]
    assert list(built["scores"]) == ["security", "legal", "architecture", "break_risk", "confidence", "efficiency", "speed"]
    assert all(list(item) == list(document.FINDING_KEYS) for item in built["findings"])
    assert all(list(item) == ["lens", "reason"] for item in built["skipped"])
    assert json.loads(json.dumps(built)) == built


def test_judgements_stay_null_and_are_skipped_by_their_skill():
    built = document.assemble([quality([]), *document.judgements()])
    assert built["scores"]["break_risk"] is None
    assert built["scores"]["confidence"] is None
    assert {item["lens"] for item in built["skipped"]} == {"kvb-quality-break-risk", "kvb-quality-confidence"}


def test_scores_no_lens_filled_are_null():
    security = document.Result("security", "security.py sha256:00", [], {"security": 75}, None, None)
    built = document.assemble([quality([]), security])
    assert built["scores"] == {
        "security": 75,
        "legal": None,
        "architecture": None,
        "break_risk": None,
        "confidence": None,
        "efficiency": None,
        "speed": None,
    }


def test_lenses_map_every_lens_that_ran_to_its_version():
    results = [quality([]), document.skipped("quality-deep", "needs --db"), document.failed("security", "exit 2")]
    built = document.assemble(results)
    assert built["ran"] == ["quality"]
    assert built["lenses"] == {"quality": VERSION}
    assert built["skipped"] == [
        {"lens": "quality-deep", "reason": "needs --db"},
        {"lens": "security", "reason": "exit 2"},
    ]


def test_findings_are_ordered_by_path_then_line():
    found = [finding("b.py", 2), finding("a.py", 3), finding("a.py", None), finding("a.py", 1)]
    built = document.assemble([quality(found)])
    assert [(item["path"], item["line"]) for item in built["findings"]] == [
        ("a.py", None),
        ("a.py", 1),
        ("a.py", 3),
        ("b.py", 2),
    ]


def test_exit_codes_follow_quality_check():
    assert document.exit_code([quality([]), *document.judgements()]) == 0
    assert document.exit_code([quality([finding("a.py", 1)])]) == 1
    assert document.exit_code([quality([]), document.failed("security", "exit 2")]) == 2
    assert document.exit_code([quality([finding("a.py", 1)]), document.failed("security", "exit 2")]) == 2
    pending = document.Result("quality", VERSION, [], {}, None, "pending rules: x")
    assert document.exit_code([pending]) == 2
