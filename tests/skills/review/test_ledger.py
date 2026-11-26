import hashlib
import json

import pytest

from quality import QualityError
from quality.agent.ledger import fingerprint
from tests.skills.review.support import module

ledger = module("ledger")

RULE = "clean.function-length"
LEDGER = "security-accepted.jsonl"
TEXT = "import os\n\ndef long():\n    return 1\n\nx = 2\n"
LINE = 3


def sha1(text: str) -> str:
    return hashlib.sha1(text.encode()).hexdigest()


def item(path: str, line: int | None) -> dict:
    return {"rule": RULE, "path": path, "line": line}


def test_a_row_with_context_accepts_until_the_neighbourhood_changes():
    sha, context = fingerprint(TEXT, LINE)
    reviewed = {(RULE, "a.py", sha, context)}
    assert ledger.kept([item("a.py", LINE)], {"a.py": TEXT}, reviewed) == [False]
    edited = TEXT.replace("return 1", "return 2")
    assert ledger.kept([item("a.py", LINE)], {"a.py": edited}, reviewed) == [True]


def test_a_row_without_context_accepts_only_a_finding_without_a_twin():
    reviewed = {(RULE, "a.py", sha1("def long():"), None)}
    assert ledger.kept([item("a.py", LINE)], {"a.py": TEXT}, reviewed) == [False]
    twins = TEXT + "def long():\n    return 3\n"
    assert ledger.kept([item("a.py", LINE), item("a.py", 7)], {"a.py": twins}, reviewed) == [True, True]


def test_a_finding_on_another_path_or_without_text_is_kept():
    reviewed = {(RULE, "a.py", sha1("def long():"), None)}
    assert ledger.kept([item("b.py", LINE)], {"b.py": TEXT}, reviewed) == [True]
    assert ledger.kept([item("a.py", LINE)], {}, reviewed) == [True]


def roots(tmp_path, monkeypatch) -> tuple:
    council, state = tmp_path / "council", tmp_path / "state"
    monkeypatch.setenv("AGENTS_COUNCIL_ROOT", str(council))
    monkeypatch.setenv("XDG_STATE_HOME", str(state))
    kept = state / "agents-council"
    council.mkdir()
    kept.mkdir(parents=True)
    return council, kept


def test_rows_read_the_shared_ledger_and_its_kept_copy(tmp_path, monkeypatch):
    council, kept = roots(tmp_path, monkeypatch)
    assert ledger.rows() == set()
    rows = [
        {"rule": RULE, "path": "a.py", "sha1": "1" * 40, "reason": "by design"},
        {"rule": RULE, "path": "b.py", "sha1": "2" * 40, "context": "3" * 40, "reason": "by design"},
    ]
    (council / LEDGER).write_text("".join(json.dumps(row) + "\n" for row in rows) + "\n")
    (kept / LEDGER).write_text(json.dumps({"rule": RULE, "path": "c.py", "sha1": "4" * 40}) + "\n")
    assert ledger.rows() == {(RULE, "a.py", "1" * 40, None), (RULE, "b.py", "2" * 40, "3" * 40), (RULE, "c.py", "4" * 40, None)}
    assert ledger.wanted(ledger.rows()) == {(RULE, "a.py"), (RULE, "b.py"), (RULE, "c.py")}


@pytest.mark.parametrize("line", ["not json", '{"rule": "x", "path": "a.py"}', "[1, 2]"], ids=["text", "no-sha1", "list"])
def test_a_malformed_row_is_an_error(tmp_path, monkeypatch, line):
    council, _kept = roots(tmp_path, monkeypatch)
    (council / LEDGER).write_text(line + "\n")
    with pytest.raises(QualityError, match="security-accepted.jsonl:1"):
        ledger.rows()
