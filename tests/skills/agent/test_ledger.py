import hashlib

import pytest

from quality.agent import ledger

RULE = "clean.function-length"
TEXT = "import os\n\ndef long():\n    return 1\n\nx = 2\n"
LINE = 3
SHA = "1" * 40


def sha1(text: str) -> str:
    return hashlib.sha1(text.encode()).hexdigest()


def test_a_line_fingerprint_is_its_stripped_text_and_neighbourhood():
    lines = TEXT.splitlines()
    assert ledger.fingerprint(TEXT, LINE) == (sha1("def long():"), sha1("\n".join(row.strip() for row in lines[0:5])))


def test_a_file_fingerprint_is_the_whole_text():
    assert ledger.fingerprint(TEXT, None) == (sha1(TEXT), None)


def test_a_line_outside_the_text_has_no_fingerprint():
    assert ledger.fingerprint(TEXT, 99) == (None, None)


def test_a_row_without_context_accepts_only_a_key_without_a_twin():
    key, twin = (RULE, "a.py", SHA, "2" * 40), (RULE, "a.py", SHA, "3" * 40)
    reviewed = {(RULE, "a.py", SHA, None)}
    assert ledger.accepted([key, None], reviewed) == [True, False]
    assert ledger.accepted([key, twin], reviewed) == [False, False]
    assert ledger.accepted([key, twin], reviewed | {key}) == [True, False]


@pytest.mark.parametrize("line", ["not json", '{"rule": "x", "path": "a.py"}', "[1, 2]"], ids=["text", "no-sha1", "list"])
def test_a_malformed_row_names_its_source_and_line(line):
    good = f'{{"rule": "{RULE}", "path": "a.py", "sha1": "{SHA}"}}\n\n'
    with pytest.raises(ValueError, match="ledger.jsonl:3: want a JSON row"):
        ledger.parse(good + line, "ledger.jsonl")


def test_a_missing_ledger_holds_no_rows(tmp_path):
    assert ledger.listing(tmp_path) == set()
