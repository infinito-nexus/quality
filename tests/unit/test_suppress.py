import re

import pytest

from quality import QualityError
from quality.suppress import (
    NOTHING,
    declaration,
    line_comment,
    nocheck_rule,
    python_comments,
    rule_matches,
    with_declaration,
)


def test_no_declaration_is_empty():
    assert declaration(None, {"python"}) == {"directives": [], "pragmas_allowed": []}


def test_a_declaration_joins_the_catalogue_groups():
    catalogue = {"directives": [{"tool": "mypy", "spellings": ["type:"]}]}
    found = declaration(b"directives:\n  - spellings: ['nocheck:']\npragmas_allowed: ['noqa: E']\n", {"python"})
    merged = with_declaration(catalogue, found)
    assert [group["spellings"] for group in merged["directives"]] == [["type:"], ["nocheck:"]]
    assert merged["pragmas_allowed"] == ["noqa: E"]


def test_without_allowed_pragmas_nothing_matches():
    assert re.search(NOTHING, "# noqa") is None


@pytest.mark.parametrize(
    "content",
    [b"- x\n", b"pragmas_allowed: []\n", b"directives: x\n", b"directives:\n  - [x]\n", b": :\n  - ["],
)
def test_a_malformed_declaration_is_refused(content):
    with pytest.raises(QualityError, match=r"^\.quality/comments\.yml: "):
        declaration(content, None)


@pytest.mark.parametrize(
    ("comment", "expected"),
    [
        ("# nocheck: coding.x -- because", "coding.x"),
        ("#nocheck:coding.x -- because", "coding.x"),
        ("// nocheck: clean -- group", "clean"),
        ("# nocheck: coding.x", None),
        ("# nocheck: coding.x --", None),
        ("# nocheck: coding.x -- ", None),
        ("# no check", None),
    ],
)
def test_nocheck_rule(comment: str, expected: str | None):
    assert nocheck_rule(comment) == expected


def test_python_comments_ignore_strings_and_docstrings():
    source = b'x = "# not"  # real\n"""\n# neither\n"""\ny = 1\n# last\n'
    assert python_comments(source) == {1: "# real", 6: "# last"}


def test_python_comments_survive_a_broken_file():
    assert python_comments(b'# first\nx = "open\n(') == {1: "# first"}


def test_python_comments_survive_undecodable_bytes():
    assert python_comments(b'# first\nx = 1\ny = "caf\xe9"\n# later\n').get(1) == "# first"
    assert python_comments(b'x = "caf\xe9"  # hidden\n') == {}


@pytest.mark.parametrize(
    ("text", "marker", "expected"),
    [
        ("echo hi # real", "#", "# real"),
        ('echo "# not" # real', "#", "# real"),
        ("echo '# not'", "#", None),
        ("echo $# ${#x}", "#", None),
        (r'echo "a\" # still quoted"', "#", None),
        ('x = "http://a"; // real', "//", "// real"),
        ("no comment", "//", None),
    ],
)
def test_line_comment(text: str, marker: str, expected: str | None):
    assert line_comment(text, marker) == expected


def test_rule_matches_id_and_group_only():
    assert rule_matches("coding.x", "coding.x")
    assert rule_matches("coding.x", "coding")
    assert not rule_matches("coding.x", "cod")
    assert not rule_matches("coding.x", "coding.y")
