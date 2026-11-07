import pytest

from quality.suppress import line_comment, nocheck_rule, python_comments, rule_matches


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
