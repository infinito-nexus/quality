import pytest

from quality import QualityError, printable
from quality.adapters import chunked
from quality.cli import main
from quality.report import Outcome, exit_code, public_finding
from quality.snapshot import safe_path


def outcome(findings: list, incomplete: list) -> Outcome:
    return Outcome(findings, [], [], [], [], incomplete, [])


def test_clean_exits_0():
    assert exit_code(outcome([], [])) == 0


def test_findings_exit_1_even_when_incomplete():
    assert exit_code(outcome([object()], [])) == 1
    assert exit_code(outcome([object()], ["security.secret"])) == 1


def test_incomplete_without_findings_exits_2():
    assert exit_code(outcome([], ["security.secret"])) == 2


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["check"],
        ["check", "--staged", "--all"],
        ["check", "--bas", "main"],
        ["unknown"],
    ],
)
def test_usage_errors_exit_2(argv: list):
    with pytest.raises(SystemExit) as caught:
        main(argv)
    assert caught.value.code == 2


def test_internal_error_prints_only_its_type(monkeypatch, capsys):
    def explode(_options):
        raise RuntimeError("QUALITYREDACTCANARY")

    monkeypatch.setattr("quality.modes.check", explode)
    assert main(["check", "--all"]) == 2
    captured = capsys.readouterr()
    assert "QUALITYREDACTCANARY" not in captured.out + captured.err
    assert "RuntimeError" in captured.err


@pytest.mark.parametrize(
    ("raw", "shown"),
    [
        ("plain ü.py: text", "plain ü.py: text"),
        ("a\nb", "a\\nb"),
        ("\x1b[31m", "\\x1b[31m"),
        ("\x9b", "\\x9b"),
        (chr(0x2028), "\\u2028"),
        ("\udc80", "\\udc80"),
    ],
)
def test_printable_escapes_only_what_a_terminal_would_act_on(raw: str, shown: str):
    assert printable(raw) == shown


def test_version_exits_0(capsys):
    with pytest.raises(SystemExit) as caught:
        main(["--version"])
    assert caught.value.code == 0
    assert capsys.readouterr().out.startswith("quality ")


@pytest.mark.parametrize(
    "path",
    ["/abs.py", "../up.py", "a/../b.py", ".git/config", "a/.GIT/config", "a//b.py", "./a.py", "-"],
)
def test_safe_path_rejects(path: str):
    with pytest.raises(QualityError):
        safe_path(path)


def test_safe_path_accepts_plain_paths():
    assert safe_path("a/b.py") == "a/b.py"
    assert safe_path(".github/workflows/x.yml") == ".github/workflows/x.yml"
    assert safe_path("ü.py") == "ü.py"


def test_chunked_respects_the_budget_and_keeps_every_file():
    files = ["aa", "bb", "cc", "dd"]
    assert chunked(files, 6) == [["aa", "bb"], ["cc", "dd"]]
    assert chunked(files, 1) == [["aa"], ["bb"], ["cc"], ["dd"]]
    assert chunked([], 6) == []


def test_public_finding_holds_only_the_allowed_fields():
    class FakeRule:
        id = "coding.x"
        severity = "low"
        summary = "summary"

    class FakeHit:
        rule = FakeRule()
        path = "a.py"
        line = 1
        value = None
        commit = None
        message = "CANARY"
        source = "CANARY"
        entity = "CANARY"

    finding = public_finding(FakeHit())
    assert set(finding) == {"rule", "path", "line", "severity", "summary", "value", "commit"}
    assert "CANARY" not in str(finding)
