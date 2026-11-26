import pytest

from tests.skills.review.support import module, run_review

options = module("options")


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["--staged"], (options.STAGED, None, None)),
        (["--base", "main"], (options.BASE, "main", None)),
        (["--range", "main..feature"], (options.RANGE, "main", "feature")),
        (["--all"], (options.ALL, None, None)),
    ],
    ids=["staged", "base", "range", "all"],
)
def test_each_mode_parses(argv, expected):
    request = options.parse(["--repo", ".", "--json", *argv])
    assert (request.mode, request.ref, request.end) == expected
    assert (request.paths, request.db, request.measure, request.command) == ((), None, False, ())


def test_paths_are_repeatable_and_repository_relative():
    request = options.parse(
        ["--repo", ".", "--json", "--staged", "--path", "./a.py", "--path", "pkg/b.py", "--path", "a.py"]
    )
    assert request.paths == ("a.py", "pkg/b.py")


def test_measure_takes_the_command_after_the_separator():
    request = options.parse(["--repo", ".", "--json", "--base", "main", "--measure", "--", "make", "test", "--fast"])
    assert request.measure
    assert request.command == ("make", "test", "--fast")


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["--staged", "--all"],
        ["--base", "main", "--range", "main..feature"],
        ["--staged", "--nonsense"],
        ["--staged", "--pat", "a.py"],
        ["--range", "main...feature"],
        ["--range", "main"],
        ["--range", "..feature"],
        ["--staged", "--path", "/etc/hosts"],
        ["--staged", "--path", "../a.py"],
        ["--staged", "--path", "."],
        ["--staged", "--measure"],
        ["--staged", "--", "make"],
    ],
    ids=[
        "no-mode",
        "staged-and-all",
        "base-and-range",
        "unknown-option",
        "abbreviated-option",
        "three-dot-range",
        "range-without-end",
        "range-without-start",
        "absolute-path",
        "path-leaving-the-repository",
        "path-of-the-root",
        "measure-without-command",
        "command-without-measure",
    ],
)
def test_usage_errors_exit_2(argv):
    with pytest.raises(SystemExit) as raised:
        options.parse(["--repo", ".", "--json", *argv])
    assert raised.value.code == 2


def test_a_missing_json_flag_exits_2():
    with pytest.raises(SystemExit) as raised:
        options.parse(["--repo", ".", "--staged"])
    assert raised.value.code == 2


@pytest.mark.parametrize(
    "argv",
    [["--staged", "--all"], ["--staged", "--nonsense"]],
    ids=["two-modes", "unknown-option"],
)
def test_the_script_exits_2_on_usage_errors_before_printing_json(tmp_path, argv):
    result = run_review(tmp_path, "--repo", str(tmp_path), "--json", *argv)
    assert result.returncode == 2, result.stderr
    assert result.stdout == ""
    assert "usage: review.py" in result.stderr


def test_the_script_exits_2_outside_a_repository(tmp_path):
    result = run_review(tmp_path, "--repo", str(tmp_path), "--json", "--all")
    assert result.returncode == 2
    assert result.stdout == ""
    assert "review: error:" in result.stderr
