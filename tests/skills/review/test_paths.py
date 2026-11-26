from tests.skills.review.support import finding, module

options = module("options")


def outside(findings: list, paths: tuple) -> list:
    return [item["path"] for item in findings if item["path"] not in paths]


def parsed(*paths: str):
    flags = [flag for path in paths for flag in ("--path", path)]
    return options.parse(["--repo", ".", "--json", "--staged", *flags])


def test_path_limits_findings_to_those_files():
    request = parsed("a.py")
    found = [finding("a.py", 1), finding("b.py", 1), finding("pkg/a.py", 1)]
    kept = [item for item in found if request.covers(item["path"])]
    assert [item["path"] for item in kept] == ["a.py"]
    assert outside(kept, request.paths) == []


def test_negative_control_a_finding_outside_path_fails_the_path_test():
    request = parsed("a.py")
    assert outside([finding("a.py", 1), finding("b.py", 1)], request.paths) == ["b.py"]


def test_without_path_every_file_is_covered():
    request = parsed()
    assert request.paths == ()
    assert all(request.covers(path) for path in ("a.py", "b.py", "pkg/a.py"))
