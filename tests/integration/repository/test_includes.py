import pytest

from tests.integration.repository.support import (
    PARTIAL_SCAN,
    VULNERABLE,
    feature_check,
    feature_with_links,
    findings_of,
)
from tests.integration.support import VULNERABLE_PIN, report


@pytest.mark.deep
@pytest.mark.parametrize("include", ["-r base.txt", "--requirement=base.txt", "-c base.txt"])
@pytest.mark.parametrize(("padding", "rule"), [(70000, PARTIAL_SCAN), (0, VULNERABLE)], ids=["long-line", "plain"])
def test_osv_scanner_reads_and_confirms_what_a_requirements_file_includes(target, include, padding, rule):
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    target.write("requirements.txt", f"{include}\n")
    target.write("base.txt", VULNERABLE_PIN + (f"# {'x' * padding}\n" if padding else ""))
    target.commit()
    result = target.check("--base", "main", "--json")
    assert result.returncode == 1, result.stderr
    assert [(item["rule"], item["path"]) for item in report(result)["findings"]] == [(rule, "requirements.txt")]


@pytest.mark.deep
@pytest.mark.parametrize(
    "include",
    ["-r missing.txt", "--requirement=missing.txt", "--requirement ../outside.txt", "-c /outside.txt", "-r https://x.example/r.txt"],
)
def test_a_requirements_include_missing_or_outside_the_tree_is_a_partial_scan(target, include):
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    target.write("requirements.txt", f"{VULNERABLE_PIN}{include}\n")
    target.commit()
    result = target.check("--base", "main", "--json")
    assert result.returncode == 1, result.stderr
    assert findings_of(result, PARTIAL_SCAN) == [("requirements.txt", None)]


@pytest.mark.deep
@pytest.mark.parametrize(
    ("files", "links"),
    [
        ({"requirements.txt": f"{chr(0xFEFF)}-r base.txt\n", "base.txt": VULNERABLE_PIN}, {}),
        ({"requirements.txt": '-r "base.txt"\n', "base.txt": VULNERABLE_PIN}, {}),
        ({"requirements.txt": "-r 'base.txt'\n", "base.txt": VULNERABLE_PIN}, {}),
        ({"requirements.txt": '-r "my pins.txt"\n', "my pins.txt": VULNERABLE_PIN}, {}),
        ({"requirements.txt": "-r pins,v2.txt\n", "pins,v2.txt": VULNERABLE_PIN}, {}),
        ({"requirements.txt": "--requirement=pins,v2.txt\n", "pins,v2.txt": VULNERABLE_PIN}, {}),
        ({"requirements.txt": "-r common.txt\n", "pins/common.txt": VULNERABLE_PIN}, {"common.txt": "pins/common.txt"}),
        ({"requirements.txt": "-r reqs/base.txt\n", "real/base.txt": VULNERABLE_PIN}, {"reqs": "real"}),
        ({"requirements.txt": "-r reqs/base.txt\n", "real/base.txt": "-r pins.txt\n", "real/pins.txt": VULNERABLE_PIN}, {"reqs": "real"}),
    ],
    ids=["bom", "double-quoted", "single-quoted", "quoted-blank", "comma", "comma-equals", "symlink", "directory-symlink", "directory-symlink-nested"],
)
def test_osv_scanner_reads_an_include_as_pip_names_it(target, files, links):
    result = feature_with_links(target, files, links)
    assert result.returncode == 1, result.stderr
    assert [(item["rule"], item["path"]) for item in report(result)["findings"]] == [(VULNERABLE, "requirements.txt")]


@pytest.mark.deep
@pytest.mark.parametrize(
    ("include", "link", "destination"),
    [
        ("common.txt", "common.txt", "../outside.txt"),
        ("common.txt", "common.txt", "pins/missing.txt"),
        ("common.txt", "common.txt", "common.txt"),
        ("reqs/base.txt", "reqs", "../outside"),
        ("reqs/base.txt", "reqs", "missing"),
        ("reqs/base.txt", "reqs", "reqs"),
    ],
    ids=["outside", "dangling", "loop", "directory-outside", "directory-dangling", "directory-loop"],
)
def test_a_symlinked_include_pip_cannot_read_from_the_tree_is_a_partial_scan(target, include, link, destination):
    result = feature_with_links(target, {"requirements.txt": f"{VULNERABLE_PIN}-r {include}\n"}, {link: destination})
    assert result.returncode == 1, result.stderr
    assert findings_of(result, PARTIAL_SCAN) == [("requirements.txt", None)]


LONG_COMMENT = f"# {'x' * 70000}\n"
INCLUDE_CASES = {
    "plain": ({"requirements.txt": "-r base.txt\n", "base.txt": VULNERABLE_PIN}, VULNERABLE),
    "comment_after": ({"requirements.txt": "-r base.txt  # shared pins\n", "base.txt": VULNERABLE_PIN}, VULNERABLE),
    "comment_after_long": ({"requirements.txt": "-r base.txt  # pins\n", "base.txt": VULNERABLE_PIN + LONG_COMMENT}, PARTIAL_SCAN),
    "quoted_long": ({"requirements.txt": '-r "base.txt"\n', "base.txt": VULNERABLE_PIN + LONG_COMMENT}, PARTIAL_SCAN),
    "cycle": ({"requirements.txt": f"-r base.txt\n{VULNERABLE_PIN}", "base.txt": "-r requirements.txt\nflask==2.0.0\n"}, VULNERABLE),
    "cycle_equals": ({"requirements.txt": f"--requirement=base.txt\n{VULNERABLE_PIN}", "base.txt": "--requirement=requirements.txt\n"}, VULNERABLE),
    "self_include": ({"requirements.txt": f"-r requirements.txt\n{VULNERABLE_PIN}"}, VULNERABLE),
    "diamond": ({"requirements.txt": "-r a.txt\n-r b.txt\n", "a.txt": "-r common.txt\n", "b.txt": "-r common.txt\n", "common.txt": VULNERABLE_PIN}, VULNERABLE),
    "environment_variable": ({"requirements.txt": "-r ${PINS}/base.txt\n", "pins/base.txt": VULNERABLE_PIN}, PARTIAL_SCAN),
    "crlf": ({"requirements.txt": "-r base.txt\r\n", "base.txt": VULNERABLE_PIN.replace("\n", "\r\n")}, VULNERABLE),
    "dot_slash": ({"requirements.txt": "-r ./base.txt\n", "base.txt": VULNERABLE_PIN}, VULNERABLE),
    "double_slash": ({"requirements.txt": "-r sub//base.txt\n", "sub/base.txt": VULNERABLE_PIN}, VULNERABLE),
    "tab": ({"requirements.txt": "-r\tbase.txt\n", "base.txt": VULNERABLE_PIN}, VULNERABLE),
    "long_option_blank": ({"requirements.txt": "--requirement base.txt\n", "base.txt": VULNERABLE_PIN}, VULNERABLE),
    "glued": ({"requirements.txt": "-rbase.txt\n", "base.txt": VULNERABLE_PIN}, VULNERABLE),
    "include_is_lockfile": ({"requirements.txt": "-r requirements-base.txt\n", "requirements-base.txt": VULNERABLE_PIN}, VULNERABLE),
    "hash_continuation": ({"requirements.txt": "-r base.txt \\\n    # trailing\n", "base.txt": VULNERABLE_PIN}, VULNERABLE),
    "file_scheme": ({"requirements.txt": "-r file:base.txt\n", "base.txt": VULNERABLE_PIN}, PARTIAL_SCAN),
    "package_then_include": ({"requirements.txt": "flask==2.0.0 -r base.txt\n", "base.txt": "six==1.16.0\n"}, VULNERABLE),
    "index_then_include": ({"requirements.txt": "-i https://pypi.org/simple -r base.txt\n", "base.txt": VULNERABLE_PIN}, VULNERABLE),
    "include_then_index": ({"requirements.txt": "-r base.txt -i https://pypi.org/simple\n", "base.txt": VULNERABLE_PIN}, VULNERABLE),
    "constraint": ({"requirements.txt": "-c constraints.txt\nrequests\n", "constraints.txt": VULNERABLE_PIN}, VULNERABLE),
    "bom_equals": ({"requirements.txt": f"{chr(0xFEFF)}--requirement=base.txt\n", "base.txt": VULNERABLE_PIN}, VULNERABLE),
    "bom_in_include": ({"requirements.txt": "-r base.txt\n", "base.txt": f"{chr(0xFEFF)}-r pins.txt\n", "pins.txt": VULNERABLE_PIN}, VULNERABLE),
    "tab_comment": ({"requirements.txt": "-r base.txt\t# shared\n", "base.txt": VULNERABLE_PIN}, VULNERABLE),
    "trailing_blanks": ({"requirements.txt": "-r base.txt   \n", "base.txt": VULNERABLE_PIN}, VULNERABLE),
    "leading_blanks": ({"requirements.txt": "   -r base.txt\n", "base.txt": VULNERABLE_PIN}, VULNERABLE),
    "double_blank": ({"requirements.txt": "-r  base.txt\n", "base.txt": VULNERABLE_PIN}, VULNERABLE),
    "crlf_comment": ({"requirements.txt": "-r base.txt # pins\r\n", "base.txt": VULNERABLE_PIN}, VULNERABLE),
    "comma_constraint": ({"requirements.txt": "-c pins,v2.txt\nrequests\n", "pins,v2.txt": VULNERABLE_PIN}, VULNERABLE),
    "comma_long": ({"requirements.txt": "--requirement=pins,v2.txt\n", "pins,v2.txt": VULNERABLE_PIN + LONG_COMMENT}, PARTIAL_SCAN),
    "colon": ({"requirements.txt": "--requirement=pins:v2.txt\n", "pins:v2.txt": VULNERABLE_PIN}, VULNERABLE),
    "quoted_long_option": ({"requirements.txt": '--requirement "base.txt"\n', "base.txt": VULNERABLE_PIN}, VULNERABLE),
    "quoted_single_blank": ({"requirements.txt": "-r 'my pins.txt'\n", "my pins.txt": VULNERABLE_PIN}, VULNERABLE),
    "quoted_constraint": ({"requirements.txt": '-c "base.txt"\nrequests\n', "base.txt": VULNERABLE_PIN}, VULNERABLE),
    "quoted_constraint_long_option": ({"requirements.txt": '--constraint "base.txt"\nrequests\n', "base.txt": VULNERABLE_PIN}, VULNERABLE),
    "quoted_url_constraint": ({"requirements.txt": '-c "https://x.example/constraints.txt"\n'}, PARTIAL_SCAN),
    "quoted_equals": ({"requirements.txt": '--requirement="base.txt"\n', "base.txt": VULNERABLE_PIN}, VULNERABLE),
    "quoted_nested": ({"requirements.txt": "-r base.txt\n", "base.txt": '-r "pins.txt"\n', "pins.txt": VULNERABLE_PIN}, VULNERABLE),
    "quoted_missing": ({"requirements.txt": f'{VULNERABLE_PIN}-r "missing.txt"\n'}, PARTIAL_SCAN),
    "comma_nested": ({"requirements.txt": "-r pins,v2.txt\n", "pins,v2.txt": "-r base.txt\n", "base.txt": VULNERABLE_PIN}, VULNERABLE),
}
NESTED_INCLUDE_CASES = {
    "parent_of_subdirectory": ({"sub/requirements.txt": "-r ../base.txt\n", "base.txt": VULNERABLE_PIN}, "sub/requirements.txt"),
    "requirements_directory": ({"requirements.txt": "-r requirements/base.txt\n", "requirements/base.txt": VULNERABLE_PIN}, "requirements.txt"),
    "relative_in_directory": ({"requirements/prod.txt": "-r base.txt\n", "requirements/base.txt": VULNERABLE_PIN}, "requirements/prod.txt"),
    "named_directory": ({"requirements/prod.txt": "-r ../shared/base.txt\n", "shared/base.txt": VULNERABLE_PIN}, "requirements/prod.txt"),
    "comma_in_directory": ({"requirements/a,b.txt": VULNERABLE_PIN}, "requirements/a,b.txt"),
    "comma_in_directory_nested": ({"requirements/a,b.txt": "-r base.txt\n", "requirements/base.txt": VULNERABLE_PIN}, "requirements/a,b.txt"),
}


@pytest.mark.deep
def test_every_include_shape_reads_as_pip_reads_it(target):
    cases = {name: (files, "requirements.txt", rule) for name, (files, rule) in INCLUDE_CASES.items()}
    cases |= {name: (files, including, VULNERABLE) for name, (files, including) in NESTED_INCLUDE_CASES.items()}
    result = feature_check(target, {f"{name}/{path}": text for name, (files, _, _) in cases.items() for path, text in files.items()})
    assert result.returncode == 1, result.stderr
    rules = {}
    for item in report(result)["findings"]:
        rules.setdefault(item["path"], set()).add(item["rule"])
    wrong = {}
    for name, (_files, including, rule) in cases.items():
        found = rules.get(f"{name}/{including}", set())
        if rule not in found or (rule == VULNERABLE and PARTIAL_SCAN in found):
            wrong[name] = found
    assert wrong == {}


@pytest.mark.deep
@pytest.mark.parametrize(
    ("files", "findings"),
    [
        ({"requirements.txt": "-e . -r base.txt\n", "base.txt": VULNERABLE_PIN, "setup.py": ""}, [(VULNERABLE, "requirements.txt")]),
        ({"requirements.txt": "# old pins, see C:\\pins\\\n--requirement=base.txt\n", "base.txt": VULNERABLE_PIN}, []),
        ({"requirements.txt": "# pins, see C:\\pins\\\n-c base.txt\nsix==1.16.0\n", "base.txt": VULNERABLE_PIN}, []),
        ({"requirements.txt": "# shared \\\n-r base.txt\n", "base.txt": VULNERABLE_PIN + LONG_COMMENT}, None),
    ],
    ids=[
        "editable-line-include-over-reported",
        "include-after-comment-continuation-missed",
        "constraint-after-comment-continuation-unread",
        "unreadable-include-after-comment-continuation-exits-2",
    ],
)
def test_named_residuals_of_requirements_includes(target, files, findings):
    result = feature_with_links(target, files, {})
    if findings is None:
        assert result.returncode == 2
        assert "outside this check" in result.stderr
        return
    assert result.returncode == (1 if findings else 0), result.stderr
    assert [(item["rule"], item["path"]) for item in report(result)["findings"]] == findings


@pytest.mark.deep
@pytest.mark.parametrize("include", ["-r base.txt", "--requirement=base.txt", "-c base.txt"])
def test_an_include_pin_the_base_side_held_already_is_no_new_finding(target, include):
    target.write("requirements.txt", f"{include}\nrequests\n")
    target.write("base.txt", VULNERABLE_PIN)
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    target.write("requirements.txt", f"{include}\nrequests\nsix==1.16.0\n")
    target.commit()
    result = target.check("--base", "main", "--json")
    assert result.returncode == 0, result.stderr
    assert report(result)["findings"] == []
