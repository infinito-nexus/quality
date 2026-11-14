import json
import os
import shutil
from pathlib import Path

import pytest

from tests.integration.repository.support import PARTIAL_SCAN, VULNERABLE, findings_of
from tests.integration.support import (
    SECRET_ENV_LINE,
    TEST_DB,
    VULNERABLE_PIN,
    edit_yaml,
    path_with,
    report,
    rules_copy,
    rules_with_enforcers,
    write_shim,
)

SECRET_RULE = "security.secret"


@pytest.mark.deep
@pytest.mark.parametrize(
    ("enforcer", "tool", "line"),
    [("manifest", "trivy", 1), ("lockfile", "osv-scanner", None)],
    ids=["trivy", "osv-scanner"],
)
def test_vuln_offline(target, tmp_path, enforcer, tool, line):
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    target.write("requirements.txt", VULNERABLE_PIN)
    target.write("service/requirements.txt", "six==1.16.0\n")
    target.commit()
    rules = rules_with_enforcers(tmp_path / "rules", VULNERABLE, {enforcer})
    result = target.check("--base", "main", "--json", "--verbose", "--rules", str(rules))
    assert result.returncode == 1, result.stderr
    assert findings_of(result, VULNERABLE) == [("requirements.txt", line)]
    assert f"tool {tool}:" in result.stderr
    assert not os.access(TEST_DB, os.W_OK)
    other = {"trivy": "osv-scanner", "osv-scanner": "trivy"}[tool]
    assert f"tool {other}:" not in result.stderr


def poetry_lock(*packages: tuple) -> str:
    entries = "".join(
        f'[[package]]\nname = "{name}"\nversion = "{version}"\ndescription = ""\n'
        'optional = false\npython-versions = "*"\nfiles = []\n\n'
        for name, version in packages
    )
    return entries + '[metadata]\nlock-version = "2.0"\npython-versions = "*"\ncontent-hash = "x"\n'


REQUESTS = ("requests", "2.19.0")
URLLIB3 = ("urllib3", "1.24.1")
SIX = ("six", "1.16.0")


@pytest.mark.deep
@pytest.mark.parametrize("enforcer", ["manifest", "lockfile"], ids=["trivy", "osv-scanner"])
def test_swapped_vulnerable_package_is_new(target, tmp_path, enforcer):
    rules = str(rules_with_enforcers(tmp_path / "rules", VULNERABLE, {enforcer}))
    target.write("one/poetry.lock", poetry_lock(REQUESTS))
    target.write("two/poetry.lock", poetry_lock(SIX))
    target.commit()
    target.git("checkout", "-q", "-b", "kept")
    target.write("one/poetry.lock", poetry_lock(REQUESTS, SIX))
    target.commit()
    assert target.check("--base", "main", "--rules", rules).returncode == 0
    target.git("checkout", "-q", "-b", "same-file", "main")
    target.write("one/poetry.lock", poetry_lock(URLLIB3))
    target.commit()
    swapped = target.check("--base", "main", "--json", "--rules", rules)
    assert findings_of(swapped, VULNERABLE) == [("one/poetry.lock", None)]
    target.git("checkout", "-q", "-b", "across-files", "main")
    target.write("one/poetry.lock", poetry_lock(SIX))
    target.write("two/poetry.lock", poetry_lock(URLLIB3))
    target.commit()
    moved = target.check("--base", "main", "--json", "--rules", rules)
    assert findings_of(moved, VULNERABLE) == [("two/poetry.lock", None)]


def go_mod(*modules: tuple) -> str:
    lines = "".join(f"\t{name} {version}\n" for name, version in modules)
    return f"module example.com/m\n\ngo 1.22\n\nrequire (\n{lines})\n"


def composer_lock(*packages: tuple) -> str:
    entries = [{"name": name, "version": version, "type": "library"} for name, version in packages]
    return json.dumps({"packages": entries, "packages-dev": []}) + "\n"


def npm_lock(*packages: tuple) -> str:
    tree = {"": {"name": "x", "version": "1.0.0", "dependencies": dict(packages)}}
    for name, version in packages:
        tree[f"node_modules/{name}"] = {
            "version": version,
            "resolved": f"https://registry.npmjs.org/{name}/-/x-{version}.tgz",
        }
    return json.dumps({"name": "x", "version": "1.0.0", "lockfileVersion": 3, "packages": tree}) + "\n"


def vulnerable_after_change(target, tmp_path: Path, enforcer: str, before: dict, after: dict) -> tuple:
    """
    Args:
        target: Repository to commit into.
        tmp_path: Directory for the reduced rule data.
        enforcer: The one enforcer of the vulnerable-dependency rule that stays.
        before: Files committed on main.
        after: Files a feature branch then changes.

    Returns:
        The paths --base main reports as vulnerable, and the finished process.
    """
    rules = str(rules_with_enforcers(tmp_path / "rules", VULNERABLE, {enforcer}))
    for name, text in before.items():
        target.write(name, text)
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    for name, text in after.items():
        target.write(name, text)
    target.commit()
    result = target.check("--base", "main", "--json", "--rules", rules)
    return {path for path, _line in findings_of(result, VULNERABLE)}, result


GO_TEXT = go_mod(("golang.org/x/text", "v0.3.0"))
GO_CRYPTO = go_mod(("golang.org/x/crypto", "v0.0.0-20190308221718-c2843e01d9a2"))
SWAPS = {
    "go.mod": (GO_TEXT, GO_CRYPTO),
    "composer.lock": (composer_lock(("guzzlehttp/guzzle", "6.5.0")), composer_lock(("symfony/http-kernel", "4.4.0"))),
    "package-lock.json": (npm_lock(("@babel/traverse", "7.22.0")), npm_lock(("@xmldom/xmldom", "0.7.0"))),
    "requirements.txt": ("requests==2.31.0\n", "requests==2.19.0\n"),
    "upgraded/requirements.txt": ("requests==2.19.0\n", "requests==2.25.0\n"),
}


@pytest.mark.deep
@pytest.mark.parametrize("enforcer", ["manifest", "lockfile"], ids=["trivy", "osv-scanner"])
def test_swap_or_downgrade_of_a_vulnerable_package_is_new(target, tmp_path, enforcer):
    before = {name: texts[0] for name, texts in SWAPS.items()}
    after = {name: texts[1] for name, texts in SWAPS.items()}
    paths, result = vulnerable_after_change(target, tmp_path, enforcer, before, after)
    assert result.returncode == 1, result.stderr
    assert paths == set(SWAPS) - {"upgraded/requirements.txt"}


RESPELLED = {
    "requirements.txt": ("requests==2.19.0\nPyYAML==5.3\n", "Requests==2.19.0\npyyaml==5.3\n"),
    "composer.lock": (composer_lock(("guzzlehttp/guzzle", "6.5.0")), composer_lock(("GuzzleHttp/Guzzle", "6.5.0"))),
}


@pytest.mark.deep
@pytest.mark.parametrize("enforcer", ["manifest", "lockfile"], ids=["trivy", "osv-scanner"])
def test_a_package_spelled_another_way_is_not_new(target, tmp_path, enforcer):
    before = {name: texts[0] for name, texts in RESPELLED.items()}
    after = {name: texts[1] for name, texts in RESPELLED.items()}
    paths, result = vulnerable_after_change(target, tmp_path, enforcer, before, after)
    assert result.returncode == 0, result.stdout
    assert paths == set()


PYLOCK = 'lock-version = "1.0"\ncreated-by = "x"\n\n[[packages]]\nname = "requests"\nversion = "2.19.0"\n'


@pytest.mark.deep
@pytest.mark.parametrize(
    ("enforcer", "name", "text"),
    [
        ("lockfile", "npm-shrinkwrap.json", npm_lock(("lodash", "4.17.15"))),
        ("lockfile", "pylock.dev.toml", PYLOCK),
        ("manifest", "pylock.dev.toml", PYLOCK),
    ],
    ids=["osv-scanner-shrinkwrap", "osv-scanner-pylock", "trivy-pylock"],
)
def test_every_lockfile_name_a_tool_parses_is_read(target, tmp_path, enforcer, name, text):
    paths, result = vulnerable_after_change(target, tmp_path, enforcer, {"seed.py": "x = 1\n"}, {name: text})
    assert result.returncode == 1, result.stderr
    assert paths == {name}


@pytest.mark.deep
@pytest.mark.parametrize("enforcer", ["manifest", "lockfile"], ids=["trivy", "osv-scanner"])
def test_a_lockfile_broken_on_the_base_side_counts_every_head_finding_as_new(target, tmp_path, enforcer):
    fixed = {"package-lock.json": npm_lock(("lodash", "4.17.15"))}
    broken = {"package-lock.json": "{ broken\n"}
    paths, result = vulnerable_after_change(target, tmp_path, enforcer, broken, fixed)
    assert result.returncode == 1, result.stderr
    assert paths == {"package-lock.json"}
    assert not [note for note in report(result)["notes"] if note.startswith("base side failed, ")]


OVERSIZED = "security.oversized-code"


@pytest.mark.deep
def test_oversized_lockfile_is_a_hard_finding_while_the_deep_tier_runs(target, tmp_path):
    rules = rules_copy(tmp_path / "rules", True)
    edit_yaml(rules / "limits.yml", lambda document: document.update(blob_max_bytes=128))
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    target.write("package-lock.json", npm_lock(("lodash", "4.17.15")))
    target.stage()
    staged = report(target.check("--staged", "--json", "--rules", str(rules)))
    assert staged["findings"] == []
    assert staged["unchecked"] == ["package-lock.json"]
    target.commit()
    result = target.check("--base", "main", "--json", "--rules", str(rules))
    assert result.returncode == 1, result.stderr
    assert [(item["rule"], item["path"]) for item in report(result)["findings"]] == [
        (OVERSIZED, "package-lock.json")
    ]


@pytest.mark.deep
def test_osv_scanner_reads_every_requirements_file(target, tmp_path):
    rules = rules_with_enforcers(tmp_path / "rules", VULNERABLE, {"lockfile"})
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    names = ["deploy/requirements/prod.txt", "dev-requirements.txt", "requirements-dev.txt"]
    for name in names:
        target.write(name, VULNERABLE_PIN)
    target.commit()
    result = target.check("--base", "main", "--json", "--rules", str(rules))
    assert findings_of(result, VULNERABLE) == [(name, None) for name in names]


@pytest.mark.deep
@pytest.mark.parametrize("name", ["package-lock.json", "Cargo.lock", "poetry.lock", "composer.lock", "npm-shrinkwrap.json"])
def test_a_lockfile_no_scanner_can_parse_is_one_partial_scan_finding(target, name):
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    target.write(name, f"[[package]\n{SECRET_ENV_LINE}")
    target.write("app.env", SECRET_ENV_LINE)
    target.commit()
    result = target.check("--base", "main", "--json")
    assert result.returncode == 1, result.stderr
    assert findings_of(result, PARTIAL_SCAN) == [(name, None)]
    secrets = sorted([("app.env", 1), (name, 2)])
    assert findings_of(result, SECRET_RULE) == secrets
    whole = target.check("--all", "--json")
    assert whole.returncode == 1, whole.stderr
    assert f"parse incomplete: {name}" in report(whole)["notes"]
    assert findings_of(whole, SECRET_RULE) == secrets


@pytest.mark.deep
def test_a_broken_lockfile_next_to_a_vulnerable_one_is_still_a_partial_scan(target):
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    target.write("npm-shrinkwrap.json", chr(0xFEFF) + npm_lock(("lodash", "4.17.4")))
    target.write("requirements-dev.txt", VULNERABLE_PIN)
    target.commit()
    result = target.check("--base", "main", "--json")
    assert result.returncode == 1, result.stderr
    assert findings_of(result, PARTIAL_SCAN) == [("npm-shrinkwrap.json", None)]
    assert findings_of(result, VULNERABLE) == [("requirements-dev.txt", None)]


@pytest.mark.deep
@pytest.mark.parametrize(
    ("printed", "message"),
    [
        ("Error during extraction: (extracting as vulnmatch/osvlocal) unable to fetch OSV database", "outside this check"),
        ("", "confirmed no lockfile and exited 127"),
    ],
    ids=["database-error", "silent"],
)
def test_a_lockfile_scanner_failing_without_naming_a_file_still_stops_the_check(target, tmp_path, printed, message):
    write_shim(tmp_path / "shims", "osv-scanner", f'echo "{printed}" >&2\nexit 127')
    target.write("package-lock.json", '{"name": "x", "lockfileVersion": 3, "packages": {"": {}}}\n')
    target.commit()
    result = target.check("--all", path_value=path_with(tmp_path / "shims"))
    assert result.returncode == 2
    assert message in result.stderr


@pytest.mark.deep
def test_a_lockfile_osv_scanner_does_not_confirm_is_a_partial_scan(target):
    target.write("seed.py", "x = 1\n")
    target.write("test-requirements.txt", VULNERABLE_PIN)
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    target.write("test-requirements.txt", f"# touched\n{VULNERABLE_PIN}")
    target.write("requirements-b.txt", f"{VULNERABLE_PIN}# {'x' * 70000}\n")
    target.commit()
    result = target.check("--base", "main", "--json")
    assert result.returncode == 1, result.stderr
    assert findings_of(result, PARTIAL_SCAN) == [("requirements-b.txt", None)]


@pytest.mark.deep
@pytest.mark.parametrize(
    ("files", "silent"),
    [
        ({"requirements-b.txt": VULNERABLE_PIN}, "requirements-b.txt file and found"),
        ({"requirements-b.txt": "-r base.txt\n", "base.txt": VULNERABLE_PIN}, "base.txt file and found"),
    ],
    ids=["its-own-line", "its-include-line"],
)
def test_a_lockfile_osv_scanner_neither_confirms_nor_names_is_a_partial_scan(target, tmp_path, files, silent):
    shims = tmp_path / "shims"
    real = shutil.which("osv-scanner")
    write_shim(shims, "osv-scanner", f'log=$(mktemp)\n"{real}" "$@" 2>"$log"\ncode=$?\ngrep -v "{silent}" "$log" >&2\nrm -f "$log"\nexit $code')
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    target.write("requirements-a.txt", VULNERABLE_PIN)
    for name, text in files.items():
        target.write(name, text)
    target.commit()
    result = target.check("--base", "main", "--json", path_value=path_with(shims))
    assert result.returncode == 1, result.stderr
    assert findings_of(result, PARTIAL_SCAN) == [("requirements-b.txt", None)]
    assert findings_of(result, VULNERABLE) == [("requirements-a.txt", None)]
