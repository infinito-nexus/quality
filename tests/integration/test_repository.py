import json
import os
import shutil
import subprocess
import sys
import tempfile
import tomllib
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from quality.db import OSV_DIR, TRIVY_DIR, open_bundle, tree_digest, write_manifest
from tests.integration.support import (
    DEEP_TOOLS,
    LAUNCHER,
    ROOT,
    RULES,
    SECRET_ENV_LINE,
    TEST_DB,
    VULNERABLE_PIN,
    branchy,
    catalogue,
    edit_yaml,
    git,
    path_with,
    pending_tools,
    quality,
    report,
    rules_copy,
    rules_with_enforcers,
    rules_without_pending,
    write_shim,
)
from tests.service.support import load_launcher

VULNERABLE = "security.vulnerable-dependency"
PARTIAL_SCAN = "security.partial-scan"
SECRET_RULE = "security.secret"

SERVICE_PATHS = ("service/web/", "ansible/roles/web-app-cst-quality-check/")


def project() -> dict:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def tracked_files() -> list:
    listing = git(ROOT, "ls-files", "-c", "-z").stdout
    return [name for name in listing.split("\0") if name]


def copy_of_this_repository(destination: Path) -> None:
    for name in tracked_files():
        source = ROOT / name
        if source.is_file():
            target_file = destination / name
            target_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target_file)


@pytest.fixture(scope="module")
def wheel(tmp_path_factory) -> Path:
    work = tmp_path_factory.mktemp("wheel")
    copy = work / "copy"
    copy_of_this_repository(copy)
    for path in SERVICE_PATHS:
        planted = copy / path / "planted.py"
        planted.parent.mkdir(parents=True, exist_ok=True)
        planted.write_text("x = 1\n", encoding="utf-8")
    dist = work / "dist"
    subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--no-isolation", "--outdir", dist, copy],
        check=True,
        capture_output=True,
    )
    return next(dist.glob("kvb_quality-*.whl"))


def test_license_is_mit():
    text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert text.startswith("MIT License")
    assert "Permission is hereby granted, free of charge" in text
    assert project()["project"]["license"] == "MIT"


def test_name_and_script():
    assert project()["project"]["name"] == "kvb-quality"
    assert project()["project"]["scripts"] == {"quality": "quality.cli:main"}


def test_mirrors_list_the_right_project():
    lines = (ROOT / "MIRRORS").read_text(encoding="utf-8").splitlines()
    assert lines[0] == "git@github.com:infinito-nexus/quality.git"
    assert "https://pypi.org/project/kvb-quality/" in lines
    assert "https://pypi.org/project/quality/" not in lines


def test_dependencies_are_only_pyyaml_and_pathspec():
    assert sorted(project()["project"]["dependencies"]) == ["PyYAML", "pathspec"]


def test_package_excludes_service(wheel):
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        entry_points = next(name for name in names if name.endswith("entry_points.txt"))
        assert "quality = quality.cli:main" in archive.read(entry_points).decode()
    assert "quality/cli.py" in names
    assert "quality/rules/tools.yml" in names
    assert "quality/rules/semgrep/javascript.yml" in names
    leaked = [name for name in names if "service" in name or "ansible" in name or "planted" in name]
    assert leaked == []


def test_package_excludes_service_from_image():
    pytest.skip("needs nix: the image is built by phase D, this criterion holds for the wheel only")


@pytest.mark.deep
def test_wheel_runs_from_its_packaged_rules(wheel, target, tmp_path):
    unpacked = tmp_path / "unpacked"
    with zipfile.ZipFile(wheel) as archive:
        archive.extractall(unpacked)
    target.write("a.py", "import os\n")
    target.write("app.js", "new Function(location.hash)();\n")
    target.commit()
    launcher = (
        "import sys\n"
        f"sys.path.insert(0, {str(unpacked)!r})\n"
        "from quality.cli import main\n"
        "sys.exit(main(sys.argv[1:]))\n"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", launcher, "check", "--all", "--db", str(TEST_DB)],
        cwd=target.path,
        env={"PATH": os.environ["PATH"], "TMPDIR": tempfile.gettempdir()},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1, result.stderr
    assert "coding.unused-import" in result.stdout
    assert "security.static-analysis" in result.stdout


@pytest.mark.deep
def test_all_on_this_repository(target):
    pending = pending_tools()
    if pending:
        pytest.skip(f"pending rules need {', '.join(pending)}: phase C adds their adapters")
    copy_of_this_repository(target.path)
    target.commit()
    assert target.check("--all").returncode == 0


@pytest.mark.deep
def test_all_on_this_repository_reports_what_it_cannot_claim(target, tmp_path):
    copy_of_this_repository(target.path)
    target.commit()
    result = target.check("--all", "--json")
    document = report(result)
    pending = sorted(rule["id"] for rule in catalogue() if rule.get("pending"))
    assert document["findings"] == []
    assert [note for note in document["notes"] if note.startswith("parse incomplete:")] == []
    assert result.returncode == (2 if pending else 0)
    assert [entry for entry in document["ignored"] if entry["rule"] == "coding.dockerfile"] == []
    assert {"path": "service/dev/Dockerfile", "line": 2, "rule": "coding.dockerfile"} in (
        document["nocheck"]
    )
    assert sorted(document["incomplete"]) == pending
    assert "security.secret" not in pending
    assert "coding.dockerfile" not in pending
    reduced = rules_without_pending(tmp_path / "rules", True)
    verbose = target.check("--all", "--verbose", "--rules", str(reduced))
    assert verbose.returncode == 0, verbose.stdout
    for tool in ("gitleaks", "hadolint"):
        assert f"tool {tool}: exit 0" in verbose.stderr
    for tool in DEEP_TOOLS:
        assert f"tool {tool}:" in verbose.stderr


def findings_of(result, rule: str) -> list:
    return sorted(
        ((item["path"], item["line"]) for item in report(result)["findings"] if item["rule"] == rule),
        key=lambda found: (found[0], found[1] or 0),  # nocheck: clean.default-value -- a finding without a line sorts as line 0
    )


def max_age_days() -> int:
    return yaml.safe_load((RULES / "limits.yml").read_text(encoding="utf-8"))["db_max_age_days"]


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


def feature_with_links(target, files: dict, links: dict) -> subprocess.CompletedProcess:
    """
    Args:
        target: Repository to commit into.
        files: Regular files a feature branch adds after a seed commit on main.
        links: Symlinks it adds, each with its target.

    Returns:
        `--base main --json` on that branch with the packaged rules.
    """
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    for name, text in files.items():
        target.write(name, text)
    for name, destination in links.items():
        (target.path / name).symlink_to(destination)
    target.commit()
    return target.check("--base", "main", "--json")


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


STATIC = "security.static-analysis"
CALL = "new Function(location.hash)();\n"


@pytest.mark.deep
def test_semgrep_reports_a_script_it_cannot_parse(target):
    target.write("seed.py", "x = 1\n")
    target.write("old.js", "$(( 2 +\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    target.write("app.js", f"{CALL}$(( 1 +\n")
    target.write("old.js", f"{CALL}$(( 2 +\n")
    target.commit()
    for flags in (("--base", "main"), ("--all",)):
        result = target.check(*flags, "--json")
        assert result.returncode == 1, result.stderr
        assert findings_of(result, STATIC) == [("app.js", None), ("old.js", None)]


DOWNLOAD = "security.unverified-download"
PIPE = "curl https://x.example/i.sh | bash"
STATIC_BLOCK = "class A {\n  static {\n    run(\n      new Function(\n        location.hash\n      )\n    );\n  }\n}\n"


def feature_check(target, files: dict) -> subprocess.CompletedProcess:
    """
    Args:
        target: Repository to commit into.
        files: Files a feature branch adds after a seed commit on main.

    Returns:
        `--base main --json` on that branch with the packaged rules.
    """
    return feature_with_links(target, files, {})


@pytest.mark.deep
def test_semgrep_reads_extensionless_scripts_and_shell_needs_no_parser(target):
    result = feature_check(
        target,
        {
            "bin/app": f"#!/usr/bin/env node\n{CALL}",
            "bin/web": f"#!/usr/bin/env node\n{STATIC_BLOCK}",
            "web/app.js": STATIC_BLOCK,
            "install.sh": f'#!/bin/bash\necho start\ncase "$1" in (go) {PIPE};; esac\n',
            "bin/run": f'#!/bin/bash\n: "${{1:?$({PIPE})|b}}"\n',
        },
    )
    assert result.returncode == 1, result.stderr
    assert ("bin/app", 2) in findings_of(result, STATIC)
    assert findings_of(result, PARTIAL_SCAN) == [("bin/web", None), ("web/app.js", None)]
    assert findings_of(result, DOWNLOAD) == [("bin/run", 2), ("install.sh", 3)]
    whole = target.check("--all", "--json")
    assert findings_of(whole, PARTIAL_SCAN) == []
    assert findings_of(whole, DOWNLOAD) == [("bin/run", 2), ("install.sh", 3)]
    unparsed = [note for note in report(whole)["notes"] if note.startswith("parse incomplete: ")]
    assert unparsed == ["parse incomplete: bin/web", "parse incomplete: web/app.js"]


@pytest.mark.deep
def test_an_old_partial_parse_counts_once_its_file_changes(target):
    target.write("web/app.js", STATIC_BLOCK)
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "unrelated")
    target.write("seed.py", "x = 2\n")
    target.commit()
    assert findings_of(target.check("--base", "main", "--json"), PARTIAL_SCAN) == []
    target.git("checkout", "-q", "-b", "feature", "main")
    target.write("web/app.js", f"// changed\n{STATIC_BLOCK}")
    target.commit()
    assert findings_of(target.check("--base", "main", "--json"), PARTIAL_SCAN) == [("web/app.js", None)]


NOCHECK_GAP = f"nocheck: {PARTIAL_SCAN} -- semgrep reads no part of this"


def gap_entry(path: str) -> str:
    return f"- rule: {PARTIAL_SCAN}\n  paths: [{path}]\n  reason: semgrep reads no static block\n"


@pytest.mark.deep
def test_only_a_base_side_entry_naming_the_file_waives_a_partial_scan(target):
    target.write(".qualityignore.yml", gap_entry("web/run.js"))
    nochecked = STATIC_BLOCK.replace("static {", f"static {{ // {NOCHECK_GAP}")
    result = feature_check(target, {"web/run.js": STATIC_BLOCK, "web/app.js": nochecked})
    assert result.returncode == 1, result.stderr
    assert findings_of(result, PARTIAL_SCAN) == [("web/app.js", None)]
    assert report(result)["nocheck"] == []
    assert [item["rule"] for item in report(result)["ignored"]] == [PARTIAL_SCAN]
    whole = report(target.check("--all", "--json"))
    assert [item["rule"] for item in whole["ignored"]] == [PARTIAL_SCAN]
    assert "parse incomplete: web/run.js" not in whole["notes"]


@pytest.mark.deep
def test_a_pull_request_cannot_waive_its_own_partial_scan(target):
    result = feature_check(target, {"web/app.js": STATIC_BLOCK, ".qualityignore.yml": gap_entry("web/app.js")})
    assert result.returncode == 1, result.stderr
    assert findings_of(result, PARTIAL_SCAN) == [("web/app.js", None)]
    assert report(result)["ignored"] == []


@pytest.mark.deep
def test_a_partial_scan_entry_for_a_file_read_whole_is_stale_under_base_and_all(target):
    result = feature_check(target, {"web/clean.js": "run(1);\n", ".qualityignore.yml": gap_entry("web/clean.js")})
    assert result.returncode == 2
    assert "stale .qualityignore.yml entry" in result.stderr
    whole = target.check("--all")
    assert whole.returncode == 2
    assert "stale .qualityignore.yml entry" in whole.stderr
    target.write("web/clean.js", "run(2);\n")
    target.stage()
    assert target.check("--staged").returncode == 0


@pytest.mark.deep
def test_a_renamed_waived_file_needs_its_new_name_on_the_base_side(target):
    target.write("web/app.js", STATIC_BLOCK)
    target.write(".qualityignore.yml", gap_entry("web/app.js"))
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    target.git("mv", "web/app.js", "web/main.js")
    target.write(".qualityignore.yml", gap_entry("web/main.js"))
    target.commit()
    result = target.check("--base", "main", "--json")
    assert result.returncode == 1, result.stderr
    assert findings_of(result, PARTIAL_SCAN) == [("web/main.js", None)]


@pytest.mark.deep
def test_nochecks_around_an_unread_region_waive_nothing(target):
    body = "    run(\n      new Function(\n        location.hash\n      )\n    );\n"
    result = feature_check(
        target,
        {
            "web/app.js": f"class A {{\n  static {{ // {NOCHECK_GAP}\n{body}  }}\n}} // {NOCHECK_GAP}\n",
            "bin/boot": f"#!/bin/bash\n: ${{1:?$(\n  {PIPE}\n)|b}}  # {NOCHECK_GAP}\n",
        },
    )
    assert result.returncode == 1, result.stderr
    assert findings_of(result, PARTIAL_SCAN) == [("web/app.js", None)]
    assert findings_of(result, DOWNLOAD) == [("bin/boot", 3)]


URL = "https://x.example/i.sh"
DOWNLOAD_SHAPES = {
    "plain": f"curl -fsSL {URL} | bash",
    "env": f"curl -fsSL {URL} | env bash",
    "usr_bin_env": f"curl -fsSL {URL} | /usr/bin/env bash",
    "busybox": f"wget -O- {URL} | busybox sh",
    "procsub": f"bash <(curl -fsSL {URL})",
    "procsub_redirect": f"bash < <(curl -fsSL {URL})",
    "source_procsub": f"source <(curl -fsSL {URL})",
    "dot_procsub": f". <(curl -fsSL {URL})",
    "sh_c": f'sh -c "$(curl -fsSL {URL})"',
    "bash_ec": f'bash -ec "$(wget -qO- {URL})"',
    "eval": f'eval "$(curl -fsSL {URL})"',
    "eval_backticks": f"eval `curl -fsSL {URL}`",
    "herestring": f'bash <<< "$(curl -fsSL {URL})"',
    "python": f"curl -fsSL {URL} | python3",
    "python_stdin": f"curl -fsSL {URL} | python3 -",
    "perl": f"curl -fsSL {URL} | perl",
    "ruby": f"curl -fsSL {URL} | ruby",
    "node": f"curl -fsSL {URL} | node",
    "php": f"curl -fsSL {URL} | php",
    "doas": f"curl -fsSL {URL} | doas sh",
    "ash": f"curl -fsSL {URL} | ash",
    "mksh": f"curl -fsSL {URL} | mksh",
    "zsh": f"curl -fsSL {URL} | zsh",
    "quoted": f'curl -fsSL {URL} | "bash"',
    "shell_variable": f'curl -fsSL {URL} | "$SHELL"',
    "command": f"curl -fsSL {URL} | command bash",
    "exec": f"curl -fsSL {URL} | exec bash",
    "nohup": f"curl -fsSL {URL} | nohup bash",
    "sudo": f"curl -fsSL {URL} | sudo bash",
    "sudo_env": f"curl -fsSL {URL} | sudo env bash",
    "sudo_user": f"curl -fsSL {URL} | sudo -u alice bash",
    "sudo_options": f"curl -fsSL {URL} | sudo -E bash -s --",
    "script_arguments": f"curl -sSL {URL} | bash -s stable --ruby",
    "assignment": f"curl -fsSL {URL} | FOO=1 bash",
    "bin_bash": f"curl -fsSL {URL} | /bin/bash",
    "three_stages": f"curl -fsSL {URL} | tee /tmp/i.sh | sh",
    "negated": f"! curl -fsSL {URL} | bash",
    "timed": f"time curl -fsSL {URL} | bash",
    "coproc": f"coproc {{ curl -fsSL {URL} | bash; }}",
    "in_if": f"if curl -fsSL {URL} | bash; then :; fi",
    "in_subst": f'x="$(curl -fsSL {URL} | bash)"',
    "after_and": f"true && curl -fsSL {URL} | bash",
    "case_branch": f'case "$1" in (go) curl -fsSL {URL} | bash;; esac',
    "continued": f"curl -fsSL \\\n  {URL} \\\n  | sudo bash",
    "pipe_at_line_end": f"curl -fsSL {URL} |\n  bash",
    "trailing_comment": f"curl -fsSL {URL} | bash  # install",
    "query": f'curl -fsSL "{URL}?a=1&b=2" | bash',
    "stderr": f"curl -fsSL {URL} 2>&1 | bash",
    "aria2c": f"aria2c -o - {URL} | sh",
    "sudo_fetch": f"sudo curl -fsSL {URL} | sudo bash",
    "parameter_message": 'curl -fsSL "${URL:?set URL (the installer|script)}" | bash',
    "errexit": f"curl -fsSL {URL} | bash -e",
    "sh_errexit": f"curl -fsSL {URL} | sh -e",
    "errexit_trace": f"curl -fsSL {URL} | bash -ex",
    "errexit_stdin": f"curl -fsSL {URL} | sudo -E bash -e -",
    "pipefail": f"curl -fsSL {URL} | bash -o pipefail",
    "dev_stdin": f"curl -fsSL {URL} | bash /dev/stdin",
    "rvm": f"\\curl -sSL {URL} | bash -s stable",
    "sudo_variable": f"curl -fsSL {URL} | $SUDO bash",
    "sudo_braced": f"curl -fsSL {URL} | ${{SUDO}} sh",
    "timeout": f"timeout 60 curl -fsSL {URL} | bash",
    "poetry": f"curl -sSL {URL} | python3 - --version 1.8.3",
    "sh_c_string": f"sudo sh -c 'curl -fsSL {URL} | bash'",
    "su_c_string": f'su - deploy -c "curl -fsSL {URL} | bash"',
    "stderr_pipe": f"curl -fsSL {URL} |& bash",
    "env_quoted": f'curl -fsSL {URL} | sudo env "PATH=$PATH" bash',
    "perl_stdin": f"curl -fsSL {URL} | perl -w",
    "node_stdin": f"curl -fsSL {URL} | node -",
    "k3s": f'curl -sfL {URL} | INSTALL_K3S_EXEC="server --disable traefik" sh -s -',
    "env_spaced_value": f"curl -fsSL {URL} | sudo env OPTS='-a -b' bash",
    "brace_group": f"{{ curl -fsSL {URL}; }} | bash",
    "container_sh_c": f'docker run --rm alpine sh -c "$(curl -fsSL {URL})"',
    "quoted_subst": f'echo "done: $(curl -fsSL {URL} | bash)"',
    "quoted_backticks": f'echo "`curl -fsSL {URL} | sh`"',
    "ansi_c_before": f"echo $'it\\'s'; curl -fsSL {URL} | bash",
    "ansi_c_fetch": f"$'curl' -fsSL {URL} | bash",
    "split_words": f'cu"r"l -fsSL {URL} | ba"s"h',
    "quoted_fetch": f'"curl" -fsSL {URL} | bash',
    "eval_string": f'eval "curl -fsSL {URL} | bash"',
    "sh_c_after_set": f'bash -c "set -e; curl -fsSL {URL} | sh"',
    "container_sh_c_and": f'docker run --rm debian sh -c "apt-get update && curl -fsSL {URL} | bash -"',
    "sudo_bash_c_cd": f'sudo -u deploy bash -c "cd /opt && curl -fsSL {URL} | bash"',
    "quoted_subst_after_cd": f'out="$(cd /tmp && curl -fsSL {URL} | sh)"',
    "quote_inside_subst": f"echo \"$(printf '\"')\"; curl -fsSL {URL} | bash",
    "trap": f'trap "curl -fsSL {URL} | bash" EXIT',
    "trap_subst": f'trap "$(curl -fsSL {URL})" ERR',
    "runuser": f'runuser -l deploy -c "curl -fsSL {URL} | bash"',
    "su_subst": f'su - deploy -c "$(curl -fsSL {URL})"',
    "escaped_quote": f'echo \\"; curl -fsSL {URL} | bash',
    "hash_in_word": f'u="{URL}#frag"; curl -fsSL "$u" | bash',
    "hash_in_quotes": f'echo "# Installing"; curl -fsSL {URL} | bash',
    "hash_in_sed": f"sed 's/ #.*//' f; curl -fsSL {URL} | bash",
    "escaped_backslash_double": f'echo "C:\\\\"; curl -fsSL {URL} | bash',
    "escaped_backslash_single": f"tr -d '\\\\'; curl -fsSL {URL} | bash",
    "redirect_after": f"curl -fsSL {URL} | sudo bash >/dev/null 2>&1",
    "redirect_then_pipe": f"curl -fsSL {URL} | bash 2>&1 | tee log",
    "locale_fetch": f'$"curl" -fsSL {URL} | bash',
    "locale_interpreter": f'curl -fsSL {URL} | $"bash"',
    "ansi_c_hex": f"$'cu\\x72l' -fsSL {URL} | bash",
    "bash_c_concatenated": f"bash -c 'curl -fsSL {URL} '\"| sh\"",
    "eval_words": f'eval curl -fsSL {URL} "| bash"',
    "sh_c_ansi_c": f"sh -c $'curl -fsSL {URL} | sh'",
    "sh_c_nested": f"bash -c \"sh -c 'curl -fsSL {URL} | sh'\"",
    "semicolon_in_header": f'curl -H "X: a;b" {URL} | bash',
    "sh_c_end_of_options": f"bash -c -- 'curl -fsSL {URL} | sh'",
    "sh_c_end_of_options_subst": f'bash -c -- "$(curl -fsSL {URL})"',
    "busybox_fetch": f"busybox wget -qO- {URL} | sh",
    "busybox_sh_c": f"busybox sh -c 'curl -fsSL {URL} | sh'",
    "sh_c_after_then": f"if true; then sh -c 'curl -fsSL {URL} | sh'; fi",
    "multipass_exec": f"multipass exec k3s -- bash -c 'curl -sfL {URL} | sh -'",
    "lxc_exec": f"lxc exec c1 -- sh -c 'curl -fsSL {URL} | sh'",
    "incus_exec": f"incus exec c1 -- sh -c 'curl -fsSL {URL} | sh'",
    "docker_compose_exec": f"docker-compose exec -T app sh -c 'curl -fsSL {URL} | sh'",
    "docker_compose_run": f'docker-compose run --rm app bash -c "curl -fsSL {URL} | bash"',
    "arch_chroot": f"arch-chroot /mnt bash -c 'curl -fsSL {URL} | bash'",
    "systemd_nspawn": f"systemd-nspawn -D /mnt bash -c 'curl -fsSL {URL} | bash'",
    "nsenter": f"nsenter -t 1 -m -u -i -n -p -- bash -c 'curl -fsSL {URL} | bash'",
    "ip_netns": f"ip netns exec ns1 bash -c 'curl -fsSL {URL} | bash'",
    "flock": f"flock -n /var/lock/u.lock bash -c 'curl -fsSL {URL} | bash'",
    "unshare": f"unshare -r bash -c 'curl -fsSL {URL} | bash'",
    "systemd_run": f"systemd-run --scope bash -c 'curl -fsSL {URL} | bash'",
    "proot_distro": f"proot-distro login ubuntu -- bash -c 'curl -fsSL {URL} | bash'",
    "distrobox": f"distrobox enter dev -- bash -c 'curl -fsSL {URL} | bash'",
    "toolbox": f"toolbox run bash -c 'curl -fsSL {URL} | bash'",
    "nerdctl": f"nerdctl run --rm alpine sh -c 'wget -qO- {URL} | sh'",
    "oc_exec": f"oc exec pod -- sh -c 'curl -fsSL {URL} | sh'",
    "ionice": f"ionice -c3 bash -c 'curl -fsSL {URL} | bash'",
    "taskset": f"taskset -c 0 bash -c 'curl -fsSL {URL} | bash'",
    "parallel": f"parallel -j2 bash -c 'curl -fsSL {URL} | bash' ::: a b",
    "wsl": f"wsl bash -c 'curl -fsSL {URL} | bash'",
    "limactl": f"limactl shell default bash -c 'curl -fsSL {URL} | bash'",
    "time_p": f"time -p bash -c 'curl -fsSL {URL} | bash'",
    "coproc_c": f"coproc bash -c 'curl -fsSL {URL} | bash'",
    "bash_c_then_flag": f"bash -c -e 'curl -fsSL {URL} | sh'",
    "bash_c_then_x_subst": f'bash -c -x "$(curl -fsSL {URL})"',
    "bash_pipefail_c": f"bash -o pipefail -c 'curl -fsSL {URL} | bash'",
    "sudo_dashdash": f"sudo -u app -- bash -c 'curl -fsSL {URL} | bash'",
    "sudo_sh_c_dashdash": f"sudo sh -c -- 'curl -fsSL {URL} | sh'",
    "env_i": f"env -i PATH=/usr/bin bash -c 'curl -fsSL {URL} | bash'",
    "exec_bash_c": f"exec bash -c 'curl -fsSL {URL} | bash'",
    "function_body": f"install() {{ bash -c 'curl -fsSL {URL} | bash'; }}",
    "case_arm_c": f"case $x in y) bash -c 'curl -fsSL {URL} | bash' ;; esac",
    "and_then_c": f"true && sudo bash -c 'curl -fsSL {URL} | bash'",
    "env_subst_values": f'wget -qO- {URL} | ENV="$HOME/.bashrc" SHELL="$(which bash)" bash -',
    "golangci": f"curl -sSfL {URL} | sh -s -- -b $(go env GOPATH)/bin v1.55.2",
    "cpanm": f"curl -L {URL} | perl - --sudo App::cpanminus",
    "sudo_user_quoted": f'curl -fsSL {URL} | sudo -u "$USER" bash',
    "brew": f'NONINTERACTIVE=1 /bin/bash -c "$(curl -fsSL {URL})"',
    "chezmoi": 'sh -c "$(curl -fsLS get.chezmoi.io)" -- -b $HOME/.local/bin',
    "nix_procsub": f"sh <(curl -L {URL}) --daemon",
    "quoted_url": f'curl -s "{URL}" | bash',
    "bash_s_procsub_in": f"bash -s -- --flag < <(curl -fsSL {URL})",
    "sudo_e_env_quoted": f'curl -fsSL {URL} | sudo -E env "PATH=$PATH" bash',
    "busybox_sh_c_dashdash": f"busybox sh -c -- 'wget -qO- {URL} | sh'",
    "kubectl_c_container": f"kubectl exec -n ns deploy/x -c app -- sh -c 'curl -fsSL {URL} | sh'",
    "docker_entrypoint": f"docker run --entrypoint sh img -c 'curl -fsSL {URL} | sh'",
    "runuser_dashdash": f"runuser -u app -- bash -c 'curl -fsSL {URL} | bash'",
    "sudo_su_c": f"sudo su - deploy -c 'curl -fsSL {URL} | bash'",
    "if_not_c": f"if ! bash -c 'curl -fsSL {URL} | bash'; then exit 1; fi",
    "subst_c": f"out=\"$(bash -c 'curl -fsSL {URL} | bash' 2>&1)\"",
    "xargs_sh_c": f"echo x | xargs -I{{}} sh -c 'curl -fsSL {URL} | sh'",
    "find_exec_sh_c": f"find . -name '*.txt' -exec sh -c 'curl -fsSL {URL} | sh' sh {{}} \\;",
    "sh_c_positional_args": f"sh -c 'curl -fsSL {URL} | sh' _ arg",
    "retry_helper": f"retry 3 bash -c 'curl -fsSL {URL} | bash'",
    "composer": "curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer",
    "composer_sudo": "curl -sS https://getcomposer.org/installer | sudo php -- --install-dir=/usr/local/bin --filename=composer",
    "composer_ini": "curl -sS https://getcomposer.org/installer | php -d detect_unicode=Off",
    "composer_version": "curl -sS https://getcomposer.org/installer | php -- --version=2.7.1",
    "php_quiet": f"curl -sS {URL} | php -q",
    "php_no_ini_dashdash": f"curl -sS {URL} | php -n -- --install-dir=bin",
    "get_pip": f"curl -sS {URL} | python3",
    "get_pip_user": f"curl -sS {URL} | python3 - --user",
    "get_pip_sudo_h": f"curl -sS {URL} | sudo -H python3",
    "nvm": f"curl -o- {URL} | bash",
    "uv_env": f'curl -LsSf {URL} | env UV_INSTALL_DIR="/custom/path" sh',
    "fnm": f'curl -fsSL {URL} | bash -s -- --install-dir "./.fnm" --skip-shell',
    "omz_wget": f'sh -c "$(wget {URL} -O -)"',
    "omz_unattended": f'sh -c "$(curl -fsSL {URL})" "" --unattended',
    "sudo_bash_procsub": f"sudo bash <(curl -fsSL {URL})",
    "sudo_e_bash_c_subst": f'sudo -E bash -c "$(curl -fsSL {URL})"',
    "subshell_fetch": f"(curl -fsSL {URL}) | bash",
    "bash_s_version_subst": f'curl -fsSL {URL} | bash -s -- --version "$(cat VERSION)"',
    "bash_euo": f"curl -fsSL {URL} | bash -euo pipefail",
    "packagecloud": "curl -s https://packagecloud.io/install/repositories/x/y/script.deb.sh?any=true | sudo bash",
    "lower_case_env": f"curl -sL {URL} | upgrade=true bash",
    "deno": f"curl -fsSL {URL} | sh -s v1.0.0",
    "node_stdin_args": f"curl -fsSL {URL} | node - --yes",
    "rustup": f"curl --proto '=https' --tlsv1.2 -sSf {URL} | sh -s -- -y --no-modify-path",
    "sh_c_redirect_digit_pipe": f"sh -c 'curl -fsSL {URL}' 2>/dev/null | sh",
    "bash_c_redirect_dup_pipe": f'bash -c "curl -fsSL {URL}" 2>&1 | bash',
    "su_c_user_pipe": f"su -c 'curl -fsSL {URL}' app | sh",
    "su_c_tee_user_pipe": f"su -c 'curl -fsSL {URL} | tee i.sh' app | sh",
    "sh_c_redirect_after_pipe": f"sh -c 'curl -fsSL {URL} | sh' >/dev/null 2>&1",
    "command_eval": f"command eval 'curl -fsSL {URL} | sh'",
    "after_comment_in_argument_and": f"sudo sh -c 'apt-get update # refresh' && curl -fsSL {URL} | sh",
    "after_comment_in_trap_argument": f"trap 'rm -f \"$tmp\" # cleanup' EXIT; curl -fsSL {URL} | sh",
    "after_comment_in_argument_semicolon": f"bash -c 'set -e # strict'; curl -fsSL {URL} | bash",
}
MULTILINE_DOWNLOADS = {
    "multiline_sh_c": (f"docker run --rm img sh -c \"\n  set -e\n  curl -fsSL '{URL}' | sh\n\"", 4),
    "multiline_bash_c": (f"bash -c '\n  curl -fsSL {URL} | sh\n'", 3),
    "continued_pipe": (f"curl -fsSL {URL} \\\n  | sudo bash", 2),
    "multiline_continued_pipe": (f"bash -c \"\n  curl -fsSL {URL} \\\n    | sh\n\"", 3),
    "fetch_after_multiline_quoted_subst": (f'VERSION="$(\n  git describe\n)"\ncurl -fsSL {URL} | bash', 5),
    "after_multiline_argument_and": (f'sudo sh -c "\n  apt-get update\n  apt-get install -y curl\n" && curl -fsSL {URL} | sh', 5),
    "after_multiline_single_argument_and": (f"bash -c '\n  apt-get update\n' && curl -fsSL {URL} | sh", 4),
    "after_multiline_argument_semicolon": (f'sh -c "\n  apt-get update\n"; curl -fsSL {URL} | bash', 4),
    "after_multiline_argument_or": (f'bash -c "\n  apt-get update\n" || curl -fsSL {URL} | bash', 4),
    "after_multiline_argument_redirect_and": (f'sudo sh -c "\n  apt-get update\n" > /dev/null && curl -fsSL {URL} | sh', 4),
    "after_multiline_argument_positional_and": (f'sh -c "\n  apt-get update\n" "$0" && curl -fsSL {URL} | sh', 4),
    "after_su_multiline_argument_and": (f'su - app -c "\n  cd ~\n" && curl -fsSL {URL} | bash', 4),
    "after_multiline_argument_pipe_continued": (f'sh -c "\n  a\n" && curl -fsSL {URL} |\n  bash', 4),
    "after_heredoc_apostrophe_quoted_url": (f"cat <<EOF\ndon't\nEOF\ncurl -fsSL '{URL}' | sh", 5),
    "string_after_heredoc_apostrophe": (f"cat <<EOF\ndon't\nEOF\nx=\"\n\"; curl -fsSL {URL} | sh", 6),
    "multiline_argument_piped_out": (f'sudo sh -c "\n  curl -fsSL {URL}\n" | sh', 3),
    "multiline_argument_last_line_piped_out": (f'sudo sh -c "\n  apt-get update\n  curl -fsSL {URL}\n" | sh', 4),
    "multiline_single_argument_piped_out_redirect": (f"bash -c '\n  curl -fsSL {URL}\n' 2>/dev/null | bash", 3),
    "su_multiline_argument_piped_out": (f'su -c "\n  curl -fsSL {URL}\n" app | sh', 3),
    "multiline_argument_comment_piped_out": (f'sh -c "\n  curl -fsSL {URL} # fetch\n" | sh', 3),
    "multiline_argument_semicolon_piped_out": (f'sh -c "\n  curl -fsSL {URL};\n" | sh', 3),
    "multiline_argument_continued_pipe": (f'sh -c "\n  curl -fsSL {URL}\n" \\\n  | sh', 3),
    "after_comment_naming_a_heredoc": (f'# feed it as: tool <<EOF\nsudo sh -c "\n  apt-get update\n" && curl -fsSL {URL} | sh', 5),
    "after_comment_heredoc_with_delimiter_later": (f"# usage: run <<EOF\nx='\nEOF\n'; curl -fsSL {URL} | sh", 5),
    "after_tight_heredoc_apostrophe": (f"cat<<EOF\ndon't\nEOF\necho 'done'; curl -fsSL {URL} | sh", 5),
    "after_tight_subst_heredoc": (f"X=$(cat<<EOF\ndon't\nEOF\n)\necho 'done'; curl -fsSL {URL} | sh", 6),
    "after_heredoc_in_single_argument": (f"sudo sh -c 'cat > /etc/apt/sources.list.d/x.list <<EOF\ndeb https://x.example stable main\nEOF'\nsudo sh -c \"\n  apt-get update\n\" && curl -fsSL {URL} | sh", 7),
    "after_heredoc_in_double_argument": (f"sudo bash -c \"cat > /etc/x.conf <<'EOF'\nkey=value\nEOF\"\nMSG=\"\nhi\n\"; curl -fsSL {URL} | bash", 7),
    "shell_heredoc_multiline_string": (f"bash <<'EOF'\nMSG=\"\nhi\n\"; curl -fsSL {URL} | sh\nEOF", 5),
    "after_heredoc_closed_by_paren": (f"X=$(cat <<EOF\nit's\nEOF)\nsudo sh -c \"\n  apt-get update\n\" && curl -fsSL {URL} | sh", 7),
    "after_unterminated_heredoc": (f'let x=1<<n\nsudo sh -c "\n  apt-get update\n" && curl -fsSL {URL} | sh', 5),
    "after_unterminated_heredoc_in_argument": (f"sudo sh -c 'cat > /etc/x <<EOF\nk=v\nEOF2'\nsudo sh -c \"\n  apt-get update\n\" && curl -fsSL {URL} | sh", 7),
    "after_comment_in_argument_and_heredoc": (f"sudo sh -c 'apt-get update # refresh' && cat <<EOF > /etc/motd\ndon't\nEOF\necho 'done'; curl -fsSL {URL} | sh", 5),
    "after_comment_closed_by_multiline_argument": (f"sudo sh -c '\n  apt-get update # deps' && curl -fsSL {URL} | sh", 3),
    "after_arithmetic_shift_and_heredoc": (f"printf '%d\\n' $(( 1 << n )) > /tmp/x; cat <<EOF\ndon't\nEOF\necho 'done'; curl -fsSL {URL} | sh", 5),
    "after_heredoc_line_opening_with_its_delimiter": (f"cat <<END\nEND) of list\ndon't\nEND\necho 'done'; curl -fsSL {URL} | sh", 6),
    "after_heredoc_with_quoted_blank_delimiter": (f"cat <<'END OF HELP'\ndon't\nEND OF HELP\necho 'done'; curl -fsSL {URL} | sh", 5),
    "after_heredoc_with_bang_delimiter": (f"mail -s report root <<!\nBackup didn't finish.\n!\necho 'done'; curl -fsSL {URL} | sh", 5),
    "multiline_argument_continued_redirect_piped_out": (f'sh -c "\n  curl -fsSL {URL}\n" \\\n  2>/dev/null | sh', 3),
    "su_multiline_argument_continued_user_piped_out": (f'su -c "\n  curl -fsSL {URL}\n" \\\n  app | sh', 3),
}
NAMED_FALSE_POSITIVES = {
    "print_helper": f"log \"running\" bash -c 'curl -fsSL {URL} | sh'",
}
NAMED_MISSES = {
    "vagrant_ssh_c": f"vagrant ssh -c 'curl -fsSL {URL} | bash'",
    "ssh_sudo_bash_c": f"ssh -t host sudo bash -c \"'curl -fsSL {URL} | sh'\"",
    "string_inside_multiline_argument": f"bash -c \"\n  x='\n  '; curl -fsSL {URL} | sh\n\"",
    "multiline_argument_earlier_line_piped_out": f'sh -c "\n  curl -fsSL {URL}\n  echo done\n" | sh',
}
NOT_DOWNLOADS = {
    "echoed_parenthesis": f'echo "Install rustup (curl -sSf {URL} | sh)"',
    "echoed_and": f'echo "Run: apt install curl && curl -fsSL {URL} | bash"',
    "echoed_sh_c": f"echo 'bash -c \"$(curl -fsSL {URL})\"'",
    "echoed_backticks": f"echo 'Run `curl -fsSL {URL} | sh`'",
    "echoed_bang": f'echo "Done! curl -fsSL {URL} | bash"',
    "echoed_pipe": f'echo "Use wget | curl -fsSL {URL} | bash"',
    "echoed_ampersand": f'echo "A & curl -fsSL {URL} | bash"',
    "echoed_after_variable": f'echo "${{bold}}curl -fsSL {URL} | bash"',
    "message_after_subst": f'msg="$(date) curl -fsSL {URL} | bash"',
    "message_concatenated": f'X=foo" curl -fsSL {URL} | bash"',
    "comment_apostrophe": f"# don't run curl -fsSL {URL} | bash",
    "escaped_backticks_in_double": f'echo "Run \\`curl -fsSL {URL} | bash\\`"',
    "sudo_tee": f"curl -fsSL {URL} | sudo tee /etc/apt/keyrings/x.asc >/dev/null",
    "echo_sudo_tee": "echo x | sudo tee /etc/f >/dev/null",
    "sudo_xargs": "find . -print0 | sudo xargs -0 du -s",
    "fetch_sudo_xargs": f"curl -fsSL {URL} | sudo xargs -n1 echo",
    "sudo_psql": "printf 'select 1' | sudo -u postgres psql",
    "fetch_sudo_psql": f"curl -fsSL {URL} | sudo -u postgres psql",
    "local_script": "cat local.sh | bash",
    "echo_grep": "echo x | grep x",
    "fetch_grep": f"curl -fsSL {URL} | grep x",
    "python_module": f"curl -s {URL} | python3 -m json.tool",
    "python_code": f"curl -s {URL} | python3 -c 'import json, sys; print(json.load(sys.stdin))'",
    "python_script": f"curl -s {URL} | python3 parse.py",
    "perl_filter": f"curl -s {URL} | perl -pe 's/a/b/'",
    "node_code": f"curl -s {URL} | node -e 'process.stdin.pipe(process.stdout)'",
    "sudo_sh_c": f"curl -fsSL {URL} | sudo sh -c 'cat > /etc/apt/sources.list.d/x.list'",
    "sh_c_grep": "printf 'a\\n' | sh -c 'grep a'",
    "digest_first": f"curl -fsSL -o i.sh {URL} && sha256sum -c i.sh.sha256 && bash i.sh",
    "fallback": f"curl -fsSL {URL} || bash fallback.sh",
    "echoed": f'echo "Run: curl -fsSL {URL} | bash"',
    "comment": f"# curl -fsSL {URL} | bash",
    "diff_procsub": f"diff <(curl -s {URL}) <(curl -s {URL}.bak)",
    "shasum": f"curl -fsSL {URL} | shasum -a 256",
    "heredoc": "bash <<'EOF'\necho hi\nEOF",
    "cat_heredoc": "cat <<'EOF' | bash\necho hi\nEOF",
    "script_with_procsub": f"python3 script.py <(curl -s {URL})",
    "url_argument": f"echo {URL} | bash",
    "gpg": f"curl -fsSL {URL} | gpg --dearmor | sudo tee /usr/share/keyrings/x.gpg",
    "python_option_script": f"curl -s {URL} | python3 -s parse.py",
    "comment_parenthesis": f"# Install (curl -fsSL {URL} | sh) by hand",
    "bash_code": f"curl -fsSL {URL} | bash -ec 'cat'",
    "bash_script": f"curl -s {URL} | bash parse.sh",
    "bash_end_of_options_script": f"curl -s {URL} | bash -- parse.sh",
    "perl_loop": f"curl -s {URL} | perl -ne 'print'",
    "ruby_code": f"curl -s {URL} | ruby -e 'puts 1'",
    "node_print": f"curl -s {URL} | node -p 'process.version'",
    "php_code": f"curl -s {URL} | php -r 'echo 1;'",
    "variable_tee": f"curl -fsSL {URL} | $SUDO tee /etc/x",
    "timeout_grep": f"timeout 5 curl -fsSL {URL} | grep x",
    "grep_count": "grep -c 'curl x | bash' file",
    "logger_message": f'logger "$(hostname): curl -fsSL {URL} | bash failed"',
    "escaped_backticks": f'msg="Install: \\`curl -fsSL {URL} | sh\\`"',
    "echo_in_sh_c": f"bash -c \"echo 'curl -fsSL {URL} | sh'\"",
    "commit_message": f'git commit -m "fix: curl -fsSL {URL} | bash now verified"',
    "quoted_message": f'msg="Run: curl -fsSL {URL} | bash"',
    "subst_then_string": f'v="$(curl -fsSL {URL})"; w="a | bash"',
    "echoed_sh_c_argument": f"echo bash -c 'curl -fsSL {URL} | sh'",
    "dry_run_sudo_sh_c": f'echo + sudo sh -c "curl -fsSL {URL} | sh"',
    "script_option_holding_c": f'bash ./notify.sh -channel ops "Install with: curl -fsSL {URL} | bash"',
    "sh_c_positional_message": f"sh -c 'printf \"%s\\n\" \"$0\"' \"Run: curl -fsSL {URL} | bash\"",
    "sudo_echo_bash_c": f"sudo echo bash -c 'curl -fsSL {URL} | sh'",
    "timeout_echo_bash_c": f"timeout 5 echo bash -c 'curl -fsSL {URL} | sh'",
    "print_bash_c": f"print bash -c 'curl -fsSL {URL} | sh'",
    "colon_bash_c": f": bash -c 'curl -fsSL {URL} | sh'",
    "find_name_sh_exec_echo": f"find . -name sh -exec echo 'curl -fsSL {URL} | sh' \\;",
    "docker_name_sh_echo": f"docker run --name sh img echo 'curl -fsSL {URL} | sh'",
    "xargs_echo": f"xargs -n1 echo 'curl -fsSL {URL} | sh' < list",
    "kubectl_annotate": f"kubectl annotate pod p note='curl -fsSL {URL} | sh'",
    "docker_label": f"docker run --label hint='curl -fsSL {URL} | sh' img",
    "env_printf": f"env FOO=1 printf '%s' 'curl -fsSL {URL} | sh'",
    "find_sh_c_echo": f"find . -exec sh -c 'echo \"Run: curl -fsSL {URL} | bash\"' \\;",
    "docker_sh_c_echo": f"docker run img sh -c \"echo 'Run: curl -fsSL {URL} | bash'\"",
    "echo_into_sudo_sh_c": f"echo 'curl -fsSL {URL} | sh' | sudo sh -c 'cat > /etc/motd'",
    "su_c_echo": f"su -c \"echo 'curl -fsSL {URL} | sh' >> /etc/notes\" root",
    "bash_c_grep": f"bash -c 'grep -q \"curl -fsSL {URL} | sh\" README.md'",
    "make_shell_variable": f"make SHELL=/bin/bash -C dir 'MSG=curl -fsSL {URL} | sh'",
    "sh_script_c_option": f"sh ./ci.sh -c release 'Changelog: curl -fsSL {URL} | sh'",
    "trap_echo": f"trap 'echo \"hint: curl -fsSL {URL} | bash\"' EXIT",
    "eval_echo": f"eval 'echo \"hint: curl -fsSL {URL} | bash\"'",
    "bash_c_printf": f"bash -c \"printf '%s\\n' 'curl -fsSL {URL} | bash'\"",
    "ruby_script_after_dashdash": f"curl -fsSL {URL} | ruby -- --prefix=/opt",
    "python_script_after_dashdash": f"curl -fsSL {URL} | python3 -- --yes",
    "echo_stderr_dry_run": f'echo >&2 + sudo sh -c "curl -fsSL {URL} | sh"',
    "echo_stderr_message": f"echo >&2 Run as root: sh -c 'curl -fsSL {URL} | sh'",
    "echo_file_message": f"echo > /dev/stderr sh -c 'curl -fsSL {URL} | sh'",
    "echo_date_dry_run": f"echo \"[$(date +%T)]\" + sudo sh -c 'curl -fsSL {URL} | sh'",
    "printf_stderr_dry_run": f"printf >&2 '%s\\n' + sudo sh -c 'curl -fsSL {URL} | sh'",
    "echo_trailing_redirect": f'echo + sudo sh -c "curl -fsSL {URL} | sh" >&2',
    "echo_arithmetic_dry_run": f"echo \"[$((i + 1))/$n]\" + sudo sh -c 'curl -fsSL {URL} | sh'",
    "echo_arithmetic_minutes": f"echo \"[$((SECONDS / 60))m]\" + sudo sh -c \"curl -fsSL {URL} | sh\"",
    "echo_nested_subshell": f"echo \"[$(cd \"$dir\" && (git describe))]\" + sudo sh -c 'curl -fsSL {URL} | sh'",
    "echo_su_user_in_subst": f"echo \"[$(su -c 'id -un' app)]\" + sudo sh -c 'curl -fsSL {URL} | sh'",
    "echo_bash_positional_in_subst": f"echo \"$(bash -c 'echo $0' prog)\" + sudo sh -c 'curl -fsSL {URL} | sh'",
    "after_multiline_code_argument": f'bash -c "\n  apt-get update\n"\necho "Run: apt install curl && curl -fsSL {URL} | bash"',
    "after_multiline_string": f'MSG="\n  hello\n"\necho "Run: apt install curl && curl -fsSL {URL} | bash"',
    "after_multiline_quoted_subst": f'VERSION="$(\n  git describe --tags\n)"\necho "Run: apt install curl && curl -fsSL {URL} | bash"',
    "after_multiline_argument_echo": f'sudo sh -c "\n  apt-get update\n" && echo "Run: apt install curl && curl -fsSL {URL} | bash"',
    "after_multiline_single_argument_echo": f"bash -c '\n  apt-get update\n' && echo 'Run: apt install curl && curl -fsSL {URL} | bash'",
    "multiline_argument_positional_text": f'bash -c "\n  printf %s \\"$0\\"\n" "Run: apt install curl && curl -fsSL {URL} | bash"',
    "multiline_quoted_subst_or_die": f'VERSION="$(\n  git describe --tags\n)" || die "install with: apt install git && curl -fsSL {URL} | sh"',
    "multiline_string_then_echo": f'MSG="\n  hello\n"; echo "Run: apt install curl && curl -fsSL {URL} | bash"',
    "multiline_argument_piped_to_tee": f'sh -c "\n  curl -fsSL {URL}\n" | tee log',
    "multiline_argument_without_fetch_piped": 'sh -c "\n  apt-get update\n" | sh',
    "multiline_argument_continued_or": f'sh -c "\n  curl -fsSL {URL}\n" \\\n  || sh',
    "tight_heredoc_apostrophe_then_echo": f"cat<<EOF\ndon't\nEOF\necho 'Run: curl -fsSL {URL} | sh'",
    "heredoc_in_argument_then_echo": f"sudo bash -c 'cat > /etc/x <<EOF\nk=v\nEOF'\necho 'Run: curl -fsSL {URL} | sh'",
    "heredoc_apostrophe_then_echo": f"cat <<EOF\ndon't\nEOF\necho 'Run: curl -fsSL {URL} | sh'",
    "after_multiline_quoted_subst_far": f'VERSION="$(\n  git describe --tags\n)"\nmain() {{\n  :\n}}\nusage() {{\n  echo "Run: curl -fsSL {URL} | bash"\n}}',
}


def test_a_download_into_an_interpreter_is_found_in_every_shape(target):
    for name, body in {**DOWNLOAD_SHAPES, **NOT_DOWNLOADS, **NAMED_FALSE_POSITIVES, **NAMED_MISSES}.items():
        target.write(f"{name}.sh", f"#!/bin/bash\n{body}\n")
    for name, (body, _row) in MULTILINE_DOWNLOADS.items():
        target.write(f"{name}.sh", f"#!/bin/bash\n{body}\n")
    target.write("adjacent.sh", f"#!/bin/bash\n{PIPE}\ncurl {URL} |\n  sh\n{PIPE}\n")
    target.write("carried.sh", f"#!/bin/bash\nx=\"\n\"; {PIPE}\ny='a\nb'; {PIPE}\nz=\"$(echo '\n')\"; {PIPE}\n")
    target.stage()
    result = target.check("--staged", "--json")
    assert result.returncode == 1, result.stderr
    expected = [(f"{name}.sh", 2) for name in [*DOWNLOAD_SHAPES, *NAMED_FALSE_POSITIVES]]
    expected += [(f"{name}.sh", row) for name, (_body, row) in MULTILINE_DOWNLOADS.items()]
    expected += [("adjacent.sh", row) for row in (2, 3, 5)]
    expected += [("carried.sh", 3), ("carried.sh", 5), ("carried.sh", 7)]
    assert findings_of(result, DOWNLOAD) == sorted(expected)


CLONES = "clean.clones"


@pytest.mark.deep
def test_clone_of_an_untouched_file_is_new(target):
    target.write("a.py", branchy("original", 12))
    target.write("c.py", branchy("old_copy", 12))
    target.commit()
    target.git("checkout", "-q", "-b", "unrelated")
    target.write("seed.py", "x = 1\n")
    target.commit()
    assert findings_of(target.check("--base", "main", "--json"), CLONES) == []
    target.git("checkout", "-q", "-b", "feature", "main")
    target.write("b.py", branchy("copied", 12))
    target.commit()
    found = findings_of(target.check("--base", "main", "--json"), CLONES)
    assert "b.py" in {path for path, _line in found}


@pytest.mark.deep
def test_an_untouched_name_jscpd_cannot_read_never_breaks_an_unrelated_change(target):
    hostile = os.fsdecode(b"caf\xe9.py")
    target.write("seed.py", "x = 1\n")
    target.write(hostile, "z = 3\n")
    target.commit()
    target.git("checkout", "-q", "-b", "unrelated")
    target.write("other.py", "y = 2\n")
    target.commit()
    result = target.check("--base", "main", "--json")
    assert result.returncode == 0, result.stderr
    assert f"unchecked: {hostile}: jscpd cannot read a name that is not UTF-8" in report(result)["notes"]


@pytest.mark.deep
def test_db_missing_exits_2(target, tmp_path):
    target.write("a.py", "x = 1\n")
    target.commit()
    target.write("b.py", "y = 1\n")
    target.stage()
    missing = tmp_path / "no-db"
    empty_cache = {"XDG_CACHE_HOME": str(tmp_path / "empty-cache")}
    for flags in (("--base", "main"), ("--all",)):
        for result in (
            target.check(*flags, "--db", str(missing)),
            target.check(*flags, extra_env=empty_cache),
        ):
            assert result.returncode == 2
            assert "quality db update" in result.stderr
    unset = target.check("--all", extra_env={"XDG_CACHE_HOME": ""})
    assert unset.returncode == 2
    assert "XDG_CACHE_HOME" in unset.stderr
    assert target.check("--staged", "--db", str(missing)).returncode == 0
    assert target.check("--staged", extra_env=empty_cache).returncode == 0


def small_bundle(root: Path, date: datetime) -> str:
    (root / TRIVY_DIR / "db").mkdir(parents=True)
    (root / TRIVY_DIR / "db" / "trivy.db").write_bytes(b"trivy")
    (root / OSV_DIR).mkdir()
    digest = tree_digest(root)
    write_manifest(root, date, digest)
    return digest


@pytest.mark.deep
def test_db_too_old_exits_2(target, tmp_path):
    target.write("a.py", "x = 1\n")
    target.commit()
    limit = timedelta(days=max_age_days())
    now = datetime.now(timezone.utc)
    old = tmp_path / "old"
    small_bundle(old, now - limit - timedelta(minutes=1))
    result = target.check("--base", "main", "--db", str(old))
    assert result.returncode == 2
    assert f"older than {limit.days} days" in result.stderr
    assert "quality db update" in result.stderr
    recent = tmp_path / "recent"
    digest = small_bundle(recent, now - limit + timedelta(minutes=5))
    result = target.check("--base", "main", "--db", str(recent))
    assert result.returncode == 0, result.stderr
    assert digest in result.stdout


@pytest.mark.deep
@pytest.mark.parametrize(
    ("linked", "refusal"),
    [(False, "does not match its digest"), (True, "which is no regular file")],
    ids=["added", "linked"],
)
def test_bundle_content_must_match_its_digest(target, tmp_path, linked, refusal):
    rules = rules_with_enforcers(tmp_path / "rules", VULNERABLE, {"lockfile"})
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    target.write("requirements.txt", VULNERABLE_PIN)
    target.commit()
    tampered = tmp_path / "tampered"
    small_bundle(tampered, datetime.now(timezone.utc))
    clean = tmp_path / "clean"
    clean.mkdir()
    with zipfile.ZipFile(clean / "all.zip", "w") as archive:
        archive.writestr("PYSEC-0000-0.json", '{"id": "PYSEC-0000-0", "affected": []}')
    ecosystems = tampered / OSV_DIR / "osv-scalibr"
    ecosystems.mkdir()
    if linked:
        (ecosystems / "PyPI").symlink_to(clean)
    else:
        shutil.copytree(clean, ecosystems / "PyPI")
    result = target.check("--base", "main", "--rules", str(rules), "--db", str(tampered))
    assert result.returncode == 2
    assert refusal in result.stderr
    assert "quality db update" in result.stderr


@pytest.mark.deep
def test_hosted_scan_command_reads_the_bundle_it_names(target, tmp_path):
    note = open_bundle(TEST_DB, max_age_days(), datetime.now(timezone.utc)).note()
    write_shim(tmp_path / "shims", "quality", 'exec "$PYTHON" -I -B -c "$LAUNCHER" "$@"')
    target.write("a.py", "import os\n")
    target.commit()
    env = {
        "PATH": path_with(tmp_path / "shims"),
        "HOME": str(tmp_path),
        "XDG_CACHE_HOME": str(tmp_path),
        "TMPDIR": tempfile.gettempdir(),
        "PYTHON": sys.executable,
        "LAUNCHER": LAUNCHER,
    }
    argv = [*load_launcher().SCAN_COMMAND, str(target.path), str(TEST_DB)]
    result = subprocess.run(argv, env=env, capture_output=True, text=True, check=False)
    document = report(result)
    assert note in document["notes"]
    assert "coding.unused-import" in {item["rule"] for item in document["findings"]}


def test_db_update_refuses_a_bundle_it_cannot_swap_whole(target, tmp_path):
    mount = tmp_path / "ro" / "db"
    mount.mkdir(parents=True)
    (tmp_path / "ro").chmod(0o555)
    try:
        result = quality(target.path, "db", "update", "--db", str(mount))
    finally:
        (tmp_path / "ro").chmod(0o755)
    assert result.returncode == 2
    assert f"cannot stage the update next to {mount}" in result.stderr
    assert "Traceback" not in result.stderr
    assert list(mount.iterdir()) == []


@pytest.mark.deep
def test_report_names_db(target, tmp_path):
    note = open_bundle(TEST_DB, max_age_days(), datetime.now(timezone.utc)).note()
    target.write("a.py", "x = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    target.write("b.py", "import os\n")
    target.commit()
    reduced = rules_without_pending(tmp_path / "rules", True)
    for flags in (("--base", "main"), ("--all", "--rules", str(reduced))):
        assert note in target.check(*flags).stdout.splitlines()
        assert note in report(target.check(*flags, "--json"))["notes"]
    target.write("c.py", "y = 1\n")
    target.stage()
    assert "vulnerability database" not in target.check("--staged").stdout


def test_hosted_launcher_accepts_the_real_report(target):
    target.write(".qualityignore.yml", "- rule: clean.file-lines\n  paths: [big.py]\n  reason: fixture\n")
    target.write("big.py", "x = 1\n" * 501)
    target.write("a.py", "import os\nimport sys  # nocheck: coding.unused-import -- fixture\n")
    target.write("gap.ts", "interface I<in out T> {\n  f(x: T): T;\n}\n")
    target.commit()
    document = report(target.check("--all", "--json"))
    assert document["findings"] and document["ignored"] and document["nocheck"]
    assert document["parse_incomplete"] == ["gap.ts"]
    assert load_launcher().fits(document, load_launcher().REPORT)
