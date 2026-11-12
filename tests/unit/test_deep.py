import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

from quality import QualityError
from quality.adapters import bind_files, jscpd, once_per_gap, osvscanner, semgrep, trivy
from quality.adapters.base import Bound, Command, Skipped
from quality.db import Bundle
from quality.gate import baseline_of, code_hit, new_hits, package_hit, package_name
from quality.modes import ALL_TIERS, Session
from quality.process import Completed
from quality.ruledata import load, rule_bindings
from quality.snapshot import Snapshot

RULES = Path(__file__).resolve().parents[2] / "rules"
DATA = load(RULES)
VULNERABLE = "security.vulnerable-dependency"
STATIC = "security.static-analysis"
PARTIAL_SCAN = "security.partial-scan"


def binding(rule_id: str, tool: str):
    rule = next(rule for rule in DATA.rules if rule.id == rule_id)
    return next(item for item in rule_bindings(rule, DATA.kinds) if item.tool == tool)


def bound_of(rule_id: str, tool: str, kinds: dict) -> Bound:
    """
    Args:
        rule_id: Catalogue rule.
        tool: Tool the rule is bound to.
        kinds: Path to its kind, or to "" for a lockfile that has none.

    Returns:
        The rule bound to those files.
    """
    files = list(kinds)
    return Bound(binding(rule_id, tool), files, {path: frozenset({kinds[path]} - {""}) for path in files})


def snapshot_of(root: Path, files: dict) -> Snapshot:
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text, encoding="utf-8")
    return Snapshot(root, dict.fromkeys(files), [], set(), DATA.kinds, set(), {})


def resources(tmp_path: Path, bundle) -> dict:
    empty_json = tmp_path / "empty.json"
    empty_json.write_text("{}\n", encoding="utf-8")
    return {"rules_dir": RULES, "database": bundle, "work_dir": tmp_path, "empty_json": empty_json}


def test_semgrep_reads_scripts_but_never_shell_without_metrics(tmp_path):
    for rule_id in (STATIC, PARTIAL_SCAN):
        assert "shell" not in binding(rule_id, "semgrep").kinds
    kinds = {"b.js": "javascript", "a.js": "javascript", "bin/boot": "shell", "c.ts": "typescript"}
    bound = [bound_of(STATIC, "semgrep", kinds)]
    settings = {**DATA.tool("semgrep"), **resources(tmp_path, None)}
    (script,) = semgrep.commands(bound, settings, tmp_path / "empty.yaml")
    assert script.prefix[script.prefix.index("--config") + 1] == str(RULES / "semgrep" / "javascript.yml")
    assert script.files == ["a.js", "b.js", "c.ts"]
    assert script.prefix.count("--config") == 1
    assert {"--metrics=off", "--disable-version-check", "--disable-nosem"} <= set(script.prefix)
    assert "--scan-unknown-extensions" in script.prefix
    hostile = [bound_of(STATIC, "semgrep", {os.fsdecode(b"caf\xe9.js"): "javascript"})]
    with pytest.raises(QualityError, match="not UTF-8"):
        semgrep.commands(hostile, settings, tmp_path / "empty.yaml")


def test_the_secret_scanner_binds_every_file_by_kind_alone():
    kinds = {"a.py": frozenset({"python"}), "notes.txt": frozenset()}
    bound = bind_files(DATA.bindings()["gitleaks"], kinds, lambda _rule: True)
    assert [item.files for item in bound] == [["a.py", "notes.txt"]]


def test_only_files_patterns_mark_a_file_as_read_by_name():
    session = Session(DATA, None, None, None, ALL_TIERS, None, [])
    assert session.read_by_name("poetry.lock")
    assert not session.read_by_name("notes.txt")
    assert not session.read_by_name("bin/tool")


def gap(path: str, *rows: int) -> dict:
    locations = [{"path": path, "start": {"line": row}, "end": {"line": row}} for row in rows]
    return {"type": ["PartialParsing", locations], "path": path}


def test_semgrep_finds_unparsed_partly_read_and_unscanned_files(tmp_path):
    files = {"a.js": "new Function(x);\n", "b.js": "$((\n", "c.js": "v\nw\nx\ny\nz\n", "bin/app": "x\n"}
    snapshot = snapshot_of(tmp_path, files)
    kinds = dict.fromkeys(files, "javascript")
    bound = [bound_of(PARTIAL_SCAN, "semgrep", kinds), bound_of(STATIC, "semgrep", kinds)]
    command = Command([], list(kinds), bound)
    result = {"check_id": "r", "path": "a.js", "start": {"line": 1}}
    errors = [{"type": "Syntax error", "path": "b.js"}, gap("c.js", 2), gap("c.js", 5)]
    document = {"results": [result], "errors": errors, "paths": {"scanned": ["a.js", "b.js", "c.js"]}}
    found = semgrep.parse(json.dumps(document).encode(), command, snapshot)
    assert [(hit.rule.id, hit.path, hit.line, hit.absolute) for hit in found] == [
        (STATIC, "a.js", 1, False),
        (STATIC, "b.js", None, True),
        (PARTIAL_SCAN, "bin/app", None, False),
        (PARTIAL_SCAN, "c.js", None, False),
    ]
    unbound = Command([], list(kinds), bound[1:])
    with pytest.raises(QualityError, match="could not read all of bin/app"):
        semgrep.parse(json.dumps(document).encode(), unbound, snapshot)
    timeout = {"results": [], "errors": [{"type": "Timeout"}], "paths": {"scanned": []}}
    with pytest.raises(QualityError, match="semgrep"):
        semgrep.parse(json.dumps(timeout).encode(), command, snapshot)


def test_trivy_one_offline_command_per_lockfile(tmp_path):
    bundle = Bundle(tmp_path / "db", datetime.now(timezone.utc), "sha256:x", None)
    bound = [bound_of(VULNERABLE, "trivy", {"b/requirements.txt": "", "requirements.txt": ""})]
    settings = {**DATA.tool("trivy"), **resources(tmp_path, bundle)}
    commands = trivy.commands(bound, settings, tmp_path / "empty.yaml")
    assert [command.files for command in commands] == [["b/requirements.txt"], ["requirements.txt"]]
    prefix = commands[0].prefix
    assert prefix[prefix.index("--cache-dir") + 1] == str(tmp_path / "db" / "trivy")
    assert {"--skip-db-update", "--skip-java-db-update", "--offline-scan"} <= set(prefix)
    assert prefix[prefix.index("--cache-backend") + 1] == "memory"
    with pytest.raises(QualityError, match="quality db update"):
        trivy.commands(bound, {**settings, "database": None}, tmp_path / "empty.yaml")


def vulnerability(uid: str, name: str, vulnerability_id: str) -> dict:
    purl = f"pkg:golang/{name}@v0" if "/" in name else f"pkg:pypi/{name.lower()}@1"
    return {"PkgIdentifier": {"UID": uid, "PURL": purl}, "PkgName": name, "VulnerabilityID": vulnerability_id}


def test_trivy_reports_each_vulnerable_package_once_with_its_ids(tmp_path):
    snapshot = snapshot_of(tmp_path, {"go.mod": "module m\n"})
    bound = [bound_of(VULNERABLE, "trivy", {"go.mod": ""})]
    command = Command([], ["go.mod"], bound)
    report = {
        "Results": [
            {
                "Packages": [
                    {"Identifier": {"UID": "t"}, "Locations": [{"StartLine": 2}]},
                    {"Identifier": {"UID": "c"}},
                ],
                "Vulnerabilities": [
                    vulnerability("t", "golang.org/x/text", "CVE-2"),
                    vulnerability("t", "golang.org/x/text", "CVE-1"),
                    vulnerability("c", "golang.org/x/crypto", "CVE-3"),
                    vulnerability("y", "PyYAML", "CVE-4"),
                    vulnerability("x", "github.com/BurntSushi/toml", "CVE-5"),
                ],
            }
        ]
    }
    hits = trivy.parse(json.dumps(report).encode(), command, snapshot)
    assert [(hit.path, hit.line, hit.entity, hit.ids) for hit in hits] == [
        ("go.mod", None, "golang.org/x/crypto", {"CVE-3"}),
        ("go.mod", 2, "golang.org/x/text", {"CVE-1", "CVE-2"}),
        ("go.mod", None, "github.com/BurntSushi/toml", {"CVE-5"}),
        ("go.mod", None, "pyyaml", {"CVE-4"}),
    ]
    assert trivy.parse(b'{"Results": null}', command, snapshot) == []


def test_osv_scanner_maps_absolute_sources_and_skips_clean_packages(tmp_path):
    snapshot = snapshot_of(tmp_path, {"sub/poetry.lock": "x\n"})
    bound = [bound_of(VULNERABLE, "osv-scanner", {"sub/poetry.lock": ""})]
    [command] = osvscanner.commands(bound, {}, tmp_path / "empty.yaml")
    assert {"--offline", "--offline-vulnerabilities", "--no-resolve"} <= set(command.prefix)
    scoped = {"package": {"name": "@Babel/traverse", "ecosystem": "npm"}, "vulnerabilities": [{"id": "X"}, {"id": "Y"}]}
    clean = {"package": {"name": "six", "ecosystem": "PyPI"}, "vulnerabilities": []}
    pypi = {"package": {"name": "Zope.Interface", "ecosystem": "PyPI"}, "vulnerabilities": [{"id": "Z"}]}
    source = {"path": str(tmp_path / "sub" / "poetry.lock")}
    report = {
        "results": [
            {"source": source, "packages": [scoped, clean, pypi]},
            {"source": source, "packages": [scoped]},
        ]
    }
    hits = osvscanner.parse(json.dumps(report).encode(), command, snapshot)
    assert [(hit.path, hit.line, hit.entity, hit.ids) for hit in hits] == [
        ("sub/poetry.lock", None, "@Babel/traverse", {"X", "Y"}),
        ("sub/poetry.lock", None, "zope-interface", {"Z"}),
    ]


def test_pypi_and_composer_names_compare_as_their_registry_resolves_them():
    assert package_name("PyPI", "Zope.Interface__x") == "zope-interface-x"
    assert package_name("pypi", "PyYAML") == "pyyaml"
    assert package_name("composer", "GuzzleHttp/Guzzle") == "guzzlehttp/guzzle"
    assert package_name("Packagist", "GuzzleHttp/Guzzle") == "guzzlehttp/guzzle"
    assert package_name("npm", "JSONStream") == "JSONStream"
    assert package_name("golang", "github.com/BurntSushi/toml") == "github.com/BurntSushi/toml"
    assert package_name("", "Requests") == "Requests"


def test_osv_scanner_is_told_how_to_parse_a_requirements_directory(tmp_path):
    kinds = {"requirements/base.txt": "", "dev-requirements.txt": "", "poetry.lock": ""}
    snapshot = snapshot_of(tmp_path, dict.fromkeys(kinds, "x==1\n"))
    named, forced = osvscanner.commands([bound_of(VULNERABLE, "osv-scanner", kinds)], {}, tmp_path / "x")
    assert named.files == ["dev-requirements.txt", "poetry.lock"]
    assert forced.files == ["requirements/base.txt"]
    base = f"{tmp_path}/requirements/base.txt"
    assert osvscanner.operands(forced, snapshot, None) == [f"--lockfile=requirements.txt:{base}", "--", base]
    assert osvscanner.operands(named, snapshot, None) == ["--", f"{tmp_path}/dev-requirements.txt", f"{tmp_path}/poetry.lock"]


INCLUDING = {
    "requirements.txt": "-r base.txt\n--requirement=sub/pins.txt  # pins\n-c ../outside.txt\n-rmissing.txt\n",
    "base.txt": "-r requirements.txt\n--constraint lock.txt \\\n  # continued\n",
    "sub/pins.txt": 'x==1\n--requirement "../a\\"b.txt"\n',
    'a"b.txt': "y==1\n",
    "lock.txt": "z==1\n# -r never.txt\n",
    "dev-requirements.txt": "-r requirements.txt\n",
    "poetry.lock": "x\n",
}


def including_command(tmp_path: Path):
    snapshot = snapshot_of(tmp_path, INCLUDING)
    kinds = dict.fromkeys(["dev-requirements.txt", "poetry.lock", "requirements.txt"], "")
    [command] = osvscanner.commands([bound_of(VULNERABLE, "osv-scanner", kinds)], {}, tmp_path / "x")
    return command, snapshot


def test_osv_scanner_must_confirm_every_file_a_requirements_file_includes(tmp_path):
    command, snapshot = including_command(tmp_path)
    flags = [f"--lockfile=requirements.txt:{tmp_path}/{name}" for name in ('a"b.txt', "base.txt", "lock.txt", "sub/pins.txt")]
    assert osvscanner.operands(command, snapshot, None)[:5] == [*flags, "--"]
    present = ["a\"b.txt", "base.txt", "lock.txt", "sub/pins.txt", *command.files]
    confirmed = "".join(scanned_line(f"{tmp_path}/{name}", 1) for name in present)
    assert osvscanner.unparsed(Completed(1, b"", confirmed.encode()), command, {}, snapshot) == [
        "dev-requirements.txt",
        "requirements.txt",
    ]
    clean = Command([], ["poetry.lock"], command.bound)
    assert osvscanner.unparsed(Completed(1, b"", confirmed.encode()), clean, {}, snapshot) == []


@pytest.mark.parametrize(
    ("printed", "gaps"),
    [
        ('openAndExtractFromFile("{root}/a\\"b.txt"): bufio.Scanner: token too long', ["requirements.txt"]),
        ("Error during extraction: (extracting as python/requirements) {root}/lock.txt: x", ["requirements.txt"]),
        ("", []),
    ],
    ids=["opened-quoted", "extraction", "confirmed"],
)
def test_osv_scanner_names_the_including_file_of_an_include_it_could_not_read(tmp_path, printed, gaps):
    files = {key: value for key, value in INCLUDING.items() if key in ("base.txt", "lock.txt", "sub/pins.txt", 'a"b.txt')}
    files["requirements.txt"] = "-r base.txt\n--requirement=sub/pins.txt\n"
    snapshot = snapshot_of(tmp_path, files)
    command = Command([], ["requirements.txt"], [])
    confirmed = "".join(scanned_line(f"{tmp_path}/{name}", 1) for name in files)
    stderr = confirmed + printed.format(root=str(tmp_path).removeprefix("/")) + "\n"
    assert osvscanner.unparsed(Completed(127, b"", stderr.encode()), command, {}, snapshot) == gaps


def linked_snapshot(root: Path, files: dict, links: dict) -> Snapshot:
    """
    Args:
        root: Directory to write the snapshot into.
        files: Regular files and their text.
        links: Symlinks and their target, written as the target text, as materialize() does.

    Returns:
        The snapshot holding both.
    """
    snapshot_of(root, {**files, **links})
    return Snapshot(root, dict.fromkeys([*files, *links]), [], set(), DATA.kinds, set(links), {})


def requirements_command(snapshot: Snapshot) -> Command:
    [command] = osvscanner.commands([bound_of(VULNERABLE, "osv-scanner", {"requirements.txt": ""})], {}, snapshot.root / "x")
    return command


def passed_includes(tmp_path, files: dict, links: dict, passed: list) -> tuple:
    """
    Args:
        tmp_path: Root of the snapshot.
        files: Its regular files.
        links: Its symlinks, each with its target.
        passed: The includes osv-scanner must get as lockfiles, relative to the root.

    Returns:
        The snapshot, its requirements command and the lines confirming every
        file passed, once the command is asserted to pass exactly those.
    """
    snapshot = linked_snapshot(tmp_path, files, links)
    command = requirements_command(snapshot)
    paths = [f"{tmp_path}/{path}" for path in passed]
    assert osvscanner.operands(command, snapshot, None) == [*(f"--lockfile=requirements.txt:{path}" for path in paths), "--", f"{tmp_path}/requirements.txt"]
    return snapshot, command, "".join(scanned_line(path, 1) for path in [*paths, f"{tmp_path}/requirements.txt"])


def test_osv_scanner_passes_an_include_behind_a_bom_a_quote_or_a_symlink(tmp_path):
    files = {"requirements.txt": f"{chr(0xFEFF)}-r 'my pins.txt'\n-r common.txt\n", "my pins.txt": "x==1\n", "pins/common.txt": "y==1\n"}
    snapshot, command, confirmed = passed_includes(tmp_path, files, {"common.txt": "pins/common.txt"}, ["my pins.txt", "pins/common.txt"])
    literal = f"openAndExtractFromFile(\"{tmp_path.relative_to('/')}/'my pins.txt'\"): open: no such file or directory\n"
    assert osvscanner.unparsed(Completed(1, b"", (confirmed + literal).encode()), command, {}, snapshot) == []
    other = literal.replace("'my pins.txt'", "other.txt")
    with pytest.raises(QualityError, match="outside this check"):
        osvscanner.unparsed(Completed(1, b"", (confirmed + other).encode()), command, {}, snapshot)


def test_osv_scanner_passes_an_include_behind_a_directory_symlink(tmp_path):
    files = {"requirements.txt": "-r reqs/base.txt\n", "real/base.txt": "-r pins.txt\n", "real/pins.txt": "x==1\n"}
    snapshot, command, confirmed = passed_includes(tmp_path, files, {"reqs": "real"}, ["real/base.txt", "real/pins.txt"])
    own = f"openAndExtractFromFile(\"{tmp_path.relative_to('/')}/reqs/base.txt\"): open: not a directory\n"
    assert osvscanner.unparsed(Completed(1, b"", (confirmed + own).encode()), command, {}, snapshot) == []


@pytest.mark.parametrize(
    ("include", "link", "target"),
    [
        ("common.txt", "common.txt", "../outside.txt"),
        ("common.txt", "common.txt", "/etc/hostname"),
        ("common.txt", "common.txt", "pins/missing.txt"),
        ("common.txt", "common.txt", "common.txt"),
        ("reqs/base.txt", "reqs", "../outside"),
        ("reqs/base.txt", "reqs", "reqs"),
    ],
    ids=["outside", "absolute", "dangling", "loop", "directory-outside", "directory-loop"],
)
def test_a_symlinked_include_outside_the_root_dangling_or_looping_is_the_gap(tmp_path, include, link, target):
    snapshot = linked_snapshot(tmp_path, {"requirements.txt": f"x==1\n-r {include}\n"}, {link: target})
    command = requirements_command(snapshot)
    assert osvscanner.operands(command, snapshot, None) == ["--", f"{tmp_path}/requirements.txt"]
    confirmed = scanned_line(f"{tmp_path}/requirements.txt", 1) + scanned_line(f"{tmp_path}/{include}", 0)
    assert osvscanner.unparsed(Completed(1, b"", confirmed.encode()), command, {}, snapshot) == ["requirements.txt"]


def test_osv_scanner_counts_nothing_for_its_own_open_beside_a_copy(tmp_path):
    files = {"requirements.txt": "-r pins,v2.txt\n", "pins,v2.txt": "-r base.txt\n", "base.txt": "x==1\n"}
    snapshot = snapshot_of(tmp_path / "snap", files)
    command = requirements_command(snapshot)
    copy = osvscanner.staged(snapshot, "pins,v2.txt")
    confirmed = "".join(scanned_line(path, 1) for path in [str(copy), f"{tmp_path}/snap/base.txt", f"{tmp_path}/snap/requirements.txt"])
    beside = f"openAndExtractFromFile(\"{copy.parent.relative_to('/')}/base.txt\"): open: no such file or directory\n"
    assert osvscanner.unparsed(Completed(1, b"", (confirmed + beside).encode()), command, {}, snapshot) == []
    other = beside.replace("/base.txt", "/other.txt")
    with pytest.raises(QualityError, match="outside this check"):
        osvscanner.unparsed(Completed(1, b"", (confirmed + other).encode()), command, {}, snapshot)


def test_osv_scanner_reads_an_include_whose_name_holds_a_comma_from_a_copy(tmp_path):
    snapshot = snapshot_of(tmp_path / "snap", {"requirements.txt": "--requirement=pins,v2.txt\n", "pins,v2.txt": "x==1\n"})
    command = requirements_command(snapshot)
    flag, *rest = osvscanner.operands(command, snapshot, None)
    copy = Path(flag.removeprefix("--lockfile=requirements.txt:"))
    assert "," not in flag
    assert copy.parent == tmp_path / "snap.osv"
    assert copy.read_bytes() == b"x==1\n"
    assert rest == ["--", f"{tmp_path}/snap/requirements.txt"]
    confirmed = scanned_line(str(copy), 1) + scanned_line(f"{tmp_path}/snap/requirements.txt", 0)
    assert osvscanner.unparsed(Completed(1, b"", confirmed.encode()), command, {}, snapshot) == []
    unconfirmed = scanned_line(f"{tmp_path}/snap/requirements.txt", 0)
    assert osvscanner.unparsed(Completed(1, b"", unconfirmed.encode()), command, {}, snapshot) == ["requirements.txt"]
    found = {"package": {"name": "x", "ecosystem": "PyPI"}, "vulnerabilities": [{"id": "X"}]}
    report = {"results": [{"source": {"path": str(copy)}, "packages": [found]}]}
    assert [(hit.path, hit.entity) for hit in osvscanner.parse(json.dumps(report).encode(), command, snapshot)] == [("requirements.txt", "x")]


def test_osv_scanner_counts_a_package_of_an_include_for_every_file_including_it(tmp_path):
    command, snapshot = including_command(tmp_path)
    found = {"package": {"name": "requests", "ecosystem": "PyPI"}, "vulnerabilities": [{"id": "X"}]}
    report = {"results": [{"source": {"path": f"{tmp_path}/sub/pins.txt"}, "packages": [found]}]}
    hits = osvscanner.parse(json.dumps(report).encode(), command, snapshot)
    assert [(hit.path, hit.entity, hit.ids) for hit in hits] == [
        ("dev-requirements.txt", "requests", {"X"}),
        ("requirements.txt", "requests", {"X"}),
    ]


def extraction_error(path: str, tail: str) -> str:
    return f"Error during extraction: (extracting as javascript/packagelockjson) {path}: {tail}\n"


def scanned_line(path: str, count: int) -> str:
    return f"Scanned {path} file and found {count} package{'' if count == 1 else 's'}\n"


def test_osv_scanner_names_every_lockfile_it_did_not_confirm(tmp_path):
    files = {"a/package-lock.json": "x\n", "package-lock.json": "{}\n", "poetry.lock": "x\n", "b/requirements.txt": "#\n"}
    snapshot = snapshot_of(tmp_path, files)
    command = Command([], list(files), [])
    confirmed = scanned_line(f"{tmp_path}/package-lock.json", 1) + scanned_line(f"{tmp_path}/b/requirements.txt", 0)
    extraction = extraction_error(f"{tmp_path}/a/package-lock.json".removeprefix("/"), "could not extract: x")
    too_long = extraction_error(f"{tmp_path}/poetry.lock".removeprefix("/"), "bufio.Scanner: token too long")
    forged = scanned_line(f"/elsewhere/{tmp_path}/poetry.lock", 1) + scanned_line("poetry.lock", 1)
    for code in (127, 1, 0):
        failed = Completed(code, b"", (confirmed + extraction + too_long + forged).encode())
        assert osvscanner.unparsed(failed, command, {}, snapshot) == ["a/package-lock.json", "poetry.lock"]
        silent = Completed(code, b"", (confirmed + forged).encode())
        assert osvscanner.unparsed(silent, command, {}, snapshot) == ["a/package-lock.json", "poetry.lock"]
    both = scanned_line(f"{tmp_path}/a/package-lock.json", 1) + scanned_line(f"{tmp_path}/poetry.lock", 2)
    assert osvscanner.unparsed(Completed(1, b"", (confirmed + both).encode()), command, {}, snapshot) == []
    confirmed_but_cut = Completed(1, b"", (confirmed + both + too_long).encode())
    assert osvscanner.unparsed(confirmed_but_cut, command, {}, snapshot) == ["poetry.lock"]


def test_osv_scanner_names_every_file_of_a_joined_extraction_error(tmp_path):
    files = {"a/requirements.txt": "x\n", "poetry.lock": "x\n", "package-lock.json": "{}\n"}
    snapshot = snapshot_of(tmp_path, files)
    command = Command([], list(files), [])
    confirmed = "".join(scanned_line(f"{tmp_path}/{name}", 1) for name in files)
    root = str(tmp_path).removeprefix("/")
    joined = "".join(f"\t{root}/{name}: bufio.Scanner: token too long\n" for name in ("a/requirements.txt", "poetry.lock"))
    printed = f"Error during extraction: (extracting as python/requirements) \n{joined}"
    assert osvscanner.unparsed(Completed(1, b"", (confirmed + printed).encode()), command, {}, snapshot) == ["a/requirements.txt", "poetry.lock"]
    forged = f"{printed}\telsewhere/poetry.lock: x\n"
    with pytest.raises(QualityError, match="outside this check"):
        osvscanner.unparsed(Completed(1, b"", (confirmed + forged).encode()), command, {}, snapshot)


@pytest.mark.parametrize(
    "printed",
    [
        extraction_error("poetry.lock", "bufio.Scanner: token too long"),
        extraction_error("{root}/requirements-dev.txt", "bufio.Scanner: token too long"),
        extraction_error("other/{root}/poetry.lock", "bufio.Scanner: token too long"),
        extraction_error("{root}/poetry.lockx", "bufio.Scanner: token too long"),
        'openAndExtractFromFile("{root}/requirements-dev.txt"): bufio.Scanner: token too long\n',
        'openAndExtractFromFile("{root}/poetry.lock\\x00"): open: no such file or directory\n',
    ],
    ids=["no-root", "outside-the-command", "root-not-leading", "longer-name", "opened-outside", "opened-longer"],
)
def test_osv_scanner_refuses_an_extraction_error_it_cannot_place(tmp_path, printed):
    files = {"package-lock.json": "{}\n", "poetry.lock": "x\n"}
    snapshot = snapshot_of(tmp_path, files)
    confirmed = scanned_line(f"{tmp_path}/package-lock.json", 1) + scanned_line(f"{tmp_path}/poetry.lock", 1)
    forged = confirmed + printed.format(root=str(tmp_path).removeprefix("/"))
    with pytest.raises(QualityError, match="outside this check"):
        osvscanner.unparsed(Completed(1, b"", forged.encode()), Command([], list(files), []), {}, snapshot)


def test_lockfile_scanners_report_no_package_for_the_partial_scan_rule_alone(tmp_path):
    snapshot = snapshot_of(tmp_path, {"go.mod": "module m\n"})
    command = Command([], ["go.mod"], [bound_of(PARTIAL_SCAN, "trivy", {"go.mod": ""})])
    report = {"Results": [{"Vulnerabilities": [vulnerability("t", "golang.org/x/text", "CVE-1")]}]}
    assert trivy.parse(json.dumps(report).encode(), command, snapshot) == []
    source = {"path": str(tmp_path / "go.mod")}
    found = {"package": {"name": "golang.org/x/text", "ecosystem": "Go"}, "vulnerabilities": [{"id": "X"}]}
    osv = Command([], ["go.mod"], [bound_of(PARTIAL_SCAN, "osv-scanner", {"go.mod": ""})])
    assert osvscanner.parse(json.dumps({"results": [{"source": source, "packages": [found]}]}).encode(), osv, snapshot) == []


def test_two_scanners_failing_on_one_lockfile_give_one_partial_scan_finding():
    rule = binding(PARTIAL_SCAN, "trivy").rule
    gaps = [code_hit(rule, "go.mod", None, "lockfile could not be parsed", None) for _ in range(2)]
    vulnerable = package_finding("go.mod", "golang.org/x/text", {"A"})
    assert once_per_gap([*gaps, vulnerable, vulnerable]) == [gaps[0], vulnerable, vulnerable]


def package_finding(path: str, name: str, ids: set):
    rule = binding(VULNERABLE, "trivy").rule
    return package_hit(rule, path, None, name, ids)


@pytest.mark.parametrize(
    ("base", "head", "new"),
    [
        (("golang.org/x/text", {"A"}), ("golang.org/x/crypto", {"B"}), True),
        (("@babel/traverse", {"A"}), ("@xmldom/xmldom", {"B"}), True),
        (("requests", {"A", "B"}), ("requests", {"A", "B", "C"}), True),
        (("requests", {"A", "B", "C"}), ("requests", {"B"}), False),
        (("requests", {"A"}), ("requests", {"A"}), False),
    ],
    ids=["go-swap", "scoped-swap", "downgrade", "upgrade-still-vulnerable", "unchanged"],
)
def test_a_package_finding_is_new_with_an_id_its_lockfile_lacked(base, head, new):
    baseline = baseline_of([package_finding("go.mod", *base)], {})
    finding = package_finding("go.mod", *head)
    assert new_hits([finding], baseline) == ([finding] if new else [])
    moved = package_finding("other/go.mod", *base)
    assert new_hits([moved], baseline) == [moved]


def test_jscpd_reads_its_own_report_once_and_names_unreadable_names(tmp_path):
    snapshot = snapshot_of(tmp_path / "snap", {"a.py": "x = 1\n", "b.py": "y = 2\nx = 1\n"})
    hostile = os.fsdecode(b"caf\xe9.py")
    bound = [bound_of("clean.clones", "jscpd", {"b.py": "python", "a.py": "python", hostile: "python"})]
    settings = {**DATA.tool("jscpd"), **resources(tmp_path, None)}
    [command] = jscpd.commands(bound, settings, tmp_path / "empty.yaml")
    prefix = command.prefix
    assert command.files == ["a.py", "b.py"]
    assert prefix[prefix.index("--min-tokens") + 1] == "50"
    assert prefix[prefix.index("--config") + 1] == str(tmp_path / "empty.json")
    output = Path(prefix[prefix.index("--output") + 1])
    assert output.parent == tmp_path
    assert "--absolute" in prefix
    clone = {
        "format": "python",
        "firstFile": {"name": str(snapshot.root / "a.py"), "start": 1},
        "secondFile": {"name": str(snapshot.root / "b.py"), "start": 2},
    }
    (output / jscpd.REPORT).write_text(json.dumps({"duplicates": [clone]}), encoding="utf-8")
    found = jscpd.parse(b"", command, snapshot)
    assert [(hit.path, hit.line) for hit in found[:2]] == [("a.py", 1), ("b.py", 2)]
    assert found[2:] == [Skipped(hostile, "jscpd cannot read a name that is not UTF-8")]
    with pytest.raises(ValueError, match="no report"):
        jscpd.parse(b"", command, snapshot)
