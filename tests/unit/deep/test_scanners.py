import json
import os
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from quality import QualityError
from quality.adapters import (
    Collector,
    bind_files,
    jscpd,
    once_per_gap,
    osvscanner,
    ruff,
    semgrep,
    trivy,
    whole_scope,
)
from quality.adapters.base import Command, Skipped
from quality.db import Bundle
from quality.gate import baseline_of, code_hit, new_hits, package_hit
from quality.legal.checks import NO_DATA, REASONS, unchecked_notes
from quality.modes import ALL_TIERS, FAST, Session, tier_of
from quality.repo import Entry
from quality.ruledata import BUILTIN
from quality.snapshot import catalogue, materialize
from tests.unit.deep.support import (
    DATA,
    RULES,
    VULNERABLE,
    binding,
    bound_of,
    snapshot_of,
)

STATIC = "security.static-analysis"
PARTIAL_SCAN = "security.partial-scan"


def resources(tmp_path: Path, bundle) -> dict:
    empty_json = tmp_path / "empty.json"
    empty_json.write_text("{}\n", encoding="utf-8")
    return {"rules_dir": RULES, "database": bundle, "work_dir": tmp_path, "empty_json": empty_json, "threads": None}


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
    bound = bind_files(DATA, DATA.bindings()["gitleaks"], kinds, lambda _rule: True)
    assert [item.files for item in bound] == [["a.py", "notes.txt"]]


class CountingSnapshot:
    def __init__(self, paths: list):
        self.listed = paths
        self.classified = []
        self.exported = set()

    def paths(self) -> list:
        return self.listed

    def export(self, paths) -> None:
        self.exported.update(paths)

    def kinds_of(self, path: str) -> frozenset:
        self.classified.append(path)
        return frozenset()


def classified(predicate) -> tuple:
    snapshot = CountingSnapshot([".quality/architecture.yml", "a.py", "web/b.js"])
    tools = Collector(DATA, None).bound_tools(snapshot, ["a.py"], predicate)
    every = {path: frozenset() for path in snapshot.listed}
    for tool, bound in tools:
        if DATA.tools.get(tool, {}).get("whole_snapshot"):
            assert fields_of(bound) == fields_of(bind_files(DATA, DATA.bindings()[tool], every, predicate))
    return {tool for tool, _bound in tools}, set(snapshot.classified)


def fields_of(bound: list) -> list:
    return [(item.binding.rule.id, item.binding.tool, item.files, item.kinds) for item in bound]


def test_a_whole_snapshot_tool_classifies_only_the_files_it_binds_by_name():
    tools, paths = classified(lambda rule: tier_of(rule) == FAST)
    assert "lint-imports" in tools
    assert paths == {".quality/architecture.yml", "a.py"}
    assert classified(lambda _rule: True)[1] == {".quality/architecture.yml", "a.py", "web/b.js"}
    assert classified(lambda _rule: False) == (set(), {"a.py"})


def test_a_null_files_list_binds_by_kind_like_no_list():
    kind_bound = DATA.bindings()["jscpd"][0]
    nulled = replace(kind_bound, settings={**kind_bound.settings, "files": None})
    snapshot = CountingSnapshot([".quality/architecture.yml", "a.py", "web/b.js"])
    assert list(whole_scope(snapshot, [nulled])) == snapshot.listed


def test_only_files_patterns_mark_a_file_as_read_by_name():
    session = Session(DATA, None, None, None, ALL_TIERS, None, [], False)
    assert session.read_by_name("poetry.lock")
    assert not session.read_by_name("notes.txt")
    assert not session.read_by_name("bin/tool")


class ExportingRepo:
    def __init__(self, blobs: dict):
        self.blobs = blobs
        self.requests = []

    def sizes(self, oids: set) -> dict:
        return {oid: len(self.blobs[oid]) for oid in oids}

    def export_blobs(self, targets: dict, _request_file: Path) -> None:
        self.requests.append(sorted(targets))
        for oid, destinations in targets.items():
            for destination in destinations:
                destination.write_bytes(self.blobs[oid])


def tree_of(files: dict) -> tuple:
    oids = {path: f"{index:040x}" for index, path in enumerate(files)}
    entries = [Entry("100644", oid, path) for path, oid in oids.items()]
    return ExportingRepo({oids[path]: data for path, data in files.items()}), entries, oids


TREE = {"src/a.py": b"x = 1\n", "docs/b.md": b"# b\n", ".qualityignore.yml": b"[]\n", "big.bin": b"0" * 64}


def test_a_lazy_snapshot_writes_only_the_blobs_its_readers_open(tmp_path):
    repo, entries, oids = tree_of(TREE)
    snapshot = catalogue(repo, entries, tmp_path / "head", 32, DATA.kinds)
    assert snapshot.paths() == [".qualityignore.yml", "docs/b.md", "src/a.py"]
    assert snapshot.unchecked == ["big.bin"]
    assert (snapshot.root / "docs").is_dir()
    assert snapshot.data("src/a.py") == TREE["src/a.py"]
    assert snapshot.ignore_data() == TREE[".qualityignore.yml"]
    snapshot.export(["src/a.py", "big.bin", "missing.txt"])
    assert repo.requests == [[oids["src/a.py"]], [oids[".qualityignore.yml"]]]
    assert not (snapshot.root / "docs" / "b.md").exists()
    assert not (snapshot.root / "big.bin").exists()


def test_materialize_writes_every_kept_blob_in_one_request(tmp_path):
    repo, entries, oids = tree_of(TREE)
    snapshot = materialize(repo, entries, tmp_path / "head", 32, DATA.kinds)
    assert repo.requests == [sorted(oids[path] for path in snapshot.paths())]
    assert all((snapshot.root / path).read_bytes() == TREE[path] for path in snapshot.paths())
    assert not snapshot.pending


def test_negative_control_a_read_past_the_boundary_finds_no_blob(tmp_path):
    repo, entries, _oids = tree_of(TREE)
    snapshot = catalogue(repo, entries, tmp_path / "head", 32, DATA.kinds)
    with pytest.raises(FileNotFoundError):
        (snapshot.root / "src" / "a.py").read_bytes()
    assert snapshot.file("src/a.py").read_bytes() == TREE["src/a.py"]


class FailingRepo(ExportingRepo):
    def export_blobs(self, targets: dict, _request_file: Path) -> None:
        for destinations in targets.values():
            for destination in destinations:
                destination.write_bytes(b"partial")
        raise QualityError("git cat-file ended inside a blob")


def test_a_failed_export_removes_its_partial_files_and_keeps_them_pending(tmp_path):
    repo, entries, _oids = tree_of(TREE)
    snapshot = catalogue(FailingRepo(repo.blobs), entries, tmp_path / "head", 32, DATA.kinds)
    with pytest.raises(QualityError):
        snapshot.data("src/a.py")
    assert not (snapshot.root / "src" / "a.py").exists()
    assert "src/a.py" in snapshot.pending
    snapshot.repo = repo
    assert snapshot.data("src/a.py") == TREE["src/a.py"]


RUFF_TREE = {
    "pkg/__init__.py": b"",
    "pkg/sub/__init__.pyi": b"",
    "pkg/sub/new.py": b"import os\n\nimport helpers\nfrom lib.util import thing\nfrom . import sibling\n",
    "helpers.py": b"",
    "src/helpers.py": b"",
    "lib/__init__.py": b"",
    "lib/util.py": b"",
    "other/x.py": b"",
    "notes.md": b"",
}


def ruff_snapshot(tmp_path: Path, changed: bytes) -> tuple:
    repo, entries, _oids = tree_of({**RUFF_TREE, "pkg/sub/new.py": changed})
    snapshot = catalogue(repo, entries, tmp_path / "head", 1000, DATA.kinds)
    return snapshot, [bound_of("coding.implicit-namespace", "ruff", {"pkg/sub/new.py": "python"})]


def test_ruff_opens_the_package_markers_above_its_files_and_the_modules_their_imports_name(tmp_path):
    snapshot, bound = ruff_snapshot(tmp_path, RUFF_TREE["pkg/sub/new.py"])
    opened = ruff.opens(bound, snapshot) & set(snapshot.paths())
    assert opened == {"pkg/__init__.py", "pkg/sub/__init__.pyi", "helpers.py", "src/helpers.py", "lib/__init__.py", "lib/util.py"}
    assert opened <= Collector(DATA, None).opened([("ruff", bound)], snapshot)


def test_ruff_opens_every_python_file_when_one_of_its_files_does_not_parse(tmp_path):
    snapshot, bound = ruff_snapshot(tmp_path, b"def (:\n")
    assert ruff.opens(bound, snapshot) == {path for path in snapshot.paths() if path != "notes.md"}


def test_negative_control_a_tool_without_disk_discovery_opens_no_package_marker(tmp_path):
    snapshot, _bound = ruff_snapshot(tmp_path, RUFF_TREE["pkg/sub/new.py"])
    secrets = bind_files(DATA, DATA.bindings()["gitleaks"], {"pkg/sub/new.py": frozenset()}, lambda _rule: True)
    assert "pkg/__init__.py" not in Collector(DATA, None).opened([("gitleaks", secrets)], snapshot)


def test_a_fast_run_exports_its_judged_files_and_a_whole_snapshot_classification_every_file():
    snapshot = CountingSnapshot(["a.py", "web/b.js", "docs/c.md"])
    Collector(DATA, None).bound_tools(snapshot, ["a.py"], lambda rule: tier_of(rule) == FAST)
    assert snapshot.exported == {"a.py"}
    Collector(DATA, None).bound_tools(snapshot, ["a.py"], lambda _rule: True)
    assert snapshot.exported == set(snapshot.listed)


def test_a_bound_whole_snapshot_tool_opens_every_file_and_others_their_own_and_their_config():
    snapshot = CountingSnapshot([".quality/architecture.yml", "a.py", "web/b.js"])
    collector = Collector(DATA, None)
    tools = dict(collector.bound_tools(snapshot, ["a.py"], lambda rule: tier_of(rule) == FAST))
    assert collector.opened([("lint-imports", tools["lint-imports"])], snapshot) == set(snapshot.listed)
    secrets = bind_files(DATA, DATA.bindings()["gitleaks"], {"a.py": frozenset()}, lambda _rule: True)
    assert collector.opened([("gitleaks", secrets)], snapshot) == {"a.py", *DATA.tool("gitleaks")["loads"]}
    assert collector.opened([(BUILTIN, secrets)], snapshot) == {"a.py"}


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
    with pytest.raises(QualityError, match="^semgrep reported Timeout, so a file stays unchecked$"):
        semgrep.parse(json.dumps(timeout).encode(), command, snapshot)
    for kind in ("Timeout", ["Timeout", 3]):
        shaped = {"results": [], "errors": [{"type": kind, "path": "c.js"}], "paths": {"scanned": list(kinds)}}
        found = semgrep.parse(json.dumps(shaped).encode(), command, snapshot)
        assert [(hit.rule.id, hit.path, hit.line) for hit in found] == [(PARTIAL_SCAN, "c.js", None)]
    placed = {"results": [], "errors": [{"type": "Timeout", "path": "c.js"}], "paths": {"scanned": list(kinds)}}
    with pytest.raises(QualityError, match="could not read all of c.js"):
        semgrep.parse(json.dumps(placed).encode(), unbound, snapshot)
    fatal = {"results": [], "errors": [{"type": "Fatal error", "path": "c.js"}], "paths": {"scanned": list(kinds)}}
    with pytest.raises(QualityError, match="^semgrep reported Fatal error in c.js, so a file stays unchecked$"):
        semgrep.parse(json.dumps(fatal).encode(), command, snapshot)


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
    assert new_hits([finding], baseline, {}) == ([finding] if new else [])
    moved = package_finding("other/go.mod", *base)
    assert new_hits([moved], baseline, {}) == [moved]


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
    assert [hit.group for hit in found[:2]] == [(("a.py", 1), ("b.py", 2))] * 2
    assert found[2:] == [Skipped(hostile, "jscpd cannot read a name that is not UTF-8")]
    with pytest.raises(ValueError, match="no report"):
        jscpd.parse(b"", command, snapshot)


def test_unchecked_notes_follow_file_and_line_whatever_order_the_hits_arrive_in():
    rule = next(rule for rule in DATA.rules if rule.id == "legal.dependency-license")
    hits = [
        package_hit(rule, "b.txt", 2, "x", {NO_DATA}),
        package_hit(rule, "a.txt", 7, "y", {NO_DATA}),
        package_hit(rule, "a.txt", None, "z", {NO_DATA}),
        package_hit(rule, "a.txt", 4, "w", {NO_DATA}),
    ]
    expected = [f"unchecked: {where}: {REASONS[NO_DATA]}" for where in ("a.txt", "a.txt:4", "a.txt:7", "b.txt:2")]
    assert unchecked_notes(hits) == expected
    assert unchecked_notes(hits[::-1]) == expected
