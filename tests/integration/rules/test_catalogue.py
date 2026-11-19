import json
import re

import pytest
import yaml

from quality import QualityError
from quality.adapters import astgrep
from quality.ruledata import LENSES, build_rule, load
from tests.integration.support import (
    ROOT,
    RULES,
    add_rules,
    catalogue,
    coverage,
    quality,
    rules_copy,
    rules_without_tool,
)

PREFIXES = ("security.", "coding.", "clean.", "legal.", "architecture.")
LEGAL = {
    "legal.license-declared": ({"license-declared"}, "medium", 25),
    "legal.vendored-license": ({"vendored-license"}, "critical", 50),
    "legal.dependency-license": ({"dependency-license"}, "critical", 50),
    "legal.external-request": ({"rg"}, "medium", 25),
    "legal.reuse": ({"reuse"}, "medium", 25),
}
ARCHITECTURE = {
    "clean.complexity": ("SRP", 10),
    "clean.function-length": ("SRP", 10),
    "clean.parameters": ("SRP", 10),
    "clean.clones": ("DRY", 10),
    "coding.structural": ("fail fast", 10),
    "clean.file-lines": ("SRP", 25),
    "clean.folder-items": ("SRP", 25),
    "architecture.layer": ("SRP", 25),
    "architecture.cycle": ("SRP", 25),
}
PRINT_CALL = {"python": {"tool": "ruff", "codes": ["T201"]}}

LIMIT_LEAK = re.compile(r"500|MAX_")
CORE_COUPLING = re.compile(r"utils\.cache|PROJECT_ROOT")
AST_GREP = RULES / "ast-grep"
CENSUS = {
    "python": ("a.py", "x = 1\n"),
    "yaml": ("a.yml", "a: 1\n"),
    "markdown": ("README.md", "# Title\n"),
    "javascript": ("a.js", "const a = 1;\n"),
    "typescript": ("a.ts", "const a: number = 1;\n"),
    "tsx": ("a.tsx", "const a = <b />;\n"),
    "jinja": ("t.txt.j2", "{{ a }}\n"),
    "shell": ("a.sh", "#!/bin/bash\ntrue\n"),
    "json": ("a.json", "{}\n"),
    "env": (".env", "A=1\n"),
    "conf": ("app.conf", "a = 1\n"),
    "ini": ("a.ini", "[a]\nb = 1\n"),
    "nginx": ("nginx.conf", "events {}\n"),
    "workflow": (".github/workflows/ci.yml", "on: push\n"),
    "dockerfile": ("Dockerfile", "FROM scratch\n"),
    "html": ("a.html", "<p>a</p>\n"),
    "css": ("a.css", "a { color: red; }\n"),
    "sql": ("a.sql", "SELECT 1;\n"),
    "toml": ("a.toml", "a = 1\n"),
    "php": ("a.php", "<?php\necho 1;\n"),
    "make": ("Makefile", "all:\n\ttrue\n"),
    "ruby": ("a.rb", "puts 1\n"),
    "rust": ("a.rs", "fn main() {}\n"),
    "xml": ("a.xml", "<a/>\n"),
    "nix": ("a.nix", "{ }\n"),
    "systemd": ("a.service", "[Unit]\nDescription=a\n"),
    "tex": ("a.tex", "\\relax\n"),
    "lua": ("a.lua", "print(1)\n"),
    "hcl": ("main.tf", "locals {}\n"),
}


def test_catalogue_schema():
    rules = catalogue()
    assert rules
    for rule in rules:
        assert {"id", "severity", "summary", "enforcer"} <= set(rule), rule.get("id")
        assert rule["id"].startswith(PREFIXES), rule["id"]


def test_every_counted_rule_names_a_lens():
    rules = catalogue()
    counted = [rule for rule in rules if "architecture" in rule]
    assert [rule["id"] for rule in counted if "lens" not in rule] == []
    assert {rule["lens"] for rule in rules if "lens" in rule} <= set(LENSES)
    assert {rule["id"]: (rule["lens"], rule["architecture"]) for rule in counted} == ARCHITECTURE


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        ({"architecture": 10}, "sets architecture without lens"),
        ({"lens": "SOLID"}, "names a lens outside"),
        ({"lens": "SRP", "architecture": 0}, "positive integer"),
        ({"lens": "SRP", "architecture": True}, "positive integer"),
        ({"lens": "SRP", "architecture": "10"}, "positive integer"),
        ({"legal": 0}, "sets legal other than a positive integer"),
        ({"legal": False}, "sets legal other than a positive integer"),
        ({"legal": "25"}, "sets legal other than a positive integer"),
    ],
)
def test_malformed_architecture_raises(extra: dict, message: str):
    raw = {"id": "coding.print-call", "severity": "low", "summary": "s", "enforcer": PRINT_CALL, **extra}
    with pytest.raises(QualityError, match=message):
        build_rule(raw, "fixture.yml", {})


def test_legal_rules_carry_their_enforcer_severity_and_weight():
    found = {
        rule["id"]: (
            {settings.get("builtin") or settings["tool"] for settings in rule["enforcer"].values()},
            rule["severity"],
            rule["legal"],
        )
        for rule in catalogue()
        if rule["id"].startswith("legal.")
    }
    assert found == LEGAL
    assert [rule["id"] for rule in catalogue() if "legal" in rule and not rule["id"].startswith("legal.")] == []


def test_lens_without_architecture_is_valid():
    raw = {"id": "coding.print-call", "severity": "low", "summary": "s", "enforcer": PRINT_CALL, "lens": "KISS/YAGNI"}
    rule = build_rule(raw, "fixture.yml", {})
    assert (rule.lens, rule.architecture) == ("KISS/YAGNI", None)


def test_architecture_without_lens_fails_closed(target, tmp_path):
    rules = rules_copy(tmp_path / "rules")
    weighed = {"id": "coding.print-call", "severity": "low", "summary": "s", "enforcer": PRINT_CALL, "architecture": 10}
    add_rules(rules, [weighed])
    target.write("a.py", "x = 1\n")
    target.commit()
    result = target.check("--all", "--rules", str(rules))
    assert result.returncode == 2
    assert "coding.print-call sets architecture without lens" in result.stderr


def test_unknown_runner_enforcer_fails_closed(target, tmp_path):
    rules = rules_copy(tmp_path / "rules")
    add_rules(rules, [{"id": "clean.typo", "severity": "low", "summary": "s", "enforcer": "size-gaurd"}])
    target.write("a.py", "x = 1\n")
    target.commit()
    result = target.check("--all", "--rules", str(rules))
    assert result.returncode == 2
    assert "clean.typo" in result.stderr


def test_duplicate_rule_id_fails_closed(target, tmp_path):
    rules = rules_copy(tmp_path / "rules")
    add_rules(rules, [{"id": "clean.folder-items", "severity": "low", "summary": "s", "enforcer": "folder-items"}])
    target.write("a.py", "x = 1\n")
    target.commit()
    result = target.check("--all", "--rules", str(rules))
    assert result.returncode == 2
    assert "duplicate rule id clean.folder-items" in result.stderr


def test_no_limit_or_core_coupling_in_runner():
    sources = sorted((ROOT / "src").rglob("*.py"))
    assert sources
    for path in sources:
        text = path.read_text(encoding="utf-8")
        assert not LIMIT_LEAK.search(text), path
        assert not CORE_COUPLING.search(text), path
    for path in sorted((ROOT / "rules").glob("*.yml")):
        assert not CORE_COUPLING.search(path.read_text(encoding="utf-8")), path


def test_coverage_census(target):
    for path, text in CENSUS.values():
        target.write(path, text)
    target.commit()
    kinds = coverage(target.path)["kinds"]
    for kind in CENSUS:
        assert kind in kinds, kind
        assert kinds[kind]["rules"], kind


def test_coverage_names_gaps(target, tmp_path):
    target.write("README.md", "# Title\n")
    target.write("data.xyz", "x\n")
    target.write("LICENSE", "MIT\n")
    target.write("a.py", "x = 1\n")
    target.commit()
    document = coverage(target.path)
    assert document["gaps"] == ["unclassified *.xyz", "unclassified LICENSE"]
    assert document["kinds"]["markdown"]["rules"] == ["coding.conflict-marker"]
    without_rg = rules_without_tool(tmp_path / "rules", "rg")
    assert coverage(target.path, "--rules", str(without_rg))["gaps"] == [
        "markdown",
        "unclassified *.xyz",
        "unclassified LICENSE",
    ]
    text = quality(target.path, "coverage", "--rules", str(without_rg))
    assert text.returncode == 0, text.stderr
    assert "markdown (1 files): no rules" in text.stdout
    assert text.stdout.splitlines()[-1].endswith(
        "without rules: markdown, unclassified *.xyz, unclassified LICENSE"
    )


def test_coverage_lists_only_rules_that_run(target):
    target.write("deploy.sh.j2", "#!/bin/bash\necho {{ greeting }}\n")
    target.commit()
    kinds = coverage(target.path)["kinds"]
    assert kinds["shell"]["rules"] == [
        "clean.file-lines",
        "coding.conflict-marker",
        "legal.external-request",
        "security.uncounted-line-break",
        "security.unverified-download",
    ]
    assert kinds["jinja"]["rules"] == [
        "clean.default-value",
        "clean.tool-pragma",
        "coding.conflict-marker",
        "legal.external-request",
        "security.uncounted-line-break",
    ]


def ast_grep_documents(language: str) -> list:
    (path,) = AST_GREP.glob(f"*/{language}.yml")
    return list(yaml.safe_load_all(path.read_text(encoding="utf-8")))


def ast_grep_bindings() -> set:
    found = set()
    for rule in catalogue():
        enforcer = rule["enforcer"]
        for settings in enforcer.values() if isinstance(enforcer, dict) else ():
            if settings.get("tool") == "ast-grep":
                found.add((rule["id"], settings["language"]))
    return found


def prefixes(documents: list) -> set:
    return {document["id"].split("/", 1)[0] for document in documents}


def test_ast_grep_rule_files_match_the_catalogue():
    bindings = ast_grep_bindings()
    languages = {language for _, language in bindings}
    assert sorted(path.stem for path in AST_GREP.glob("*/*.yml")) == sorted(languages)
    assert [path.name for path in AST_GREP.glob("*.yml")] == [astgrep.SHARED_FILE]
    shared = yaml.safe_load((AST_GREP / astgrep.SHARED_FILE).read_text(encoding="utf-8"))
    assert set(shared["languages"]) == languages
    settings = load(RULES).tool("ast-grep")
    for language in languages:
        own = ast_grep_documents(language)
        bound = {rule for rule, where in bindings if where == language}
        assert {document["language"] for document in own} == {language}
        assert not prefixes(own) & prefixes(shared["documents"]), language
        assert prefixes(own) <= bound, language
        composed = astgrep.composed(AST_GREP, language, settings)
        assert bound <= prefixes(composed), language
        assert '"@' not in json.dumps(composed), language
