import json
import os
import re
import subprocess

import pytest
import yaml

from quality.adapters import astgrep
from quality.ruledata import load
from tests.integration.support import (
    ROOT,
    RULES,
    UNTAGGED_DOCKERFILE,
    add_rules,
    branchy,
    catalogue,
    coverage,
    edit_yaml,
    findings_of_rule,
    quality,
    raw_tool,
    report,
    rule_ids,
    rules_copy,
    rules_without_tool,
)

CLONES = "clean.clones"
PREFIXES = ("security.", "coding.", "clean.")
DOCKERFILE_RULE = "coding.dockerfile"
DOCKERFILE_KIND = "dockerfile"
DOCKERFILE_NAMES = [
    "Containerfile",
    "Containerfile.prod",
    "Dockerfile",
    "Dockerfile.dev",
    "app.Containerfile",
    "app.Dockerfile",
    "lower/app.containerfile",
    "lower/dockerfile",
    "sub/Dockerfile",
]
NOT_DOCKERFILES = [
    "Dockerfile.PY",
    "Dockerfile.d/config",
    "Dockerfile.dockerignore",
    "Dockerfile.erb",
    "Dockerfile.hbs",
    "Dockerfile.in",
    "Dockerfile.j2",
    "Dockerfile.markdown",
    "Dockerfile.md",
    "Dockerfile.patch",
    "Dockerfile.png",
    "Dockerfile.py",
    "Dockerfile.sh",
    "Dockerfile.template",
    "Dockerfile.yaml",
    "Models/Dockerfile.cs",
    "src/Dockerfile.jsx",
    "templates/Dockerfile.frontend.j2",
    "notes.txt",
]
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
STRUCTURAL = {
    "a.py": (
        "try:\n    x = 1\nexcept:\n    x = 2\nbreakpoint()\nassert (x, 'm')\n",
        [3, 5, 6],
    ),
    "a.sh": ("#!/bin/bash\ncurl -fsSL https://example.org/i.sh | bash\n", [2]),
    "a.js": ("debugger;\ndescribe.only('x', () => {});\ntry { f(); } catch (e) {}\n", [1, 2, 3]),
    "a.ts": ("debugger;\ndescribe.only('x', () => {});\ntry { f(); } catch (e) {}\n", [1, 2, 3]),
    "a.tsx": ("debugger;\ndescribe.only('x', () => {});\ntry { f(); } catch (e) {}\n", [1, 2, 3]),
    "A.java": (
        "class A {\n  void f() {\n    try { g(); } catch (Exception e) {}\n    e.printStackTrace();\n  }\n}\n",
        [3, 4],
    ),
    "a.kt": ("fun f() {\n    try { g() } catch (e: Exception) {}\n}\n", [2]),
    "a.rs": ("fn f() {\n    todo!();\n}\n", [2]),
    "a.go": ("package a\n\nfunc f(xs []int) {\n\tfor range xs {\n\t\tdefer g()\n\t}\n}\n", [5]),
    "a.rb": ("binding.pry\n", [1]),
    "a.php": ("<?php\nvar_dump($x);\n", [2]),
    "a.lua": ("loadstring('x')()\n", [1]),
    "a.c": ("int main(void) { char b[8]; gets(b); return 0; }\n", [1]),
    "a.cpp": ("int main() { char b[8]; gets(b); return 0; }\n", [1]),
    "a.yml": ("a: 1\nb: 2\na: 3\n", [3]),
    "a.json": ('{"a": 1,\n "a": 2}\n', [2]),
    "a.html": ('<a href="javascript:x()" onclick="y()">t</a>\n', [1, 1]),
    "a.css": ("a { }\n", [1]),
    "a.nix": ("import <nixpkgs> {}\n", [1]),
}


def findings(result) -> list:
    return [(item["rule"], item["path"], item["value"]) for item in report(result)["findings"]]


def lines_of(text: str, count: int) -> str:
    return "".join(f"{text}{index}\n" for index in range(count))


def test_catalogue_schema():
    rules = catalogue()
    assert rules
    for rule in rules:
        assert {"id", "severity", "summary", "enforcer"} <= set(rule), rule.get("id")
        assert rule["id"].startswith(PREFIXES), rule["id"]


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


def test_dockerfile_kind_gets_hadolint(target):
    target.write("seed.py", "x = 1\n")
    target.commit()
    for name in (*DOCKERFILE_NAMES, *NOT_DOCKERFILES):
        target.write(name, UNTAGGED_DOCKERFILE)
    target.stage()
    result = target.check("--staged", "--json")
    assert result.returncode == 1, result.stderr
    found = sorted(
        (item["rule"], item["path"], item["line"])
        for item in report(result)["findings"]
        if item["rule"] == DOCKERFILE_RULE
    )
    assert found == [(DOCKERFILE_RULE, name, 1) for name in DOCKERFILE_NAMES]
    for name in NOT_DOCKERFILES:
        control = raw_tool(target.path, "hadolint", "--format", "json", name)
        assert '"DL3006"' in control.stdout


def test_dockerfile_kind_leaves_out_other_kinds_and_templates():
    kinds = load(ROOT / "rules").kinds
    names = DOCKERFILE_NAMES + NOT_DOCKERFILES
    found = [name for name in names if DOCKERFILE_KIND in kinds.parsed_kinds(name, kinds.kinds_of(name, b""))]
    assert found == DOCKERFILE_NAMES
    templates = [name for name in names if DOCKERFILE_KIND in kinds.kinds_of(name, b"") and name not in found]
    assert templates == ["Dockerfile.j2", "templates/Dockerfile.frontend.j2"]


def test_kinds_match_names_case_insensitively():
    kinds = load(ROOT / "rules").kinds
    assert kinds.kinds_of(".GITHUB/WORKFLOWS/CI.YML", b"") == {"workflow", "yaml"}
    assert kinds.kinds_of("Dockerfile.PY", b"") == {"python"}
    assert kinds.kinds_of("install.SH", b"") == {"shell"}
    assert [kinds.code_name(name) for name in ("install.SH", "deploy.zsh", "a.CS", "a.md")] == [
        True,
        True,
        True,
        False,
    ]


def test_code_names_cover_dockerfiles_and_spare_known_binaries():
    kinds = load(ROOT / "rules").kinds
    names = ("Dockerfile.prod", "app.Dockerfile", "bin/tool", ".DS_Store", "sub/THUMBS.DB")
    assert [kinds.code_name(name) for name in names] == [True, True, True, False, False]


def test_custom_glob_applies_to_a_known_extension(tmp_path):
    rules = rules_copy(tmp_path / "rules")
    edit_yaml(rules / "kinds.yml", lambda document: document["globs"].update(pyglob=["tools/*.py"]))
    kinds = load(rules).kinds
    assert kinds.kinds_of("tools/a.py", b"") == {"python", "pyglob"}
    assert kinds.kinds_of("lib/a.py", b"") == {"python"}


def test_hadolint_never_reads_a_template(target, tmp_path):
    rules = rules_copy(tmp_path / "rules")
    edit_yaml(rules / "kinds.yml", lambda document: document["globs"].update(dockerfile=["*.j2"]))
    target.write("seed.py", "x = 1\n")
    target.commit()
    for name in ("Dockerfile.j2", "templates/Dockerfile.frontend.j2", "Dockerfile"):
        target.write(name, "FROM {{ image }}\n" if name.endswith(".j2") else UNTAGGED_DOCKERFILE)
    target.stage()
    result = target.check("--staged", "--json", "--verbose", "--rules", str(rules))
    assert result.returncode == 1, result.stderr
    assert "quality: tool hadolint: exit 0, files: Dockerfile\n" in result.stderr
    assert [item["path"] for item in report(result)["findings"]] == ["Dockerfile"]


def test_size_limits(target, mode):
    target.write("seed.py", "x = 1\n")
    target.start_feature(mode)
    target.write("run.sh", "#!/bin/bash\n" + lines_of("echo ", 500))
    target.write("tests/long.sh", "#!/bin/bash\n" + lines_of("printf ", 500))
    target.write("data.json", "[\n" + "".join(f"{index},\n" for index in range(500)) + "0]\n")
    target.write("yarn.lock", lines_of("x", 501))
    target.write("package-lock.json", "{\n" + lines_of('  "x', 501).replace("\n", '": 0,\n') + '  "y": 0\n}\n')
    target.write("locales/de.js", lines_of("export const a = ", 501))
    target.write("generated/api.ts", lines_of("export const a = ", 501))
    target.advance(mode)
    result = target.judge(mode, "--json")
    assert result.returncode == 1, result.stderr
    assert findings(result) == [("clean.file-lines", "run.sh", 501)]


def test_folder_limit(target, mode):
    for index in range(11):
        target.write(f"pkg/m{index}.txt", "x\n")
    for index in range(20):
        target.write(f"wide/m{index}.txt", "x\n")
    target.start_feature(mode)
    target.write("pkg/m11.txt", "x\n")
    target.write("wide/m0.txt", "y\n")
    target.advance(mode)
    assert findings(target.judge(mode, "--json")) == []
    target.write("pkg/m12.txt", "x\n")
    target.advance(mode)
    result = target.judge(mode, "--json")
    assert result.returncode == 1, result.stderr
    assert findings(result) == [("clean.folder-items", "pkg", 13)]


def test_folder_limit_counts_a_new_folder_in_its_parent(target, mode):
    for index in range(12):
        target.write(f"pkg/m{index}.txt", "x\n")
    target.start_feature(mode)
    target.write("pkg/sub/deep/a.txt", "x\n")
    target.advance(mode)
    assert findings(target.judge(mode, "--json")) == [("clean.folder-items", "pkg", 13)]


def test_folder_limit_counts_symlinks(target, mode):
    for index in range(12):
        target.write(f"pkg/m{index}.txt", "x\n")
    target.start_feature(mode)
    (target.path / "pkg" / "link").symlink_to("m0.txt")
    target.advance(mode)
    assert findings(target.judge(mode, "--json")) == [("clean.folder-items", "pkg", 13)]


def test_structure_under_all(target):
    for index in range(13):
        target.write(f"pkg/m{index}.txt", "x\n")
    target.write("report_a.txt", "x\n")
    target.write("report_b.txt", "x\n")
    target.commit()
    result = target.check("--all", "--json")
    assert sorted(findings(result)) == [
        ("clean.folder-items", "pkg", 13),
        ("clean.prefix-groups", ".", 2),
    ]


def test_prefix_groups(target, mode):
    target.write("old_a.txt", "x\n")
    target.write("old_b.txt", "x\n")
    target.start_feature(mode)
    target.write("report_a.txt", "x\n")
    target.write("report-b.txt", "x\n")
    target.write("ok/__init__.py", "")
    target.write("ok/__main__.py", "")
    target.write("ok/2026_a.md", "x\n")
    target.write("ok/2026_b.md", "x\n")
    target.write("ok/test_a.txt", "x\n")
    target.write("ok/test_b.txt", "x\n")
    target.write("ok/-a.txt", "x\n")
    target.write("ok/-b.txt", "x\n")
    target.write("ok/web-app-a/x.txt", "x\n")
    target.write("ok/web-app-b/x.txt", "x\n")
    target.advance(mode)
    result = target.judge(mode, "--json")
    assert result.returncode == 1, result.stderr
    assert findings(result) == [("clean.prefix-groups", ".", 2)]
    target.write("old_c.txt", "x\n")
    target.advance(mode)
    assert sorted(findings(target.judge(mode, "--json"))) == [
        ("clean.prefix-groups", ".", 2),
        ("clean.prefix-groups", ".", 3),
    ]


def workflow(*steps: tuple) -> str:
    body = "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
    for name, script in steps:
        indented = "".join(f"          {line}\n" for line in script)
        body += f"      - name: {name}\n        run: |\n{indented}"
    return body


ELEVEN = [*(f"echo {index}" for index in range(10)), "echo a \\", "  b", "# note", ""]
TWELVE = [f"echo {index}" for index in range(12)]


def test_inline_script_limit(target, mode):
    target.write("seed.py", "x = 1\n")
    target.start_feature(mode)
    target.write(".github/workflows/w.yml", workflow(("short", ELEVEN)))
    target.advance(mode)
    assert findings(target.judge(mode, "--json")) == []
    target.write(".github/workflows/w.yml", workflow(("short", ELEVEN), ("long", TWELVE)))
    target.advance(mode)
    result = target.judge(mode, "--json")
    assert result.returncode == 1, result.stderr
    long_run = 7 + len(ELEVEN) + 2
    assert [(item["rule"], item["line"], item["value"]) for item in report(result)["findings"]] == [
        ("clean.inline-script", long_run, 12)
    ]


def test_inline_script_nocheck(target):
    target.write("seed.py", "x = 1\n")
    target.commit()
    text = workflow(("long", TWELVE)).replace(
        "run: |", "run: |  # nocheck: clean.inline-script -- vendored step"
    )
    target.write(".github/workflows/w.yml", text)
    target.stage()
    document = report(target.check("--staged", "--json"))
    assert document["findings"] == []
    assert [item["rule"] for item in document["nocheck"]] == ["clean.inline-script"]


def test_inline_script_aliases_counted_once(target):
    target.write("seed.py", "x = 1\n")
    target.commit()
    script = "".join(f"          echo {index}\n" for index in range(12))
    text = (
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps: &steps\n"
        f"      - name: long\n        run: |\n{script}"
        "  b:\n    runs-on: ubuntu-latest\n    steps: *steps\n"
    )
    target.write(".github/workflows/w.yml", text)
    target.stage()
    assert [item["rule"] for item in report(target.check("--staged", "--json"))["findings"]] == [
        "clean.inline-script"
    ]


def function_of_length(name: str, nloc: int) -> str:
    body = "".join(f"    total += {index}\n" for index in range(nloc - 3))
    return f"def {name}():\n    total = 0\n{body}    return total\n"


def test_function_limits(target, mode):
    target.write("seed.py", "x = 1\n")
    target.start_feature(mode)
    source = "\n\n".join(
        [
            branchy("ccn_ok", 9),
            branchy("ccn_over", 10),
            function_of_length("length_ok", 50),
            function_of_length("length_over", 51),
            "def params_ok(a, b, c, d, e):\n    return a + b + c + d + e\n",
            "def params_over(a, b, c, d, e, f):\n    return a + b + c + d + e + f\n",
        ]
    )
    target.write("limits.py", source)
    target.advance(mode)
    result = target.judge(mode, "--json")
    assert result.returncode == 1, result.stderr
    metric = [item for item in report(result)["findings"] if item["rule"] != CLONES]
    assert sorted((item["rule"], item["value"]) for item in metric) == [
        ("clean.complexity", 11),
        ("clean.function-length", 51),
        ("clean.parameters", 6),
    ]


def sum_function(name: str, parameters: str, terms: int) -> str:
    """
    Args:
        name: Function name.
        parameters: Parameter list text.
        terms: Number of added literals.

    Returns:
        A function of 8 + 2 * terms jscpd tokens with one parameter, one fewer without.
    """
    total = " + ".join(str(term) for term in range(1, terms + 1))
    return f"def {name}({parameters}):\n    return a + {total}\n"


@pytest.mark.deep
def test_clone_limit(target, tmp_path):
    fifty = sum_function("first", "a", 21)
    forty_nine = sum_function("second", "", 21)
    target.write("seed.py", "x = 0\n")
    target.start_feature("base")
    target.write("one.py", f"{fifty}\n\nx = 0\n\n\n{forty_nine}")
    target.write("two.py", f"y = 1\n\n\n{fifty}\n\nz = 2\n\n\n{forty_nine}")
    target.write(".jscpd.json", '{"ignore": ["**/*.py"]}\n')
    target.write("package.json", '{"jscpd": {"ignore": ["**/*.py"]}}\n')
    target.advance("base")
    expected = [("one.py", 1), ("two.py", 4)]
    for flags in (("--base", "main"), ("--all",)):
        found = report(target.check(*flags, "--json"))["findings"]
        assert sorted((i["path"], i["line"]) for i in found if i["rule"] == CLONES) == expected
    output = tmp_path / "raw"
    home = tmp_path / "home"
    home.mkdir()
    control = subprocess.run(
        ["jscpd", "--reporters", "json", "--output", str(output), "one.py", "two.py"],
        cwd=target.path,
        env={"PATH": os.environ["PATH"], "HOME": str(home)},
        capture_output=True,
        check=False,
    )
    assert control.returncode == 0
    raw = json.loads((output / "jscpd-report.json").read_text(encoding="utf-8"))
    assert raw["duplicates"] == []


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
        "security.uncounted-line-break",
        "security.unverified-download",
    ]
    assert kinds["jinja"]["rules"] == [
        "clean.default-value",
        "clean.tool-pragma",
        "coding.conflict-marker",
        "security.uncounted-line-break",
    ]


PARSE_ERRORS = {
    "bad.json": ('{"a": }\n', [1]),
    "open.json": ('{"a": 1\n', [2]),
    "bad.yml": ("a: [1, 2\nb: 3\n", [2]),
    "alias.yml": ("a: *missing\n", [1]),
    "bad.py": ("def f(:\n    pass\n", [1, 1]),
}
GRAMMAR_GAPS = {
    "variance.ts": "interface I<in out T> {\n  f(x: T): T;\n}\n",
    "safe.rs": 'unsafe extern "C" {\n    pub safe fn sqrt(x: f64) -> f64;\n}\n',
    "range.css": "@media (width >= 600px) {\n  a {\n    color: red;\n  }\n}\n",
    "layer.css": "@import url(x.css) layer(base);\n",
    "bitint.c": "_BitInt(7) y;\n",
    "split.c": "int f(void)\n#ifdef A\n{\n#else\n{\n#endif\n  return 0;\n}\n",
    "open.js": "if (x) {\n  y();\n",
}


def test_only_full_parsers_report_syntax_errors(target):
    for name, (source, _) in PARSE_ERRORS.items():
        target.write(name, source)
    for name, source in GRAMMAR_GAPS.items():
        target.write(name, source)
    target.write("good.json", '{"a": [1, ""]}\n')
    target.write("vault.yml", "a: !vault |\n  x\n")
    target.write("good.ts", "const x: number = 1;\nconst s = `${x}`;\n")
    target.write("good.sh", "#!/bin/bash\ncat <<EOF\nEOF\nif true; then echo hi; fi\n")
    target.commit()
    result = target.check("--all", "--json")
    found = findings_of_rule(result, "coding.syntax-error")
    assert found == sorted((name, line) for name, (_, lines) in PARSE_ERRORS.items() for line in lines)
    assert report(result)["parse_incomplete"] == sorted({*GRAMMAR_GAPS, *PARSE_ERRORS} - {"alias.yml"})
    assert "parse incomplete: variance.ts" in target.check("--all").stdout.splitlines()


EVASIONS = {
    "app.js": "export function run( {\n  debugger;\n  eval(location.hash.slice(1));\n}\n",
    "io.c": "void f(char *b) { gets(b) }\n",
    "boot.lua": "function f(\n  loadstring(io.read())()\nend\n",
    "run.php": "<?php\nif ($x) {\n  eval($_GET['x']);\n",
}


def test_unreadable_changed_file_is_a_finding(target, mode):
    target.write("old.js", "export function old( {\n}\n")
    target.start_feature(mode)
    for name, source in EVASIONS.items():
        target.write(name, source)
    target.write("gap.ts", "interface I<in out T> { // nocheck: coding.parse-incomplete -- TypeScript 4.7 variance\n}\n")
    target.write("ok.js", "export const a = 1;\n")
    target.advance(mode)
    result = target.judge(mode, "--json")
    assert result.returncode == 1
    assert sorted({path for path, _ in findings_of_rule(result, "coding.parse-incomplete")}) == sorted(EVASIONS)
    assert ("gap.ts", 1) in [(item["path"], item["line"]) for item in report(result)["nocheck"]]
    target.commit()
    whole = target.check("--all", "--json")
    assert findings_of_rule(whole, "coding.parse-incomplete") == []
    assert report(whole)["parse_incomplete"] == sorted([*EVASIONS, "gap.ts", "old.js"])


def test_nocheck_waives_one_line_of_an_unreadable_region(target, mode):
    target.start_feature(mode)
    body = "".join(f"  step{n}();\n" for n in range(30))
    target.write(
        "hide.js",
        "export function run( { // nocheck: coding.parse-incomplete -- grammar gap\n"
        + body
        + "  debugger;\n  try { a(); } catch (e) {}\n}\n",
    )
    target.advance(mode)
    result = target.judge(mode, "--json")
    assert result.returncode == 1
    lines = [line for _, line in findings_of_rule(result, "coding.parse-incomplete")]
    assert 1 not in lines
    assert {32, 33} <= set(lines)
    assert [(item["path"], item["line"]) for item in report(result)["nocheck"]] == [("hide.js", 1)]


def test_missing_token_spans_its_top_level_item(target, mode):
    target.start_feature(mode)
    note = " // nocheck: coding.parse-incomplete -- grammar gap"
    target.write("item.js", "const a = 1;\nfunction f() {\n  return (4 + 5;" + note + "\n  g();\n}\nconst c = 6;\n")
    target.write("item.c", "int a = 1;\nint f(void) {\n  g();\n  return 1" + note + "\n}\nint c = 6;\n")
    target.write("plain.js", "const a = (1 + 2;\nconst b = 3;\nconst c = 4;\n")
    target.advance(mode)
    result = target.judge(mode, "--json")
    assert result.returncode == 1
    assert findings_of_rule(result, "coding.parse-incomplete") == [
        ("item.c", 5),
        ("item.js", 4),
        ("item.js", 5),
        ("plain.js", 1),
    ]


VALID = {
    "page.html": '<!doctype html>\n<html>\n<head>\n<script src="app.js"></script>\n</head>\n<body><p>x</p></body>\n</html>\n',
    "style.html": "<html>\n<head><style></style></head>\n<body><textarea></textarea></body>\n</html>\n",
    "raw.go": 'package main\n\nvar a = ``\nvar b = ""\n\nfunc main() {}\n',
    "str.lua": "local a = ''\nlocal b = [[]]\nprint(a, b)\n",
    "lib.rs": "pub fn f() -> &'static str {\n    let _a = \"\";\n    r\"\"\n}\n",
    "tag.php": "<?php\necho 1;\n?>\n<p>x</p>\n<?php echo 2; ?>\n",
    "page.php": "<!doctype html>\n<p>x</p>\n<?php echo 1; ?>\n<p>y</p>\n",
    "markup.php": '<!doctype html>\n<html lang="en"><head><meta charset="utf-8"><title>A</title></head></html>\n',
    "call.php": "<?php get_header(); ?>\n<main>\n<?php the_content(); ?>\n</main>\n<?php get_footer(); ?>\n",
    "layout.php": (
        '<!doctype html>\n<html lang="<?php echo esc_attr($lang); ?>">\n<body>\n<?php if ($user): ?>\n'
        '  <nav><a href="/">Home</a></nav>\n<?php else: ?>\n  <a href="/login">Login</a>\n<?php endif; ?>\n</body>\n'
    ),
    "loop.php": (
        "<?php while (have_posts()) : the_post(); ?>\n  <article id=\"post-<?php the_ID(); ?>\">\n"
        "    <td><?= $row['a'] ?></td>\n  </article>\n<?php endwhile; ?>\n"
    ),
    "script.php": (
        "<?php $v = 1; ?>\n<script>\nvar data = <?php echo wp_json_encode($v); ?>;\n"
        "var url = '<?php echo esc_url($v); ?>';\n</script>\n"
    ),
    "inline.php": (
        "<?php $c = get_theme_mod('color'); ?>\n<style>\n.a { color: <?php echo esc_attr($c); ?>; }\n"
        "/* header */\n.b { background: url('<?php echo esc_url($img); ?>'); }\n</style>\n"
    ),
    "eot.php": "<?php\n$a = <<<EOT\nx\nEOT?>\n<p>y</p>\n",
    "list.php": "<?php $a = 1; $b = 2; ?>\n<p><?= $a, $b ?></p>\n<?= $a, $b ?>\n",
    "switch.php": "<?php switch ($x): ?>\n<?php case 1: ?>\n<p>one</p>\n<?php endswitch; ?>\n",
    "tpl.js": "export const a = ``;\nconst b = 1\n;[b].forEach(String)\n",
    "jsx.tsx": "export const A = () => <div></div>;\n",
    "def.c": "#define FLAG\n#ifdef FLAG\nint x;\n#endif\nint main(void) { return 0; }\n",
    "doc.rb": "x = <<~EOS\nEOS\nputs x, ''\n",
    "empty.css": 'a::before { content: ""; }\n',
    "main.tf": 'locals {\n  a = ""\n  b = <<EOT\nEOT\n}\n',
    "s.nix": "{ a = \"\"; b = ''''; }\n",
    "Main.kt": 'fun main() {\n    println("")\n}\n',
    "Main.java": 'class Main {\n  String a = "";\n  String b = """\n    """;\n}\n',
}


def test_valid_code_parses_in_full(target):
    for name, source in VALID.items():
        target.write(name, source)
    target.commit()
    assert report(target.check("--all", "--json"))["parse_incomplete"] == []


HIDDEN_PHP = {
    "tag.php": ("<?php\n$x = '?>'; var_dump($x); // <?\n", 2),
    "dq.php": ('<?php $v = 1; ?>\n<script>\nvar y = "<?php $s = "?>"; var_dump($s); $t = "<?"; ?>";\n</script>\n', 3),
    "sq.php": ("<?php $v = 1; ?>\n<script>\nvar u = '<?php $s = '?>'; var_dump($s); $t = '<?'; ?>';\n</script>\n", 3),
    "dq_lines.php": ('<?php $v = 1; ?>\n<script>\nvar y = "<?php\n$s = "?>";\nvar_dump($s);\n$t = "<?";\n?>";\n</script>\n', 5),
    "sq_lines.php": ("<?php $v = 1; ?>\n<script>\nvar u = '<?php\n$s = '?>';\nvar_dump($s);\n$t = '<?';\n?>';\n</script>\n", 5),
    "block.php": ("<?php $v = 1; ?>\n<!-- /* -->\n<?php $s = '*/ ?>'; var_dump($s); $t = '<?'; ?>\n", 3),
    "heredoc.php": ("<?php\n$s = <<<EOT\n?>\nEOT;\nvar_dump($s);\n", 5),
    "comment.php": ("<?php // c ?><?php var_dump($x);\n", 1),
    "echo.php": ("<p><?= var_dump($x) ?></p>\n", 1),
    "glued.php": ("<p><?=var_dump($x)?></p>\n", 1),
}


def test_closing_tag_hidden_in_php_code_keeps_the_code(target, mode):
    target.start_feature(mode)
    for name, (source, _) in HIDDEN_PHP.items():
        target.write(name, source)
    target.advance(mode)
    found = findings_of_rule(target.judge(mode, "--json"), "coding.structural")
    assert found == sorted((name, line) for name, (_, line) in HIDDEN_PHP.items())


def test_edit_to_an_unreadable_legacy_file_is_judged_absolutely(target, mode):
    target.write("a.css", "svg .a { fill: url(#hatch); }\n.b { color: red; }\n")
    target.start_feature(mode)
    target.write("a.css", "svg .a { fill: url(#hatch); }\n.b { color: red; }\n.c { color: blue; }\n")
    target.advance(mode)
    result = target.judge(mode, "--json")
    assert result.returncode == 1
    assert findings_of_rule(result, "coding.parse-incomplete") == [("a.css", 1)]


def test_path_entry_waives_an_unreadable_region(target, mode):
    target.write(".qualityignore.yml", "- rule: coding.parse-incomplete\n  paths: [gap.js]\n  reason: grammar gap\n")
    target.start_feature(mode)
    target.write("gap.js", "export function run( {\n  a();\n  b();\n}\n")
    target.advance(mode)
    assert target.judge(mode).returncode == 0
    target.commit()
    whole = report(target.check("--all", "--json"))
    assert whole["findings"] == []
    assert whole["parse_incomplete"] == ["gap.js"]


UNUSED = {
    "fake.py": "# nocheck: clean.comment -- loop over every user and send the newsletter mail\nx = 1\n",
    "other.py": "x = 1  # nocheck: security.temp-path -- the loop retries three times\n",
}


def test_unused_nocheck_is_a_finding(target, mode):
    target.write("legacy.py", "# nocheck: clean.comment -- an old one\nx = 1\n")
    target.start_feature(mode)
    for name, source in UNUSED.items():
        target.write(name, source)
    target.write("legacy.py", "# nocheck: clean.comment -- an old one\nx = 2\n")
    target.write("used.py", "breakpoint()  # nocheck: coding.structural -- fixture\n")
    target.write("gap.ts", "interface I<in out T> { // nocheck: coding.parse-incomplete -- grammar gap\n}\n")
    target.advance(mode)
    result = target.judge(mode, "--json")
    assert result.returncode == 1
    assert findings_of_rule(result, "clean.unused-nocheck") == [("fake.py", 1), ("other.py", 1)]
    target.commit()
    whole = target.check("--all", "--json")
    assert findings_of_rule(whole, "clean.unused-nocheck") == [("fake.py", 1), ("legacy.py", 1), ("other.py", 1)]


NOT_RUN = {
    "dup.js": "export const a = 1; // nocheck: clean.clones -- each test spells out its own request\n",
    "kind.py": "x = 1  # nocheck: coding.shell-lint -- the loop retries three times\n",
    "group.js": "export const b = 1; // nocheck: clean -- each test spells out its own request\n",
    "group.ts": "export const c = 1; // nocheck: security -- vetted by the semgrep rule set\n",
}
DEEP_TIER_NOCHECKS = [("dup.js", 1), ("group.js", 1), ("group.ts", 1)]


@pytest.mark.deep
def test_nocheck_for_a_rule_that_did_not_run_is_not_judged(target, mode):
    target.start_feature(mode)
    for name, source in NOT_RUN.items():
        target.write(name, source)
    target.advance(mode)
    judged = [("kind.py", 1), *(DEEP_TIER_NOCHECKS if mode == "base" else [])]
    assert findings_of_rule(target.judge(mode, "--json"), "clean.unused-nocheck") == sorted(judged)


def test_old_nocheck_under_an_old_path_entry_stays_old(target, mode):
    target.write(".qualityignore.yml", "- rule: clean.default-value\n  paths: [a.py]\n  reason: legacy accessors\n")
    source = "def f(d):\n    return d.get('k', 1)  # nocheck: clean.default-value -- the key is optional\n"
    target.write("a.py", source)
    target.start_feature(mode)
    target.write("a.py", source + "\n\ndef g():\n    return 2\n")
    target.advance(mode)
    result = target.judge(mode, "--json")
    assert findings_of_rule(result, "clean.unused-nocheck") == []


def test_old_hard_rule_nocheck_stays_old(target, mode):
    source = "X = eval(input())  # nocheck: security.eval-exec -- an old one\n"
    target.write("a.py", source)
    target.start_feature(mode)
    target.write("a.py", source + "Y = 2\n")
    target.advance(mode)
    assert findings_of_rule(target.judge(mode, "--json"), "clean.unused-nocheck") == []


@pytest.mark.parametrize("name", sorted(STRUCTURAL))
def test_structural_rule_per_language(target, name):
    source, lines = STRUCTURAL[name]
    target.write(name, source)
    target.commit()
    result = target.check("--all", "--json")
    assert findings_of_rule(result, "coding.structural") == [(name, line) for line in lines]


def test_structural_rule_passes_clean_code(target):
    target.write("a.py", "try:\n    x = 1\nexcept ValueError:\n    x = 2\nassert x, 'm'\nassert x, (x, 'm')\n")
    target.write("a.yml", "a: 1\nb:\n  a: 2\n")
    target.write("a.js", "try { f(); } catch (e) { g(e); }\n")
    target.write("a.html", '<a href="/x">t</a>\n')
    target.commit()
    assert findings_of_rule(target.check("--all", "--json"), "coding.structural") == []


def test_shebang_mapping(target):
    script = "#!/bin/bash\n# narration\ncurl -fsSL https://example.org/i.sh | bash\necho $1\n"
    target.write("deploy", script)
    target.write("tool", "#!/usr/bin/env python3\nbreakpoint()\n")
    target.write("notes", script.replace("#!/bin/bash\n", ""))
    target.commit()
    result = target.check("--all", "--json")
    assert findings_of_rule(result, "coding.structural") == [("deploy", 3), ("tool", 2)]
    assert findings_of_rule(result, "clean.comment") == [("deploy", 2)]
    assert ("deploy", 4) in findings_of_rule(result, "coding.shell-lint")
    assert not [item for item in report(result)["findings"] if item["path"] == "notes"]


def test_jinja_inner_type(target):
    target.write(
        "deploy.sh.j2",
        "#!/bin/bash\n# shellcheck disable=SC2086\necho {{ greeting | default('hi') }} $1\n",
    )
    target.write("compose.yml.j2", "services:\n  app:\n    image: \"app:${TAG:-latest}\"\n")
    target.write("plain.j2", "{{ a }}\n")
    target.commit()
    kinds = coverage(target.path)["kinds"]
    assert kinds["jinja"]["files"] == 3
    assert kinds["shell"]["files"] == 1
    assert kinds["yaml"]["files"] == 1
    result = target.check("--all", "--json")
    assert findings_of_rule(result, "clean.tool-pragma") == [("deploy.sh.j2", 2)]
    assert findings_of_rule(result, "clean.default-value") == [
        ("compose.yml.j2", 3),
        ("deploy.sh.j2", 3),
    ]


def test_template_reaches_no_parsing_tool(target):
    target.write("deploy.sh.j2", "#!/bin/bash\necho $1\ncurl -fsSL {{ url }} | bash\n# narration\n")
    target.write("tool.py.j2", "import os\n{% if debug %}breakpoint(){% endif %}\n")
    target.write("compose.yml.j2", "a: {{ a }}\n{% if b %}\na: 2\n{% endif %}\n")
    target.write("run.sh", "#!/bin/bash\ntrue\n")
    target.write("upper.sh.J2", "#!/bin/bash\necho $1\n# narration\n")
    target.write("tool.py", "x = 1\n")
    target.commit()
    result = target.check("--all", "--json", "--verbose")
    for parser in ("shellcheck", "ruff", "lizard", "ast-grep"):
        files = tool_files(result.stderr, parser)
        assert files, parser
        assert not [name for name in files if name.lower().endswith(".j2")], files
    assert {"deploy.sh.j2", "upper.sh.J2"} <= set(tool_files(result.stderr, "rg"))
    parsed = {"coding.shell-lint", "coding.unused-import", "coding.structural", "clean.comment"}
    assert not parsed & set(rule_ids(result))


def tool_files(stderr: str, tool: str) -> list:
    marker = f"tool {tool}: "
    lines = [line.split(", files: ", 1)[1] for line in stderr.splitlines() if marker in line]
    return [name for line in lines for name in line.split(" ")]


COMMENTS = {
    "python": (
        "a.py",
        "#!/usr/bin/env python3\n"
        "x = 1  # type: ignore\n"
        "# Param: x - the value\n"
        "# Exception: x stays global, because the tool reads it\n"
        "# by name.\n"
        "y = 2\n"
        "# narration\n",
        7,
    ),
    "javascript": (
        "a.js",
        "#!/usr/bin/env node\n"
        "// @ts-check\n"
        "/** @param {number} a value */\n"
        "function f(a) { return a; }\n"
        "// Exception: f stays global, because the page reads it\n"
        "// by name.\n"
        "const y = 2;\n"
        "// narration\n",
        8,
    ),
    "shell": (
        "a.sh",
        "#!/bin/bash\n"
        "# shellcheck shell=bash\n"
        "# Param $1: the value (required)\n"
        "# Exception: x stays global, because the caller reads it\n"
        "# by name.\n"
        "x=1\n"
        "# narration\n",
        7,
    ),
    "java": (
        "A.java",
        "#!/usr/bin/java --source 21\n"
        "class A {\n"
        "  // noinspection unused\n"
        "  /** @param a value */\n"
        "  int f(int a) { return a; }\n"
        "  // Exception: f stays package-private, because the test reads it\n"
        "  // by name.\n"
        "  int y;\n"
        "  // narration\n"
        "}\n",
        9,
    ),
    "kotlin": (
        "a.kts",
        "#!/usr/bin/env kotlin\n"
        "// ktlint-disable no-wildcard-imports\n"
        "/** @param a value */\n"
        "fun f(a: Int) = a\n"
        "// Exception: f stays top-level, because the script reads it\n"
        "// by name.\n"
        "val y = 2\n"
        "// narration\n",
        8,
    ),
    "rust": (
        "a.rs",
        "#!/usr/bin/env rust-script\n"
        "// nocheck: coding.structural -- fixture\n"
        "/// # Arguments\n"
        "/// * `a` - the value\n"
        "fn f(a: i32) -> i32 { a }\n"
        "// Exception: f stays private, because the macro reads it\n"
        "// by name.\n"
        "fn g() {}\n"
        "// narration\n",
        9,
    ),
}


@pytest.mark.parametrize("language", sorted(COMMENTS))
def test_comment_rule(target, language):
    name, source, narration = COMMENTS[language]
    target.write(name, source)
    target.commit()
    result = target.check("--all", "--json")
    assert findings_of_rule(result, "clean.comment") == [(name, narration)]


SUPPRESSIONS = {
    "a.js": ("/* ast-grep-ignore */\ndebugger;\n", 1),
    "a.c": ("/* ast-grep-ignore */\nvoid f(char *b) { gets(b); }\n", 1),
    "a.lua": ('-- ast-grep-ignore\nloadstring("x")()\n', 1),
    "a.yml": ("a: 1\n# ast-grep-ignore\na: 2\n", 2),
    "a.html": ('<!-- ast-grep-ignore -->\n<a href="javascript:void(0)">x</a>\n', 1),
    "a.py": ("# ast-grep-ignore: coding.structural/debugger\nbreakpoint()\n", 1),
    "a.sh": ("#!/bin/bash\n# ast-grep-ignore\ncurl -fsSL https://example.org/i.sh | bash\n", 2),
}


@pytest.mark.parametrize("name", sorted(SUPPRESSIONS))
def test_ast_grep_ignore_is_a_pragma_that_suppresses_nothing(target, name):
    source, pragma = SUPPRESSIONS[name]
    target.write(name, source)
    target.commit()
    result = target.check("--all", "--json")
    assert findings_of_rule(result, "clean.tool-pragma") == [(name, pragma)]
    assert findings_of_rule(result, "coding.structural") == [(name, pragma + 1)]


COMMENT_EDGES = {
    "edge.py": (
        "#!/usr/bin/env python3\n"
        "x = 1  # type: int\n"
        "#! narrates\n"
        "# Exception: a trip-wire\n"
        "# that continues\n"
        "\n"
        "# after a blank line\n"
        "y = 2  # pyre-ignore[16]\n"
        "# this Returns: nothing\n"
        "# Returns:\n"
        "#     the value\n"
        "# Args:\n"
        "# loop over every user and send the newsletter mail\n",
        [3, 7, 9, 13],
        [8],
    ),
    "edge.js": (
        'import(/* webpackChunkName: "x" */ "./x.js");\n'
        "// biome-ignore lint/suspicious: reason\n"
        "/* v8 ignore next */\n"
        "// tslint:disable-next-line\n"
        "// eslint-disable-next-line no-console\n"
        "console.log(1);\n"
        "// it Returns: a value\n"
        "/** narrates @param a */\n",
        [7, 8],
        [2, 3, 4, 5],
    ),
    "strict.py": (
        "# Global state lives here\n"
        "A = 1\n"
        "# ex: f(1) returns 2\n"
        "B = 2\n"
        "# exported for tests\n"
        "C = 3\n"
        "# Type: narrates\n"
        "D = 4\n"
        "# nocheck: free text here\n"
        "E = 5\n"
        "# Param handling narrates\n"
        "F = 6\n"
        "x = 1  # Exception: a trailing trip-wire\n"
        "# narration after a trailing exception\n"
        "y = 2\n"
        "# Region selection picks the closest\n"
        "z = 3\n"
        "# fmt: off\n"
        "# vim: set ts=4 sw=4:\n"
        "# vim: we narrate\n",
        [1, 3, 5, 7, 9, 11, 14, 16, 20],
        [18],
    ),
    "doc.js": (
        "/**\n * @param x the input\n * Then the function narrates every step.\n */\n"
        "export function f(x) {\n  return x;\n}\n"
        "/**\n * @param x the input\n *   continued\n * @returns the input\n */\n"
        "export function g(x) {\n  return x;\n}\n"
        "/*\n * Args:\n *   x: the input\n */\n"
        "export function h(x) {\n  return x;\n}\n"
        "// prettier-ignore\n",
        [],
        [23],
    ),
    "scope.py": (
        "# -*- coding: utf-8 -*-\n"
        "# vim: set ts=4 sw=4:\n"
        "# global cache, mirror\n"
        "# exported helpers, wrappers\n"
        "# ex: picks the closest mirror=yes\n"
        "x = 1  # type: int\n"
        "# type: Region\n"
        "# -*- note: the loop retries three times -*-\n"
        "# coding: retries-the-request\n"
        "# nocheck: x -- this loop walks every mirror\n"
        "# nocheck: clean.comment -- a catalogue rule\n"
        "# SPDX-License-Identifier: retries OR mirrors\n"
        "# SPDX-License-Identifier: MIT OR Apache-2.0\n"
        "# @license loop-retries\n"
        "# sourceMappingURL=the-loop-retries\n"
        "# language=English\n"
        "# language=SQL\n"
        "# vim: set et:\n"
        "y = 2\n"
        "\n"
        "\n"
        "def f(a):\n"
        "    # type: (int) -> int\n"
        "    return a\n"
        "# vim: set et:\n",
        [3, 4, 5, 7, 8, 9, 10, 12, 14, 15, 16, 18],
        [],
    ),
    "scope.js": (
        "const a = /*#__PURE__*/ f();\n"
        "const b = /*@__PURE__*/ f();\n"
        "/* global foo, bar */\n"
        "// global cache, mirror\n"
        'import(/* webpackChunkName: "x" */ "./x.js");\n'
        '// webpackNote: "we retry here because the host flaps"\n'
        "/** @type {number} */\n"
        "const c = 1;\n"
        "/** @type the loop retries three times */\n"
        "const d = 1;\n"
        "/**\n *  This function narrates every step it takes.\n */\n"
        "const e = 1;\n"
        "/* Args: */\n"
        "// and here we narrate what the code below does\n"
        "const g = 1;\n"
        "// # Errors\n"
        "// the loop retries three times\n"
        "const h = 1;\n"
        "/* eslint no-eval: 0 */\n",
        [4, 6, 9, 11, 15, 16, 18, 19],
        [21],
    ),
}


@pytest.mark.parametrize("name", sorted(COMMENT_EDGES))
def test_comment_rule_edges(target, name):
    source, narration, pragmas = COMMENT_EDGES[name]
    target.write(name, source)
    target.commit()
    result = target.check("--all", "--json")
    assert findings_of_rule(result, "clean.comment") == [(name, line) for line in narration]
    assert findings_of_rule(result, "clean.tool-pragma") == [(name, line) for line in pragmas]


DOCSTRINGS = (
    '"""Narrates the module."""\n\n\n'
    'def f(a):\n    """\n    Args:\n        a: value.\n\n    Returns:\n        The value.\n    """\n    return a\n\n\n'
    'def g():\n    """Exception: the plugin loader calls g by name."""\n    return 1\n\n\n'
    'class H:\n    """\n    Attributes:\n        n: count.\n\n    Narration after the sections.\n    """\n\n'
    '    def m(self):\n        x = 1\n        """not a docstring"""\n        return x\n'
)


def test_docstring_is_checked(target):
    target.write("doc.py", DOCSTRINGS)
    target.commit()
    result = target.check("--all", "--json")
    assert findings_of_rule(result, "clean.comment") == [("doc.py", 1), ("doc.py", 21)]


def docstring_at(indent: str) -> str:
    return f'def f(a):\n{indent}"""\n{indent}Args:\n{indent}{indent}a: value.\n{indent}"""\n{indent}return a\n'


def test_docstring_passes_at_any_indentation(target):
    for name, indent in {"two.py": "  ", "tab.py": "\t", "deep.py": "\t" * 9, "wide.py": " " * 36}.items():
        target.write(name, docstring_at(indent))
    target.write("quote.py", '"""Args:\n    --port: the port.\n"""\n\n\ndef f(a):\n    """Args:\n        a: value.\n\n'
                 '    Returns:\n        The value.\n    """\n    return a\n')
    target.write("prose.py", 'def f(a):\n    """Args:\n        a: value.\n\n    Narration after the sections.\n'
                 '    """\n    return a\n')
    target.commit()
    assert findings_of_rule(target.check("--all", "--json"), "clean.comment") == [("prose.py", 2)]


PRAGMA_EXAMPLES = [
    "noqa", "ruff: noqa", "fmt: off", "flake8: noqa", "type: ignore", "mypy: ignore-errors",
    "pyright: ignore", "pyre-ignore[16]", "pylint: disable=W0611", "pylint: skip-file", "isort: skip_file",
    "nosec", "pragma: no cover", "pragma: allowlist secret", "nosemgrep", "trivy:ignore:AVD-DS-0002",
    "shellcheck disable=SC2086", "lizard forgives", "eslint-disable-next-line no-console", "eslint no-eval: 0",
    "tslint:disable-next-line", "biome-ignore lint: reason", "deno-lint-ignore no-explicit-any",
    "jshint ignore:line", "@ts-expect-error", "istanbul ignore next", "c8 ignore next", "v8 ignore next",
    "@vite-ignore", "prettier-ignore", "noinspection SpellCheckingInspection", "@formatter:off",
    "ReSharper disable once UnusedMember.Global", "NOSONAR", "NOPMD", "CHECKSTYLE:OFF", "nolint:errcheck",
    "NOLINTNEXTLINE(bugprone-easily-swappable-parameters)", "cppcheck-suppress nullPointer",
    "lint:file-ignore U1000 reason", "rubocop:disable Style/Foo", "standard:disable Style/Foo", "phpcs:ignore",
    "@phpstan-ignore-next-line", "@psalm-suppress MixedAssignment", "stylelint-disable",
    "markdownlint-disable MD013", "jscpd:ignore-start", "luacheck: ignore", "ktlint-disable no-wildcard-imports",
    "gitleaks:allow", "hadolint ignore=DL3008", "yamllint disable-line rule:truthy", "checkov:skip=CKV_AWS_20",
    "tfsec:ignore:aws-s3-enable-bucket-logging", "tflint-ignore: terraform_unused", "kics-scan ignore-line",
    "ast-grep-ignore",
]
PRAGMA_FILES = {
    "python": ("p.py", "", "# {}"),
    "bash": ("p.sh", "", "# {}"),
    "ruby": ("p.rb", "", "# {}"),
    "yaml": ("p.yml", "", "# {}"),
    "nix": ("p.nix", "", "# {}"),
    "hcl": ("p.tf", "", "# {}"),
    "javascript": ("p.js", "", "// {}"),
    "typescript": ("p.ts", "", "// {}"),
    "tsx": ("p.tsx", "", "// {}"),
    "java": ("P.java", "", "// {}"),
    "kotlin": ("p.kt", "", "// {}"),
    "csharp": ("p.cs", "", "// {}"),
    "rust": ("p.rs", "", "// {}"),
    "go": ("p.go", "", "// {}"),
    "c": ("p.c", "", "// {}"),
    "cpp": ("p.cpp", "", "// {}"),
    "php": ("p.php", "<?php\n", "// {}"),
    "lua": ("p.lua", "", "-- {}"),
    "css": ("p.css", "", "/* {} */"),
    "html": ("p.html", "", "<!-- {} -->"),
    "json": ("p.json", "", "// {}"),
}


def test_every_pragma_spelling_has_an_example():
    spellings = yaml.safe_load((RULES / "comments.yml").read_text(encoding="utf-8"))
    groups = {**spellings["pragmas"], **spellings["pragmas_anywhere"]}
    for tool, patterns in groups.items():
        for pattern in patterns:
            assert any(re.search(pattern, example, re.IGNORECASE) for example in PRAGMA_EXAMPLES), (tool, pattern)


@pytest.mark.parametrize("language", sorted(PRAGMA_FILES))
def test_every_pragma_is_a_tool_pragma_in_every_language(target, language):
    name, header, comment = PRAGMA_FILES[language]
    target.write(name, header + "".join(comment.format(example) + "\n" for example in PRAGMA_EXAMPLES))
    target.commit()
    first = header.count("\n") + 1
    found = findings_of_rule(target.check("--all", "--json"), "clean.tool-pragma")
    assert found == [(name, line) for line in range(first, first + len(PRAGMA_EXAMPLES))]


def test_nocheck_in_css_and_html(target):
    target.write("a.css", "a {} /* nocheck: coding.structural -- fixture */\nb {}\n")
    target.write(
        "a.html",
        '<a onclick="f()">y</a> <!-- nocheck: coding.structural -- fixture -->\n<a onclick="g()">z</a>\n',
    )
    target.commit()
    result = target.check("--all", "--json")
    assert findings_of_rule(result, "coding.structural") == [("a.css", 2), ("a.html", 2)]
    assert sorted((item["path"], item["line"]) for item in report(result)["nocheck"]) == [("a.css", 1), ("a.html", 1)]


def test_html_under_templates_stays_html(target):
    target.write(
        "site/templates/static.html",
        "<script>\nconst pick = (a, d) => a || d(a);\nconst m = `${i-1}`;\n</script>\n",
    )
    target.write("app/templates/django.html", '<p>{{ value|default:"none" }}</p>\n')
    target.commit()
    assert "jinja" not in coverage(target.path)["kinds"]
    assert findings_of_rule(target.check("--all", "--json"), "clean.default-value") == []


DEFAULTS_FIXTURES = {
    "app.py": (
        "import os\n\n\ndef old(a=1):\n    return a\n"
        '\n\ndef new(a, b=2, *, c=None, d=False, e="", f=[], g=()):\n'
        "    return a, b, c, d, e, f, g\n"
        '\n\nport = os.environ.get("PORT", "8080")\n'
        'home = os.getenv("HOME", "")\n'
        'name = getattr(os, "name", "posix")\n'
        "# the operator picked three retries for the flaky host\n"
        'retries = os.getenv("RETRIES", default="3")\n'
        'label = os.environ.get("LABEL") or "none"\n'
        'parser.add_argument("--level", default="info")\n'
        'parser.add_argument("--flag", default=False)\n'
        'size = {}.get("size", 0)\n'
        "pick = lambda x=None, y=5: x\n"
    ),
    "run.sh": 'echo "${OLD:-1}"\n: "${NEW:=fallback}"\necho "${SET:?SET is required} ${BLANK:-} ${QUOTED:-""}"\n',
    "Makefile": "OLD ?= 1\nNEW ?= 2\nEMPTY ?=\nrun: ; echo $${PORT:-80} # port 80 is the fixed listen port\n",
    "lib.rs": (
        "fn main() {}\n"
        "fn port(v: Option<u16>) -> u16 { v.unwrap_or(8080) }\n"
        "fn name(v: Option<String>) -> String { v.unwrap_or_default() }\n"
        "fn flag(v: Option<bool>) -> bool { v.unwrap_or(false) }\n"
        "#[serde(default)]\n"
        "// v.unwrap_or(1) in a comment is no code\n"
    ),
    "schema.sql": (
        "CREATE TABLE t (id INT DEFAULT 0);\n"
        "CREATE TABLE u (n INT DEFAULT 5, note TEXT DEFAULT NULL, s TEXT DEFAULT '');\n"
        "INSERT INTO u DEFAULT VALUES; -- DEFAULT 7 in a comment\n"
    ),
    "main.tf": (
        'variable "old" {\n  default = 1\n}\n'
        'variable "port" {\n  default = 8080\n}\n'
        'variable "tags" {\n  default = {}\n}\n'
        "locals {\n  default = 3\n}\n"
    ),
    "web.ts": (
        "export function connect(host: string, port = 8080, tls = false) {\n"
        '  const { retries = 3, name = "" } = options;\n'
        "  const timeout = options.timeout ?? 30;\n"
        '  const label = options.label || "anon";\n'
        "  const flag = options.flag || other;\n"
        "  const empty = options.empty ?? null;\n"
        "  return [host, port, tls, retries, name, timeout, label, flag, empty];\n"
        "}\n"
        "const handler = (event, limit = 10) => limit;\n"
    ),
    "site.yml": (
        'port: "{{ app_port | default(8080) }}"\n'
        "user: \"{{ app_user | default('') }}\"\n"
        "home: \"{{ lookup('env', 'HOME') | default('') }}\"\n"
        'list: "{{ items | default([]) }}"\n'
        'cmd: "echo ${PORT:-80} ${EMPTY:-}"\n'
    ),
    "Store.java": (
        "class Store {\n"
        '  int port(java.util.Map<String, Integer> m) { return m.getOrDefault("port", 8080); }\n'
        '  Integer none(java.util.Map<String, Integer> m) { return m.getOrDefault("x", null); }\n'
        "}\n"
    ),
    "Svc.cs": (
        "class Svc {\n"
        "  void Run(int retries = 3, string name = null) { }\n"
        '  string Host(string h) => h ?? "localhost";\n'
        "  string Must(string h) => h ?? throw new System.ArgumentNullException(nameof(h));\n"
        "}\n"
    ),
    "Dockerfile": "FROM debian\nARG PORT\nRUN echo ${PORT:-80}\n",
    "compose.yml.j2": (
        "services:\n  app:\n"
        '    image: "app:${TAG:-latest}"\n'
        "    user: \"{{ app_user | default('root') }}\"\n"
    ),
    "ok.py": (
        "import os\n\n\n"
        'def f(a=None, b=False, c="", d=(), *, e=b"", g=frozenset()):\n'
        "    return a, b, c, d, e, g\n\n\n"
        'x = os.environ.get("K", "") or []\n'
        'y = {}.get("k", None)\n'
        'z = getattr(os, "x", None)\n'
        'w = os.getenv("W", default=False)\n'
    ),
    "ok.sh": 'echo "${A:-} ${B:-""} ${C:=}"\n',
    "ok.yml": "a: \"{{ x | default(false) }} {{ y | default(None) }} {{ z | default('') }}\"\n",
    "ok.ts": "function f(a = null, b = undefined, c = '') { return a ?? null; }\n",
    "ok.js": 'const m = `user || "<none>" on host ?? "n/a" as ${user ?? ""}`;\n',
    "wrap.js": 'const n = check(\n  a,\n)\n  || "x";\nconst o = p ??\n  "y";\n',
    "subst.js": (
        "const url = `${process.env.URL ?? 'http://localhost'}/api`;\n"
        "const port = `${process.env.PORT || 8080}`;\n"
        'const m = `user ${f(x || "y")} on ${`${host ?? "n/a"}`}`;\n'
    ),
    "subst.ts": "export const url: string = `${process.env.URL ?? 'http://localhost'}/api`;\n",
    "subst.tsx": "export const A = () => <a href={`${base || '/'}x`}>x</a>;\n",
    "quoted.yml": (
        'msg: "see #docs {{ port | default(8080) }}"\n'
        "# {{ x | default(1) }}\n"
        'key: "a #b" # {{ y | default(2) }}\n'
        "note: 'it''s # {{ z | default(3) }}'\n"
        'json: {"msg":"see #docs {{ port | default(8080) }}"}\n'
        'url: "http://h/#/x"  # {{ x | default(1) }}\n'
        "sq: 'x' # it's {{ x | default(1) }}\n"
        'bs: "x\\\\" # {{ x | default(1) }}\n'
        "ap: \"it's\" # {{ x | default(1) }}\n"
        "cut: cut -d':' -f2 /etc/passwd  # {{ x | default(1) }}\n"
        "ifs: IFS=':' read -r a b <<< \"$x\"  # {{ x | default(1) }}\n"
        "awk: awk -F'\":\"' '{print $2}' f.json  # {{ x | default(1) }}\n"
        "when: item.split(':')[0] == 1  # {{ x | default(1) }}\n"
        "cut_sq: cut -d' ' -f1 /etc/hosts  # {{ x | default(1) }}\n"
        'cut_dq: cut -d" " -f1 /etc/hosts  # {{ x | default(1) }}\n'
        "ifs_sq: IFS=' ' read -r a b <<< \"$x\"  # {{ x | default(1) }}\n"
        "split_sq: item.split(' ')[0] == 1  # {{ x | default(1) }}\n"
        'split_dq: item.split(" ")[0] == 1  # {{ x | default(1) }}\n'
        'starts: out.stdout.startswith(" ")  # {{ x | default(1) }}\n'
        "join: x | join(', ') == y  # {{ x | default(1) }}\n"
        "era: music from the '90s  # {{ x | default(1) }}\n"
        'flow: {"a" :"b #x {{ x | default(1) }}"}\n'
        "lookup: lookup('env', 'CI') | length > 0  # locally: ci | default(false)\n"
        "esc_sq: '{{ item.name | default('''') }}'\n"
        'esc_dq: "{{ item.name | default(\\"\\") }}"\n'
        "dollar: echo ${A:-x  # see }\n"
        "--- 'a # {{ x | default(1) }}'\n"
        '--- [a, "b # {{ x | default(1) }}"]\n'
    ),
}
DEFAULTS_HITS = {
    "Dockerfile": [3],
    "Makefile": [1, 2, 4],
    "Store.java": [2],
    "Svc.cs": [2, 3],
    "app.py": [4, 8, 12, 14, 16, 17, 18, 20, 21],
    "compose.yml.j2": [3, 4],
    "lib.rs": [2, 3, 5],
    "main.tf": [2, 5],
    "run.sh": [1, 2],
    "schema.sql": [1, 2],
    "quoted.yml": [1, 4, 5, 22, 27, 28],
    "site.yml": [1, 3, 5],
    "subst.js": [1, 2, 3],
    "subst.ts": [1],
    "subst.tsx": [1],
    "web.ts": [1, 2, 3, 4, 9],
    "wrap.js": [4, 5],
}


def test_defaults_parity(target):
    for name, text in DEFAULTS_FIXTURES.items():
        target.write(name, text)
    target.commit()
    found = set(findings_of_rule(target.check("--all", "--json"), "clean.default-value"))
    assert found == {(name, line) for name, lines in DEFAULTS_HITS.items() for line in lines}


DEFAULT_VALUE = "clean.default-value"
AVATAR_DEFAULTS = (
    "export const port = Number(process.env.AVATAR_PORT || 8765);\n"
    "export const host = process.env.AVATAR_HOST || '127.0.0.1';\n"
    "export const origin = process.env.AVATAR_PUBLIC_ORIGIN || `http://${host}:${port}`;\n"
    "export function neutralFrame(sequence = 0, timestampMs = 0) {\n"
    "  return {sequence, timestampMs};\n"
    "}\n"
    "export class TimingWindow {\n"
    "  constructor(limit = 10000) {\n"
    "    this.limit = limit;\n"
    "  }\n"
    "}\n"
)
AVATAR_REQUIRED = (
    "export function serverPort(env) {\n"
    "  if (typeof env.AVATAR_PORT !== 'string') throw new Error('AVATAR_PORT must be set in the Avatar process environment');\n"
    "  return Number(env.AVATAR_PORT);\n"
    "}\n"
    "export function receivedAt(packet) {\n"
    "  return packet?.receivedAt ?? null;\n"
    "}\n"
    "export class LatestFrame {\n"
    "  frame(neutralFrame) {\n"
    "    return this.current || neutralFrame(0, 0);\n"
    "  }\n"
    "}\n"
)


def test_default_value_flags_the_old_avatar_shapes(target, mode):
    target.write("seed.py", "x = 1\n")
    target.start_feature(mode)
    target.write("renderer/defaults.mjs", AVATAR_DEFAULTS)
    target.write("renderer/required.mjs", AVATAR_REQUIRED)
    target.advance(mode)
    result = target.judge(mode, "--json")
    assert result.returncode == 1, result.stderr
    found = sorted(
        {(item["path"], item["line"], item["severity"]) for item in report(result)["findings"] if item["rule"] == DEFAULT_VALUE}
    )
    assert found == [("renderer/defaults.mjs", line, "medium") for line in (1, 2, 3, 4, 8)]
    summary = next(rule["summary"] for rule in catalogue() if rule["id"] == DEFAULT_VALUE)
    assert "fail early" in summary and "names the missing key and where to set it" in summary
    text = target.judge(mode).stdout.splitlines()
    for line in (1, 2, 3, 4, 8):
        assert f"renderer/defaults.mjs:{line}: {DEFAULT_VALUE} [medium] {summary}" in text


def test_default_value_takes_a_nocheck_never_a_plain_comment(target, mode):
    target.write("seed.py", "x = 1\n")
    target.start_feature(mode)
    default = "export const port = process.env.AVATAR_PORT || 8765;"
    target.write("commented.mjs", f"{default} // the renderer listens on 8765 on a laptop\n")
    target.write("waived.mjs", f"{default} // nocheck: {DEFAULT_VALUE} -- the local renderer port\n")
    target.advance(mode)
    result = target.judge(mode, "--json")
    assert result.returncode == 1, result.stderr
    assert findings_of_rule(result, DEFAULT_VALUE) == [("commented.mjs", 1)]
    assert report(result)["nocheck"] == [{"path": "waived.mjs", "line": 1, "rule": DEFAULT_VALUE}]


FOCUSED = (
    "const { test } = require('@playwright/test');\n"
    "test.describe.only('suite', () => {});\n"
    "test.only('b', async () => {});\n"
    "describe.only('c', () => {});\n"
    "it.only('d', () => {});\n"
    "test.describe.serial.only('e', () => {});\n"
    "context.only('f', () => {});\n"
    "QUnit.only('g', () => {});\n"
    "QUnit.test.only('h', () => {});\n"
    "QUnit.module.only('i', () => {});\n"
    "bench.only('j', () => {});\n"
    "module.only('k', function (hooks) {});\n"
    "test.describe('kept', () => {});\n"
    "test('kept', () => {});\n"
    "x.only('kept');\n"
    "test.onlyIf('kept');\n"
    "settings.test.only();\n"
    "module.exports = { only: () => {} };\n"
    "module.exports.only();\n"
    "module.require('kept');\n"
)


def test_focused_test_flags_playwright_jest_mocha_qunit_and_vitest(target):
    names = [f"focus.spec.{suffix}" for suffix in ("js", "ts", "tsx")]
    for name in names:
        target.write(name, FOCUSED)
    target.commit()
    found = findings_of_rule(target.check("--all", "--json"), "coding.structural")
    assert found == sorted((name, line) for name in names for line in range(2, 13))


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
