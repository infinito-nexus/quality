from quality.ruledata import load
from tests.integration.support import (
    ROOT,
    UNTAGGED_DOCKERFILE,
    coverage,
    edit_yaml,
    findings_of_rule,
    raw_tool,
    report,
    rule_ids,
    rules_copy,
)

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


def test_html_under_templates_stays_html(target):
    target.write(
        "site/templates/static.html",
        "<script>\nconst pick = (a, d) => a || d(a);\nconst m = `${i-1}`;\n</script>\n",
    )
    target.write("app/templates/django.html", '<p>{{ value|default:"none" }}</p>\n')
    target.commit()
    assert "jinja" not in coverage(target.path)["kinds"]
    assert findings_of_rule(target.check("--all", "--json"), "clean.default-value") == []
