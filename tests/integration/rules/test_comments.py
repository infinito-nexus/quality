import re

import pytest
import yaml

from tests.integration.support import RULES, findings_of_rule, report

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
