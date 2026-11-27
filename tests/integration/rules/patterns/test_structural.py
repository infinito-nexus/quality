import pytest

from tests.integration.support import findings_of_rule

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
