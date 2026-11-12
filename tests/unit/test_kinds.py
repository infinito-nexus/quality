from pathlib import Path

import pytest

from quality.ruledata import load

KINDS = load(Path(__file__).resolve().parents[2] / "rules").kinds
BASH = b"#!/bin/bash\n"


@pytest.mark.parametrize(
    ("path", "first_line", "expected"),
    [
        ("deploy", BASH, {"shell"}),
        ("deploy", b"#!/usr/bin/env -S python3 -u\n", {"python"}),
        ("deploy", b"echo hi\n", set()),
        ("run.sh", b"#!/usr/bin/env python3\n", {"shell"}),
        ("deploy.sh.j2", b"", {"jinja", "shell"}),
        ("deploy.sh.J2", b"", {"jinja", "shell"}),
        ("site.yml.Jinja2", b"", {"jinja", "yaml"}),
        ("run.JINJA", BASH, {"jinja", "shell"}),
        ("compose.yml.j2", b"", {"jinja", "yaml"}),
        ("run.j2", BASH, {"jinja", "shell"}),
        ("a.j2.j2", BASH, {"jinja", "shell"}),
        ("Dockerfile", b"FROM scratch\n", {"dockerfile"}),
        ("Dockerfile.j2", b"", {"dockerfile", "jinja"}),
        ("nginx.conf", b"", {"conf", "nginx"}),
        (".env", b"", {"env"}),
        (".github/workflows/ci.yml", b"", {"workflow", "yaml"}),
    ],
)
def test_kinds_of(path, first_line, expected):
    assert KINDS.kinds_of(path, first_line) == frozenset(expected)


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("deploy.sh.j2", {"jinja"}),
        ("deploy.sh.J2", {"jinja"}),
        ("Dockerfile.j2", {"jinja"}),
        ("run.sh", {"shell"}),
    ],
)
def test_parsing_tools_see_no_inner_type(path, expected):
    assert KINDS.parsed_kinds(path, KINDS.kinds_of(path, BASH)) == frozenset(expected)


@pytest.mark.parametrize(
    ("path", "needs"),
    [("deploy", True), ("run.j2", True), ("run.sh.j2", False), ("run.sh", False)],
)
def test_first_line_read_only_without_inner_extension(path, needs):
    assert KINDS.needs_first_line(path) is needs


@pytest.mark.parametrize(
    ("path", "code"),
    [("big.py", True), ("tool", True), ("deploy.sh.j2", True), ("site.yml.j2", False), ("data.json", False)],
)
def test_code_name_follows_the_inner_type(path, code):
    assert KINDS.code_name(path) is code
