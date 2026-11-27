import pytest

from tests.integration.support import findings_of_rule

PRIVATE = chr(0xE000)
WORKFLOW = ".github/workflows/ci.yml"

CASES = [
    (
        "security.workflow-fork-checkout",
        WORKFLOW,
        "on:\n  pull_request_target:\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n"
        "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n",
        "on:\n  pull_request:\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n"
        "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n",
        8,
    ),
    ("security.sudo-preserve-env", "run.sh", "#!/bin/bash\nsudo -E make install\n", "#!/bin/bash\nsudo --preserve-env=PATH make install\n", 2),
    ("clean.private-use-char", "notes.md", f"# Notes\n\nA {PRIVATE} b.\n", "# Notes\n\nA b.\n", 3),
    ("coding.workflow-runner-latest", WORKFLOW, "jobs:\n  a:\n    runs-on: ubuntu-latest\n", "jobs:\n  a:\n    runs-on: ubuntu-24.04\n", 3),
    ("coding.shell-or-true", "run.sh", "#!/bin/bash\nrm -f x || true\n", "#!/bin/bash\n# rm -f x || true\nrm -f x\n", 2),
    ("coding.empty-except", "a.py", "try:\n    f()\nexcept Exception:\n    pass\n", "try:\n    f()\nexcept Exception:\n    g()\n", 3),
    ("coding.workflow-timeout", WORKFLOW, "jobs:\n  a:\n    timeout-minutes: 360\n", "jobs:\n  a:\n    timeout-minutes: 355\n", 3),
    ("coding.dockerfile-syntax-directive", "Dockerfile", "# syntax=docker/dockerfile:1\nFROM alpine:3.20\n", "FROM alpine:3.20\n", 1),
    ("coding.distro-codename-tag", "Dockerfile", "FROM debian:bookworm-slim\n", "FROM debian:12.8-slim\n", 1),
    ("coding.timeout-foreground", "a.py", "ARGV = ['timeout', '5', 'make']\n", "ARGV = ['timeout', '--foreground', '5', 'make']\nLIMIT = SPEC['timeout']\n", 1),  # nocheck: coding.timeout-foreground -- the rule's own hit fixture
    ("clean.line-reference", "notes.md", "# Notes\n\nSee [run](src/run.py#L12).\n", "# Notes\n\nSee [run](src/run.py) and [host](http://localhost:8080).\n", 3),
    ("clean.todo-without-link", "a.py", "x = 1\n# TODO drop this\n", "x = 1\n# TODO https://example.org/issues/1\n", 2),
    ("clean.default-value", "Dockerfile", "FROM alpine:3.20\nARG TAG=latest\n", 'FROM alpine:3.20\nARG TAG\nARG MODE=""\n', 2),
]


@pytest.mark.parametrize("case", CASES, ids=[case[0] for case in CASES])
def test_a_pattern_rule_hits_its_line_and_not_the_control(target, case):
    rule, path, hit, clean, line = case
    target.write(path, hit)
    target.stage()
    assert findings_of_rule(target.check("--staged", "--json"), rule) == [(path, line)]
    target.write(path, clean)
    target.stage()
    assert findings_of_rule(target.check("--staged", "--json"), rule) == []


def test_a_nocheck_waives_a_pattern_rule(target):
    target.write("run.sh", "#!/bin/bash\nrm -f x || true  # nocheck: coding.shell-or-true -- x may be absent\n")
    target.stage()
    assert findings_of_rule(target.check("--staged", "--json"), "coding.shell-or-true") == []
