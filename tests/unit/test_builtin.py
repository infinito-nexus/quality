from collections import Counter

import pytest

from quality.adapters import builtin
from quality.legal.index import license_of
from quality.legal.spdx import allowed

PERMISSIVE = {"MIT", "ISC", "Apache-2.0"}
JOB = "    runs-on: ubuntu-latest\n    steps:\n      - &step\n        name: s\n        run: echo 1\n"
REFERENCES = 200


def counting(calls: Counter, name: str, original):
    def counted(node):
        calls[name] += 1
        return original(node)

    return counted


@pytest.fixture
def scans(monkeypatch):
    calls = Counter()
    for name in ("mapping_items", "sequence_items"):
        monkeypatch.setattr(builtin, name, counting(calls, name, getattr(builtin, name)))
    return calls


def test_aliased_jobs_are_scanned_once(scans):
    aliases = "".join(f"  j{index}: *job\n" for index in range(REFERENCES))
    document = f"on: push\njobs:\n  a: &job\n{JOB}{aliases}"
    assert len(builtin.workflow_scripts(document.encode())) == 1
    assert scans["mapping_items"] < 10


def test_aliased_steps_are_scanned_once(scans):
    aliases = "".join("      - *step\n" for _ in range(REFERENCES))
    document = f"on: push\njobs:\n  a:\n{JOB}{aliases}"
    assert len(builtin.workflow_scripts(document.encode())) == 1
    assert scans["mapping_items"] < 10


def test_shared_step_lists_are_scanned_once(scans):
    lists = "".join(f"  j{index}:\n    steps: *steps\n" for index in range(REFERENCES))
    document = (
        "on: push\njobs:\n  a:\n    steps: &steps\n      - name: s\n        run: echo 1\n"
        f"{lists}"
    )
    assert len(builtin.workflow_scripts(document.encode())) == 1
    assert scans["sequence_items"] == 1


def test_invalid_yaml_yields_nothing():
    assert builtin.workflow_scripts(b"jobs: [unclosed\n") == []


@pytest.mark.parametrize(
    ("script", "expected"),
    [
        ("echo 1\necho 2\n", 2),
        ("\n# note\n  \necho 1\n", 1),
        ("echo a \\\n  b \\\n  c\necho d\n", 2),
        ("# comment \\\necho 1\n", 1),
    ],
)
def test_logical_lines(script, expected):
    assert builtin.logical_lines(script) == expected


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("report_a.txt", "report"),
        ("report-b.txt", "report"),
        ("__init__.py", None),
        ("2026_a.md", None),
        ("test_a.py", None),
        ("-a.txt", None),
        ("plain.txt", None),
    ],
)
def test_name_prefix(name, expected):
    assert builtin.name_prefix(name, ["test"]) == expected


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ("MIT", True),
        ("GPL-3.0-only", False),
        ("MIT OR GPL-3.0-only", True),
        ("MIT AND GPL-3.0-only", False),
        ("GPL-3.0-only AND (MIT OR ISC)", False),
        ("(GPL-3.0-only AND MIT) OR ISC", True),
        ("Apache-2.0 WITH LLVM-exception", True),
        ("mit or isc", False),
        ("MIT OR", None),
        ("(MIT", None),
        ("MIT ISC", None),
        ("", None),
    ],
)
def test_allowed_evaluates_the_spdx_expression(expression, expected):
    assert allowed(expression, PERMISSIVE) == expected


def test_license_of_prefers_the_release_then_the_shared_licence():
    packages = {"npm": {"a": {"1.0.0": "GPL-3.0-only", "*": "MIT"}, "b": {"2.0.0": "ISC"}, "c": {"*": 7}}}
    assert license_of(packages, "npm", "a", "1.0.0") == "GPL-3.0-only"
    assert license_of(packages, "npm", "a", "2.0.0") == "MIT"
    assert license_of(packages, "npm", "a", "") == "MIT"
    assert license_of(packages, "npm", "b", "") is None
    assert license_of(packages, "npm", "c", "") is None
    assert license_of(packages, "PyPI", "a", "1.0.0") is None
    assert license_of(None, "npm", "a", "1.0.0") is None
