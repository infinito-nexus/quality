from collections import Counter

import pytest

from quality.adapters import builtin

JOB = "    runs-on: ubuntu-latest\n    steps:\n      - &step\n        name: s\n        run: echo 1\n"
REFERENCES = 200


@pytest.fixture
def scans(monkeypatch):
    calls = Counter()
    for name in ("mapping_items", "sequence_items"):
        original = getattr(builtin, name)

        def counted(node, name=name, original=original):
            calls[name] += 1
            return original(node)

        monkeypatch.setattr(builtin, name, counted)
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
