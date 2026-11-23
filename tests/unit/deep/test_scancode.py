import json

import pytest

from quality import QualityError
from quality.adapters import bind_files, scancode
from quality.adapters.base import Command
from quality.legal.checks import NO_SCAN, REASONS, split_unchecked, unchecked_notes
from tests.unit.deep.support import DATA, bound_of, snapshot_of

ORIGIN = "legal.foreign-origin"
COPYRIGHT = "legal.foreign-copyright"
TIMEOUT = "ERROR: for scanner: licenses:\nERROR: Processing interrupted: timeout after 120 seconds."
CRASH = "ERROR: for scanner: licenses:\nTraceback (most recent call last):\nValueError: boom"
MIT = "MIT License\n\nCopyright (c) 2026 Example Project\n"


def entry(index: int, name: str, errors: list) -> dict:
    return {"path": f"{index}/{name}", "type": "file", "scan_errors": errors, "license_detections": [], "holders": []}


def report(files: list, header_errors: list) -> bytes:
    return json.dumps({"headers": [{"errors": header_errors}], "license_rule_references": [], "files": files}).encode()


def judged(snapshot, files: dict, document: bytes) -> list:
    bound = [bound_of(ORIGIN, "scancode", files), bound_of(COPYRIGHT, "scancode", files)]
    return scancode.parse(document, Command([], list(files), bound), snapshot)


def test_scancode_never_receives_a_gettext_catalogue():
    kinds = {"a.py": frozenset({"python"}), "locale/de/docs.po": frozenset(), "messages.pot": frozenset()}
    bound = bind_files(DATA, DATA.bindings()["scancode"], kinds, lambda _rule: True)
    assert sorted((item.binding.rule.id, item.files) for item in bound) == [(COPYRIGHT, ["a.py"]), (ORIGIN, ["a.py"])]


def test_a_scancode_timeout_leaves_the_file_unchecked(tmp_path):
    snapshot = snapshot_of(tmp_path, {"a.py": "y = 1\n"})
    files = {"a.py": "python"}
    hits = judged(snapshot, files, report([entry(0, "file.py", [TIMEOUT])], ["Path: in/0/file.py"]))
    findings, undecided = split_unchecked(hits)
    assert findings == []
    assert sorted((hit.rule.id, hit.path, hit.line, hit.ids) for hit in undecided) == [
        (COPYRIGHT, "a.py", None, frozenset({NO_SCAN})),
        (ORIGIN, "a.py", None, frozenset({NO_SCAN})),
    ]
    assert unchecked_notes(undecided) == [f"unchecked: a.py: {REASONS[NO_SCAN]}"]


def test_a_timed_out_licence_file_leaves_the_holders_of_its_files_unchecked(tmp_path):
    snapshot = snapshot_of(tmp_path, {"LICENSE": MIT, "a.py": "# Copyright (c) 2026 Someone\ny = 1\n"})
    files = {"a.py": "python"}
    scanned = entry(0, "file.py", [])
    scanned["holders"] = [{"holder": "Someone", "start_line": 1}]
    document = report([scanned, entry(1, "file", [TIMEOUT])], ["Path: in/1/file"])
    hits = judged(snapshot, files, document)
    assert [(hit.rule.id, hit.path, hit.ids) for hit in hits] == [(COPYRIGHT, "a.py", frozenset({NO_SCAN}))]


@pytest.mark.parametrize(
    ("errors", "header_errors", "message"),
    [
        ([CRASH], ["Path: in/0/file.py"], "^scancode could not scan a file, so it stays unchecked$"),
        ([TIMEOUT, CRASH], ["Path: in/0/file.py"], "^scancode could not scan a file, so it stays unchecked$"),
        ([TIMEOUT], ["Path: in/0/file.py", "Timeout waiting for resource. Path unknown."], "^scancode reported an error"),
        ([], ["Path: in/0/file.py"], "^scancode reported an error"),
    ],
    ids=["other-error", "timeout-and-other-error", "codebase-error", "header-only"],
)
def test_any_scancode_error_but_a_timeout_aborts_the_run(tmp_path, errors, header_errors, message):
    snapshot = snapshot_of(tmp_path, {"a.py": "y = 1\n"})
    with pytest.raises(QualityError, match=message):
        judged(snapshot, {"a.py": "python"}, report([entry(0, "file.py", errors)], header_errors))


def test_a_scancode_run_without_a_report_aborts_the_run(tmp_path):
    snapshot = snapshot_of(tmp_path, {"a.py": "y = 1\n"})
    with pytest.raises(QualityError, match="^scancode wrote no report, so its files stay unchecked$"):
        judged(snapshot, {"a.py": "python"}, b"")
