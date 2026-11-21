import base64
import json

import pytest

from tests.service.support import (
    ACCEPTED_URLS,
    FINDING,
    REJECTED_URLS,
    REPORT,
    load_launcher,
)

launcher = load_launcher()


@pytest.mark.parametrize("url", ACCEPTED_URLS)
def test_url_validation_accepts(url):
    assert launcher.valid_url(url)


@pytest.mark.parametrize("url", REJECTED_URLS)
def test_url_validation_rejects(url):
    assert not launcher.valid_url(url)


@pytest.mark.parametrize(
    ("name", "expected"),
    [("../../x.py", "x.py"), (".git/config", "config"), ("a\nb.py", "a_b.py"), ("..\\..\\y.sh", "y.sh"), ("", "upload")],
)
def test_filename_normalised(name, expected):
    assert launcher.safe_name(name) == expected


def encoded(data):
    return base64.b64encode(data).decode()


def test_parse_job_kinds():
    url = launcher.parse_job(json.dumps({"kind": "url", "url": "https://example.org/a"}), 10)
    assert url == {"kind": "url", "url": "https://example.org/a"}
    text = launcher.parse_job(json.dumps({"kind": "text", "language": "python", "content": encoded(b"x")}), 10)
    assert text["name"] == "snippet.py"
    upload = launcher.parse_job(json.dumps({"kind": "file", "name": "../a.py", "content": encoded(b"x")}), 10)
    assert upload["name"] == "a.py"


@pytest.mark.parametrize(
    ("job", "reason"),
    [
        ({"kind": "url", "url": "http://example.org/a"}, "invalid url"),
        ({"kind": "shell"}, "invalid job"),
        ({"kind": "text", "language": "cobol", "content": encoded(b"x")}, "invalid language"),
        ({"kind": "file", "name": "a", "content": "!!"}, "invalid content"),
        ({"kind": "file", "name": "a", "content": encoded(b"x" * 11)}, "too large"),
        ({"kind": "url", "url": "https://example.org/a", "image": "evil"}, None),
    ],
)
def test_parse_job_refuses(job, reason):
    if reason is None:
        assert "image" not in launcher.parse_job(json.dumps(job), 10)
        return
    with pytest.raises(launcher.JobFailed, match=reason):
        launcher.parse_job(json.dumps(job), 10)


def test_parse_job_deep_nesting_raises():
    with pytest.raises((RecursionError, launcher.JobFailed)):
        launcher.parse_job("[" * 100000 + "]" * 100000, 10)


def report(**changes):
    return {**REPORT, "findings": [dict(FINDING)], **changes}


def test_report_schema_accepts_runner_output():
    assert launcher.fits(report(), launcher.REPORT)
    ignored = [{"rule": "clean.folder-items", "paths": ["."], "reason": "why"}]
    nocheck = [{"path": "a.py", "line": 3, "rule": "x"}]
    assert launcher.fits(report(ignored=ignored, nocheck=nocheck), launcher.REPORT)
    assert launcher.fits(report(findings=[{**FINDING, "lens": "SRP"}], architecture=75), launcher.REPORT)
    assert launcher.fits(report(legal=50, legal_blockers=1, legal_unchecked=2), launcher.REPORT)


@pytest.mark.parametrize(
    "document",
    [
        report(extra=1),
        report(findings=[{"rule": "r"}]),
        report(findings=[{**report()["findings"][0], "line": True}]),
        report(findings=[{**report()["findings"][0], "severity": "fatal"}]),
        report(findings=[{**report()["findings"][0], "message": "leak"}]),
        report(findings=[{**report()["findings"][0], "lens": 1}]),
        report(architecture="100"),
        report(architecture=True),
        {key: value for key, value in report().items() if key != "architecture"},
        report(legal="100"),
        report(legal=True),
        report(legal_blockers=True),
        report(legal_unchecked="1"),
        report(legal_unchecked=1.0),
        *({key: value for key, value in report().items() if key != name} for name in ("legal", "legal_blockers", "legal_unchecked")),
        report(notes=[1]),
        report(findings={}),
        [],
    ],
)
def test_report_schema_refuses(document):
    assert not launcher.fits(document, launcher.REPORT)


def test_job_file_name_orders_members_first():
    names = [launcher.job_file_name(tier, "a" * 32) for tier in ("anonymous", "member", "registered")]
    assert sorted(names)[0].startswith("0-")
    assert all(launcher.JOB_FILE.match(name) for name in names)
