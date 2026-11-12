import base64
import json

import pytest

from tests.service.support import load_launcher

launcher = load_launcher()

ACCEPTED = ["https://example.org/a/b", "https://git.example.co.uk/owner/repo.git", "https://example.org:443/a"]
REJECTED = [
    "http://example.org/a/b",
    "ssh://example.org/a/b",
    "file:///etc/passwd",
    "ext::sh -c id",
    "/a/b",
    "https://user@example.org/a/b",
    "https://user:secret@example.org/a/b",
    "https://example.org:8443/a/b",
    "https://127.0.0.1/a/b",
    "https://[::1]/a/b",
    "https://2130706433/a/b",
    "https://0x7f.1/a/b",
    "https://localhost/a/b",
    "https://example.org/a/b?x=1",
    "https://example.org/a/b#x",
    "-https://example.org/a/b",
    "https://example.org",
    "https://example.org/a b",
    "https://example.org/%2e%2e/b",
    "https://-example.org/a",
    "https://example.123/a",
    "https://EXAMPLE.org/a",
]


@pytest.mark.parametrize("url", ACCEPTED)
def test_url_validation_accepts(url):
    assert launcher.valid_url(url)


@pytest.mark.parametrize("url", REJECTED)
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
    with pytest.raises(RecursionError):
        launcher.parse_job("[" * 100000 + "]" * 100000, 10)


def report(**changes):
    finding = {"rule": "r", "path": "p", "line": 1, "severity": "high", "summary": "s", "value": None, "commit": None}
    document = {"findings": [finding], "ignored": [], "nocheck": [], "unchecked": [], "notes": [], "incomplete": []}
    document["parse_incomplete"] = []
    document.update(changes)
    return document


def test_report_schema_accepts_runner_output():
    assert launcher.fits(report(), launcher.REPORT)
    ignored = [{"rule": "clean.folder-items", "paths": ["."], "reason": "why"}]
    nocheck = [{"path": "a.py", "line": 3, "rule": "x"}]
    assert launcher.fits(report(ignored=ignored, nocheck=nocheck), launcher.REPORT)


@pytest.mark.parametrize(
    "document",
    [
        report(extra=1),
        report(findings=[{"rule": "r"}]),
        report(findings=[{**report()["findings"][0], "line": True}]),
        report(findings=[{**report()["findings"][0], "severity": "fatal"}]),
        report(findings=[{**report()["findings"][0], "message": "leak"}]),
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
