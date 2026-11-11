import json
import re
import time

from tests.service.webapp import (
    build,
    headers,
    login,
    queued,
    session_cookie,
    solve,
    text_job,
)

ANONYMOUS_OFF = {"access": {"anonymous": False, "captcha": True}}
CAPTCHA_OFF = {"access": {"anonymous": True, "captcha": False}}


def limits(**values):
    base = {
        "anonymous_per_ip_hour": 100,
        "anonymous_hourly_total": 100,
        "per_host_hour": 100,
        "registered_per_user_hour": 100,
    }
    return {"rate_limits": {**base, **values}}


def challenge_of(client):
    page = client.get("/", headers=headers()).get_data(as_text=True)
    found = re.search(r'challenge="([^"]+)"', page)
    return found.group(1).replace("&#34;", '"').replace("&quot;", '"')


def test_missing_real_ip(tmp_path):
    app, _state = build(tmp_path)
    assert app.test_client(use_cookies=False).get("/").status_code == 400


def test_anonymous_needs_captcha(tmp_path):
    app, state = build(tmp_path)
    client = app.test_client(use_cookies=False)
    assert client.post("/submit", data=text_job(), headers=headers()).status_code == 403
    assert client.post("/submit", data=text_job(altcha="bm9wZQ=="), headers=headers()).status_code == 403
    payload = solve(challenge_of(client))
    assert client.post("/submit", data=text_job(altcha=payload), headers=headers()).status_code == 303
    assert client.post("/submit", data=text_job(altcha=payload), headers=headers()).status_code == 403
    assert len(queued(state)) == 1


def test_expired_captcha_refused(tmp_path, monkeypatch):
    app, state = build(tmp_path)
    client = app.test_client(use_cookies=False)
    payload = solve(challenge_of(client))
    later = time.time() + 3600
    monkeypatch.setattr(time, "time", lambda: later)
    assert client.post("/submit", data=text_job(altcha=payload), headers=headers()).status_code == 403
    assert queued(state) == []


def test_captcha_switch(tmp_path):
    app, state = build(tmp_path, **CAPTCHA_OFF, **limits(anonymous_per_ip_hour=1))
    client = app.test_client(use_cookies=False)
    page = client.get("/", headers=headers()).get_data(as_text=True)
    assert "altcha" not in page
    assert client.post("/submit", data=text_job(), headers=headers()).status_code == 303
    assert client.post("/submit", data=text_job(), headers=headers()).status_code == 429
    assert len(queued(state)) == 1


def test_registration_required(tmp_path):
    app, state = build(tmp_path, **ANONYMOUS_OFF)
    client = app.test_client(use_cookies=False)
    assert "<form" not in client.get("/", headers=headers()).get_data(as_text=True)
    assert client.post("/submit", data=text_job(), headers=headers()).status_code == 403
    token = login(app)
    response = client.post("/account/submit", data=text_job(), headers=headers(**session_cookie(token)))
    assert response.status_code == 303
    assert [name[0] for name in queued(state)] == ["1"]


def test_registered_rate_limit(tmp_path):
    app, _state = build(tmp_path, **limits(registered_per_user_hour=2))
    client = app.test_client(use_cookies=False)
    cookie = session_cookie(login(app))
    page = client.get("/account/", headers=headers(**cookie)).get_data(as_text=True)
    assert "altcha" not in page
    codes = [client.post("/account/submit", data=text_job(), headers=headers(**cookie)).status_code for _ in range(3)]
    assert codes == [303, 303, 429]


def test_anonymous_rate_limit(tmp_path):
    app, _state = build(tmp_path, **CAPTCHA_OFF, **limits(anonymous_per_ip_hour=1))
    client = app.test_client(use_cookies=False)
    assert client.post("/submit", data=text_job(), headers=headers("198.51.100.1")).status_code == 303
    assert client.post("/submit", data=text_job(), headers=headers("198.51.100.1")).status_code == 429
    assert client.post("/submit", data=text_job(), headers=headers("198.51.100.2")).status_code == 303
    assert client.post("/submit", data=text_job(), headers=headers("2001:db8::1")).status_code == 303
    assert client.post("/submit", data=text_job(), headers=headers("2001:db8::ffff")).status_code == 429


def test_anonymous_hourly_total(tmp_path):
    app, _state = build(tmp_path, **CAPTCHA_OFF, **limits(anonymous_hourly_total=2))
    client = app.test_client(use_cookies=False)
    codes = [
        client.post("/submit", data=text_job(), headers=headers(f"198.51.100.{index}")).status_code
        for index in range(1, 4)
    ]
    assert codes == [303, 303, 429]
    cookie = session_cookie(login(app, member=True))
    assert client.post("/account/submit", data=text_job(), headers=headers(**cookie)).status_code == 303


def test_target_host_limit(tmp_path):
    app, _state = build(tmp_path, **CAPTCHA_OFF, **limits(per_host_hour=1))
    client = app.test_client(use_cookies=False)
    job = {"kind": "url", "url": "https://example.org/a/b"}
    assert client.post("/submit", data=job, headers=headers("198.51.100.1")).status_code == 303
    assert client.post("/submit", data=job, headers=headers("198.51.100.2")).status_code == 429
    other = {"kind": "url", "url": "https://example.net/a/b"}
    assert client.post("/submit", data=other, headers=headers("198.51.100.3")).status_code == 303


def test_anonymous_queue_cap(tmp_path):
    app, _state = build(tmp_path, **CAPTCHA_OFF)
    app.extensions["quality"]["settings"]["limits"]["anonymous_queue"] = 1
    client = app.test_client(use_cookies=False)
    assert client.post("/submit", data=text_job(), headers=headers("198.51.100.1")).status_code == 303
    assert client.post("/submit", data=text_job(), headers=headers("198.51.100.2")).status_code == 429
    cookie = session_cookie(login(app, member=True))
    assert client.post("/account/submit", data=text_job(), headers=headers(**cookie)).status_code == 303


def test_member_no_quota(tmp_path):
    app, state = build(tmp_path, **limits(registered_per_user_hour=1, anonymous_hourly_total=1))
    client = app.test_client(use_cookies=False)
    cookie = session_cookie(login(app, member=True))
    codes = {client.post("/account/submit", data=text_job(), headers=headers(**cookie)).status_code for _ in range(5)}
    assert codes == {303}
    assert [name[0] for name in queued(state)] == ["0"] * 5


def test_forged_identity(tmp_path):
    app, _state = build(tmp_path, **ANONYMOUS_OFF)
    client = app.test_client(use_cookies=False)
    forged = headers(
        **{"X-Forwarded-User": "admin", "X-Forwarded-Groups": "/roles/web-app-cst-quality-check/member"},
        **session_cookie("unknown"),
    )
    assert client.post("/account/submit", data=text_job(), headers=forged).status_code == 403
    assert client.get("/account/", headers=forged).status_code == 302


def test_foreign_origin_refused(tmp_path):
    app, state = build(tmp_path)
    client = app.test_client(use_cookies=False)
    cookie = session_cookie(login(app, member=True))
    foreign = {**headers(**cookie), "Origin": "https://evil.example"}
    assert client.post("/account/submit", data=text_job(), headers=foreign).status_code == 403
    assert queued(state) == []


def test_null_origin_counts_only_from_the_same_origin(tmp_path):
    app, state = build(tmp_path)
    client = app.test_client(use_cookies=False)
    cookie = session_cookie(login(app, member=True))
    bare = {**headers(**cookie), "Origin": "null"}
    for refused in (bare, {**bare, "Sec-Fetch-Site": "cross-site"}):
        assert client.post("/account/submit", data=text_job(), headers=refused).status_code == 403
    assert queued(state) == []
    own = {**bare, "Sec-Fetch-Site": "same-origin"}
    assert client.post("/account/submit", data=text_job(), headers=own).status_code == 303
    assert len(queued(state)) == 1


def test_session_expires(tmp_path):
    app, _state = build(tmp_path)
    client = app.test_client(use_cookies=False)
    cookie = session_cookie(login(app, member=True, created=time.time() - 9 * 3600))
    assert client.post("/account/submit", data=text_job(), headers=headers(**cookie)).status_code == 403


def test_expired_sessions_and_past_counters_leave_memory(tmp_path):
    app, _state = build(tmp_path)
    expired = login(app, name="old", created=time.time() - 9 * 3600)
    live = login(app, name="new")
    limiter = app.extensions["quality"]["limiter"]
    stale = ("address", "past-hour", 0)
    limiter.counts[stale] = 1
    assert app.test_client(use_cookies=False).get("/healthz", headers=headers()).status_code == 200
    sessions = app.extensions["quality"]["login"].sessions
    assert expired not in sessions and live in sessions
    assert stale not in limiter.counts


def test_anonymous_visit_sets_no_cookie(tmp_path):
    app, _state = build(tmp_path)
    response = app.test_client(use_cookies=False).get("/", headers=headers())
    assert "Set-Cookie" not in response.headers


def test_report_link(tmp_path):
    app, state = build(tmp_path, **CAPTCHA_OFF)
    client = app.test_client(use_cookies=False)
    response = client.post("/submit", data=text_job(), headers=headers())
    job_id = response.headers["Location"].rsplit("/", 1)[-1]
    assert re.fullmatch(r"[0-9a-f]{32}", job_id)
    pending = client.get(f"/r/{job_id}", headers=headers())
    assert pending.status_code == 200
    assert 'http-equiv="refresh"' in pending.get_data(as_text=True)
    assert "The scan is queued." in pending.get_data(as_text=True)
    for path in (state / "spool").iterdir():
        path.unlink()
    (state / "reports" / f"{job_id}.running").write_text("", encoding="utf-8")
    assert "The scan is running." in client.get(f"/r/{job_id}", headers=headers()).get_data(as_text=True)
    unknown = client.get(f"/r/{'0' * 32}", headers=headers())
    assert unknown.status_code == 404
    assert unknown.headers["Referrer-Policy"] == "no-referrer"
    assert "noindex" in unknown.headers["X-Robots-Tag"]
    assert client.get("/r/", headers=headers()).status_code == 404
    assert client.get("/r/../spool", headers=headers()).status_code == 404


def test_report_escaped(tmp_path):
    app, state = build(tmp_path)
    finding = {
        "rule": "coding.unused-import",
        "path": "<script>alert(1)</script>.py",
        "line": 1,
        "severity": "medium",
        "summary": "Imported name is never used",
        "value": None,
        "commit": None,
    }
    result = {"findings": [finding], "ignored": [], "nocheck": [], "unchecked": [], "notes": [], "incomplete": []}
    document = {"status": "done", "reason": None, "kind": "file", "commit": None, "history": None}
    document.update(quality="local", database=None, result=result, finished=0)
    job_id = "a" * 32
    (state / "reports" / f"{job_id}.json").write_text(json.dumps(document), encoding="utf-8")
    page = app.test_client(use_cookies=False).get(f"/r/{job_id}", headers=headers()).get_data(as_text=True)
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page
    assert "<a href" not in page.split("<main>")[1].split("</main>")[0]


def test_failed_report_shows_not_checked(tmp_path):
    app, state = build(tmp_path)
    job_id = "b" * 32
    report = {"status": "failed", "reason": "timeout", "finished": 0}
    (state / "reports" / f"{job_id}.json").write_text(json.dumps(report), encoding="utf-8")
    page = app.test_client(use_cookies=False).get(f"/r/{job_id}", headers=headers()).get_data(as_text=True)
    assert "Not checked: timeout." in page
    assert "finding" not in page


def test_upload_limit(tmp_path):
    app, state = build(tmp_path, **CAPTCHA_OFF)
    app.extensions["quality"]["settings"]["limits"]["upload_bytes"] = 10
    client = app.test_client(use_cookies=False)
    response = client.post("/submit", data=text_job(text="x" * 11), headers=headers())
    assert response.status_code == 413
    assert queued(state) == []


def test_spool_full(tmp_path):
    app, state = build(tmp_path, **CAPTCHA_OFF)
    (state / "spool").chmod(0o500)
    try:
        response = app.test_client(use_cookies=False).post("/submit", data=text_job(), headers=headers())
    finally:
        (state / "spool").chmod(0o700)
    assert response.status_code == 429
