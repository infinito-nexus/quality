import base64
import os
from urllib.parse import urlsplit

import launcher
from flask import (
    Blueprint,
    abort,
    current_app,
    redirect,
    render_template,
    request,
    url_for,
)
from markupsafe import Markup

from quality_web.spool import SpoolFull

SESSION_COOKIE = "__Host-quality-session"
LOGIN_COOKIE = "__Host-quality-login"
LOGIN_COOKIE_SECONDS = 600
LEGAL_LANGUAGES = ("en", "de")

pages = Blueprint("pages", __name__)


def quality():
    return current_app.extensions["quality"]


def current_user():
    return quality()["login"].identity(request.cookies.get(SESSION_COOKIE))


@pages.app_context_processor
def page_context():
    return {"user": current_user(), "login_available": quality()["login"].available}


def form_context(tier):
    settings = quality()["settings"]
    captcha = tier == "anonymous" and settings["access"]["captcha"]
    endpoint = "pages.submit_anonymous" if tier == "anonymous" else "pages.submit_account"
    return {
        "action": url_for(endpoint),
        "challenge": quality()["captcha"].challenge() if captcha else None,
        "languages": sorted(launcher.LANGUAGES),
        "upload_bytes": settings["limits"]["upload_bytes"],
    }


@pages.get("/healthz")
def health():
    return "ok"


@pages.get("/")
def index():
    anonymous = quality()["settings"]["access"]["anonymous"]
    return render_template("index.html", form=form_context("anonymous") if anonymous else None)


@pages.get("/account/")
def account():
    user = current_user()
    if user is None:
        return redirect(url_for("pages.login"))
    return render_template("index.html", form=form_context("member" if user["member"] else "registered"))


def require_origin():
    expected = quality()["settings"]["public_url"].rstrip("/")
    origin = request.headers.get("Origin", "").rstrip("/")
    if origin == expected:
        return
    # Exception: Referrer-Policy no-referrer makes browsers send Origin: null on this site's own form posts;
    # Sec-Fetch-Site comes from the browser alone, so it still tells those apart from a sandboxed or foreign page
    if origin == "null" and request.headers.get("Sec-Fetch-Site") == "same-origin":
        return
    abort(403)


def content_job(job, data):
    if len(data) > quality()["settings"]["limits"]["upload_bytes"]:
        abort(413)
    if not data:
        abort(400)
    return {**job, "content": base64.b64encode(data).decode("ascii")}


def read_job():
    kind = request.form.get("kind")
    if kind == "url":
        url = request.form.get("url", "").strip()
        if not launcher.valid_url(url):
            abort(400)
        return {"kind": "url", "url": url}
    if kind == "text":
        language = request.form.get("language")
        if language not in launcher.LANGUAGES:
            abort(400)
        return content_job({"kind": "text", "language": language}, request.form.get("text", "").encode())
    upload = request.files.get("file")
    if kind != "file" or upload is None:
        abort(400)
    data = upload.stream.read(quality()["settings"]["limits"]["upload_bytes"] + 1)
    return content_job({"kind": "file", "name": launcher.safe_name(upload.filename or "")}, data)


def enqueue(tier, job):
    try:
        job_id = quality()["spool"].submit(tier, job)
    except SpoolFull:
        abort(429)
    return redirect(url_for("pages.report", job_id=job_id), code=303)


@pages.post("/submit")
def submit_anonymous():
    settings = quality()["settings"]
    require_origin()
    if not settings["access"]["anonymous"]:
        abort(403)
    if settings["access"]["captcha"] and not quality()["captcha"].verify(request.form.get("altcha")):
        abort(403)
    job = read_job()
    if quality()["spool"].anonymous_queued() >= settings["limits"]["anonymous_queue"]:
        abort(429)
    limits = settings["rate_limits"]
    checks = [
        ("address", request.environ["quality.address"], limits["anonymous_per_ip_hour"]),
        ("total", "anonymous", limits["anonymous_hourly_total"]),
    ]
    if job["kind"] == "url":
        checks.append(("host", urlsplit(job["url"]).hostname, limits["per_host_hour"]))
    if not quality()["limiter"].allow(checks):
        abort(429)
    return enqueue("anonymous", job)


@pages.post("/account/submit")
def submit_account():
    require_origin()
    user = current_user()
    if user is None:
        abort(403)
    job = read_job()
    if user["member"]:
        return enqueue("member", job)
    limit = quality()["settings"]["rate_limits"]["registered_per_user_hour"]
    if not quality()["limiter"].allow([("user", user["name"], limit)]):
        abort(429)
    return enqueue("registered", job)


@pages.get("/r/<job_id>")
def report(job_id):
    state, document = quality()["spool"].status(job_id)
    if state is None:
        abort(404)
    if state == "report":
        return render_template("report.html", report=document)
    return render_template("pending.html", state=state)


@pages.get("/<any(privacy, terms):page>")
def legal(page):
    # Exception: the footer links carry no ?lang= and sit on pages written in English, so they open the English text
    language = request.args.get("lang", "en")
    if language not in LEGAL_LANGUAGES:
        abort(404)
    path = os.path.join(quality()["settings"]["legal_dir"], language, f"{page}.html")
    with open(path, encoding="utf-8") as handle:
        return render_template("legal.html", body=Markup(handle.read()))


@pages.get("/notices")
def notices():
    return render_template("notices.html")


@pages.get("/account/login")
def login():
    if not quality()["login"].available:
        abort(404)
    flow_id, url = quality()["login"].start()
    response = redirect(url)
    response.set_cookie(
        LOGIN_COOKIE, flow_id, max_age=LOGIN_COOKIE_SECONDS, secure=True, httponly=True, samesite="Lax", path="/"
    )
    return response


@pages.get("/account/callback")
def callback():
    if not quality()["login"].available:
        abort(404)
    flow_id = request.cookies.get(LOGIN_COOKIE)
    token = quality()["login"].finish(flow_id, request.args.get("state"), request.args.get("code"))
    if token is None:
        abort(403)
    response = redirect(url_for("pages.account"))
    response.delete_cookie(LOGIN_COOKIE, path="/", secure=True, httponly=True, samesite="Lax")
    seconds = quality()["settings"]["limits"]["session_hours"] * 3600
    response.set_cookie(SESSION_COOKIE, token, max_age=seconds, secure=True, httponly=True, samesite="Lax", path="/")
    return response


@pages.get("/account/logout")
def logout():
    if not quality()["login"].available:
        abort(404)
    response = redirect(quality()["login"].logout(request.cookies.get(SESSION_COOKIE)))
    response.delete_cookie(SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="Lax")
    return response
