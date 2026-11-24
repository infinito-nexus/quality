from flask import Flask, abort, render_template, request
from jinja2 import ChoiceLoader, FileSystemLoader, PrefixLoader

from quality_web import i18n
from quality_web.access import Limiter, client_address
from quality_web.captcha import Captcha
from quality_web.login import Login
from quality_web.pages import pages
from quality_web.settings import load
from quality_web.spool import Spool

FORM_OVERHEAD_BYTES = 65536
ERRORS = (400, 403, 404, 413, 429)
SECURITY_HEADERS = {
    "Referrer-Policy": "no-referrer",
    "X-Robots-Tag": "noindex, nofollow",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": (
        "default-src 'self'; worker-src 'self'; img-src 'self'; frame-ancestors 'none'; "
        "base-uri 'none'; form-action 'self'"
    ),
}


def create_app(config_path):
    """
    Args:
        config_path: JSON configuration of the web app.

    Returns:
        The Flask application.
    """
    settings = load(config_path)
    app = Flask(__name__)
    app.jinja_env.autoescape = True
    upload = settings["limits"]["upload_bytes"]
    app.config.update(MAX_CONTENT_LENGTH=upload * 2 + FORM_OVERHEAD_BYTES, MAX_FORM_MEMORY_SIZE=upload + FORM_OVERHEAD_BYTES)
    app.extensions["quality"] = {
        "settings": settings,
        "limiter": Limiter(settings["secret"]),
        "captcha": Captcha(settings),
        "login": Login(settings),
        "spool": Spool(settings),
        "languages": i18n.load(i18n.LOCALE),
    }
    legal = PrefixLoader({"legal": FileSystemLoader(settings["legal_dir"])})
    app.jinja_env.loader = ChoiceLoader([app.jinja_env.loader, legal])
    app.before_request(i18n.choose_language)
    app.before_request(require_address)
    app.after_request(secure)
    app.after_request(i18n.vary)
    app.context_processor(i18n.language_context)
    for code in ERRORS:
        app.register_error_handler(code, message)
    app.register_blueprint(pages)
    return app


def require_address():
    address = client_address(request.headers.get("X-Real-IP"))
    if address is None:
        abort(400)
    request.environ["quality.address"] = address


def secure(response):
    response.headers.update(SECURITY_HEADERS)
    return response


def message(error):
    return render_template("message.html.j2", key=f"error.{error.code}"), error.code
