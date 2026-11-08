from flask import Flask, abort, render_template, request

from quality_web.access import Limiter, client_address
from quality_web.captcha import Captcha
from quality_web.login import Login
from quality_web.pages import pages
from quality_web.settings import load
from quality_web.spool import Spool

FORM_OVERHEAD_BYTES = 65536
MESSAGES = {
    400: "The submission is not valid.",
    403: "The submission was refused.",
    404: "There is no such page or report.",
    413: "The submission is larger than the upload limit.",
    429: "Too many submissions right now. Please try again later.",
}
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
    upload = settings["limits"]["upload_bytes"]
    app.config.update(MAX_CONTENT_LENGTH=upload * 2 + FORM_OVERHEAD_BYTES, MAX_FORM_MEMORY_SIZE=upload + FORM_OVERHEAD_BYTES)
    app.extensions["quality"] = {
        "settings": settings,
        "limiter": Limiter(settings["secret"]),
        "captcha": Captcha(settings),
        "login": Login(settings),
        "spool": Spool(settings),
    }
    app.before_request(require_address)
    app.after_request(secure)
    for code in MESSAGES:
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
    return render_template("message.html", text=MESSAGES[error.code]), error.code
