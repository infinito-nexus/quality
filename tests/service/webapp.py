import copy
import json
import time
from pathlib import Path

from altcha import Challenge, Payload, solve_challenge
from quality_web import create_app

from tests.service.support import ROLE, ROOT

ORIGIN = "https://quality.example"
SECRET = "s" * 64
BASE = json.loads((ROOT / "service" / "dev" / "config.json").read_text(encoding="utf-8"))
OIDC = {
    "issuer": "https://login.example/realms/main",
    "client_id": "quality-check",
    "redirect_uri": f"{ORIGIN}/account/callback",
    "logout_redirect": f"{ORIGIN}/",
    "group_claim": "groups",
    "member_group": "/roles/web-app-cst-quality-check/member",
}


def build(tmp_path: Path, **changes):
    """
    Args:
        tmp_path: Directory for the state, the secret and the configuration.
        changes: Top-level configuration keys to replace, such as access or rate_limits.

    Returns:
        (Flask app, state directory).
    """
    state = tmp_path / "state"
    for name in ("spool", "reports", "claimed"):
        (state / name).mkdir(parents=True, exist_ok=True)
    secret = tmp_path / "secret"
    secret.write_text(SECRET, encoding="utf-8")
    settings = copy.deepcopy(BASE)
    settings.update(
        state_dir=str(state), legal_dir=str(ROLE / "files" / "legal"), secret_file=str(secret), public_url=ORIGIN
    )
    settings["limits"]["captcha_cost"] = 10
    settings["oidc"] = OIDC
    settings.update(copy.deepcopy(changes))
    config = tmp_path / "config.json"
    config.write_text(json.dumps(settings), encoding="utf-8")
    return create_app(str(config)), state


def solve(challenge_json: str) -> str:
    challenge = Challenge.from_dict(json.loads(challenge_json))
    solution = solve_challenge(challenge)
    return Payload(challenge, solution).to_base64()


def headers(address="203.0.113.7", **extra):
    """
    Args:
        address: X-Real-IP of the client; by default a TEST-NET-3 address (RFC 5737) that no real client has.
        extra: Further headers.
    """
    return {"X-Real-IP": address, "Origin": ORIGIN, **extra}


def text_job(**extra):
    return {"kind": "text", "language": "python", "text": "import os\n", **extra}


def queued(state: Path) -> list:
    return sorted(path.name for path in (state / "spool").iterdir() if not path.name.startswith("."))


def login(app, name="alice", member=False, created=None) -> str:
    """
    Args:
        app: Flask app whose login service holds the session.
        name: User name; "alice" by default, since only tests comparing two users need a second name.
        member: Whether the user holds the member group.
        created: Session start in epoch seconds; None means now.

    Returns:
        The session token.
    """
    login_service = app.extensions["quality"]["login"]
    token = f"token-{name}"
    login_service.sessions[token] = {"name": name, "member": member, "created": created or time.time()}
    return token


def session_cookie(token: str) -> dict:
    return {"Cookie": f"__Host-quality-session={token}"}
