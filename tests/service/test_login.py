import time
from urllib.parse import parse_qs, urlsplit

import pytest
from authlib.integrations.requests_client import OAuth2Session
from joserfc import jwt
from joserfc.jwk import KeySet, RSAKey

from tests.service.webapp import OIDC, build, headers, session_cookie, text_job

ISSUER = OIDC["issuer"]
KEY = RSAKey.generate_key(2048, parameters={"kid": "test", "alg": "RS256", "use": "sig"})
DISCOVERY = {
    "issuer": ISSUER,
    "authorization_endpoint": f"{ISSUER}/protocol/openid-connect/auth",
    "token_endpoint": f"{ISSUER}/protocol/openid-connect/token",
    "jwks_uri": f"{ISSUER}/protocol/openid-connect/certs",
    "end_session_endpoint": f"{ISSUER}/protocol/openid-connect/logout",
}


class FakeProvider:
    def __init__(self, monkeypatch, app):
        self.claims = {}
        login = app.extensions["quality"]["login"]
        monkeypatch.setattr(login, "fetch", self.fetch)
        monkeypatch.setattr(OAuth2Session, "fetch_token", self.fetch_token)

    def fetch(self, url):
        if url.endswith("/.well-known/openid-configuration"):
            return DISCOVERY
        return KeySet([KEY]).as_dict(private=False)

    def fetch_token(self, _url, **_kwargs):
        return {"id_token": jwt.encode({"alg": "RS256", "kid": "test"}, self.claims, KEY)}


def cookie_value(response, name):
    for header in response.headers.getlist("Set-Cookie"):
        if header.startswith(f"{name}="):
            return header.split(";", 1)[0].split("=", 1)[1], header
    return None, None


def start(client):
    response = client.get("/account/login", headers=headers())
    assert response.status_code == 302
    query = parse_qs(urlsplit(response.headers["Location"]).query)
    assert query["code_challenge_method"] == ["S256"]
    flow, _header = cookie_value(response, "__Host-quality-login")
    return flow, query["state"][0], query["nonce"][0]


def claims(flow_nonce, **changes):
    now = int(time.time())
    base = {
        "iss": ISSUER,
        "aud": OIDC["client_id"],
        "nonce": flow_nonce,
        "exp": now + 300,
        "iat": now,
        "preferred_username": "alice",
        "groups": [],
    }
    return {**base, **changes}


def callback(client, flow, state):
    login_cookie = {"Cookie": f"__Host-quality-login={flow}"}
    return client.get(f"/account/callback?state={state}&code=c", headers=headers(**login_cookie))


@pytest.fixture
def provider(tmp_path, monkeypatch):
    app, state = build(tmp_path)
    return app, state, FakeProvider(monkeypatch, app)


def test_token_checks(provider):
    app, state, fake = provider
    client = app.test_client(use_cookies=False)
    for wrong in ({"iss": "https://evil.example"}, {"aud": "other"}, {"nonce": "other"}, {"exp": 1}):
        flow, login_state, nonce = start(client)
        fake.claims = claims(nonce, **wrong)
        assert callback(client, flow, login_state).status_code == 403
    flow, login_state, nonce = start(client)
    fake.claims = claims(nonce, groups=[OIDC["member_group"]])
    member_session, _header = cookie_value(callback(client, flow, login_state), "__Host-quality-session")
    response = client.post("/account/submit", data=text_job(), headers=headers(**session_cookie(member_session)))
    assert response.status_code == 303
    flow, login_state, nonce = start(client)
    fake.claims = claims(nonce, preferred_username="bob", groups=[OIDC["member_group"].lstrip("/")])
    registered, _header = cookie_value(callback(client, flow, login_state), "__Host-quality-session")
    assert app.extensions["quality"]["login"].identity(registered) == {"name": "bob", "member": False}
    tiers = sorted(path.name[0] for path in (state / "spool").iterdir())
    assert tiers == ["0"]


def test_session_cookie(provider):
    app, _state, fake = provider
    client = app.test_client(use_cookies=False)
    flow, login_state, nonce = start(client)
    fake.claims = claims(nonce)
    response = callback(client, flow, login_state)
    value, header = cookie_value(response, "__Host-quality-session")
    assert "HttpOnly" in header and "Secure" in header and "SameSite=Lax" in header and "Path=/" in header
    assert "." not in value
    assert response.headers["Location"].endswith("/account/")


def test_login_state_bound(provider):
    app, _state, fake = provider
    client = app.test_client(use_cookies=False)
    first_flow, _first_state, _nonce = start(client)
    _second_flow, second_state, nonce = start(client)
    fake.claims = claims(nonce)
    assert callback(client, first_flow, second_state).status_code == 403
    assert client.get(f"/account/callback?state={second_state}&code=c", headers=headers()).status_code == 403


def test_logout(provider):
    app, _state, fake = provider
    client = app.test_client(use_cookies=False)
    flow, login_state, nonce = start(client)
    fake.claims = claims(nonce)
    session, _header = cookie_value(callback(client, flow, login_state), "__Host-quality-session")
    response = client.get("/account/logout", headers=headers(**session_cookie(session)))
    assert response.status_code == 302
    location = urlsplit(response.headers["Location"])
    assert f"{location.scheme}://{location.netloc}{location.path}" == DISCOVERY["end_session_endpoint"]
    assert parse_qs(location.query)["client_id"] == [OIDC["client_id"]]
    after = client.post("/account/submit", data=text_job(), headers=headers(**session_cookie(session)))
    assert after.status_code == 403


def test_login_off_without_oidc(tmp_path):
    app, _state = build(tmp_path, oidc=None)
    client = app.test_client(use_cookies=False)
    assert client.get("/account/login", headers=headers()).status_code == 404
    assert "Log in" not in client.get("/", headers=headers()).get_data(as_text=True)
