import secrets
import threading
import time
from urllib.parse import urlencode

import requests
from authlib.common.security import generate_token
from authlib.integrations.requests_client import OAuth2Session
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet

FLOW_SECONDS = 600
HTTP_TIMEOUT = 10
CLOCK_LEEWAY = 30
ID_TOKEN_ALGORITHMS = ["RS256", "ES256", "PS256"]


class Login:
    def __init__(self, settings):
        self.oidc = settings["oidc"]
        self.session_seconds = settings["limits"]["session_hours"] * 3600
        self.lock = threading.Lock()
        self.flows = {}
        self.sessions = {}
        self.metadata = None

    @property
    def available(self):
        return self.oidc is not None

    def fetch(self, url):
        response = requests.get(url, timeout=HTTP_TIMEOUT)
        response.raise_for_status()
        return response.json()

    def discovery(self):
        if self.metadata is None:
            self.metadata = self.fetch(f"{self.oidc['issuer']}/.well-known/openid-configuration")
        return self.metadata

    def client(self):
        return OAuth2Session(
            self.oidc["client_id"],
            redirect_uri=self.oidc["redirect_uri"],
            scope="openid profile",
            code_challenge_method="S256",
        )

    def start(self):
        """
        Returns:
            (flow id for the short-lived login cookie, authorization URL with state, nonce and S256 challenge).
        """
        flow = {"state": generate_token(32), "nonce": generate_token(32), "verifier": generate_token(64)}
        endpoint = self.discovery()["authorization_endpoint"]
        url, _state = self.client().create_authorization_url(
            endpoint, state=flow["state"], nonce=flow["nonce"], code_verifier=flow["verifier"]
        )
        flow_id = secrets.token_urlsafe(32)
        now = time.time()
        with self.lock:
            self.flows = {key: value for key, value in self.flows.items() if value["created"] > now - FLOW_SECONDS}
            self.flows[flow_id] = {**flow, "created": now}
        return flow_id, url

    def finish(self, flow_id, state, code):
        """
        Args:
            flow_id: Value of the login cookie, or None.
            state: State parameter of the callback, or None.
            code: Authorization code of the callback, or None.

        Returns:
            A new session token, or None when the flow, the state or the ID token does not check out.
        """
        with self.lock:
            flow = self.flows.pop(flow_id or "", None)
        if flow is None or not state or not code or not secrets.compare_digest(state, flow["state"]):
            return None
        endpoint = self.discovery()["token_endpoint"]
        token = self.client().fetch_token(endpoint, code=code, code_verifier=flow["verifier"])
        claims = self.claims(token.get("id_token"), flow["nonce"])
        if claims is None or not isinstance(claims.get("preferred_username"), str):
            return None
        groups = claims.get(self.oidc["group_claim"]) or []
        member = isinstance(groups, list) and self.oidc["member_group"] in groups
        session = secrets.token_urlsafe(32)
        with self.lock:
            self.sessions[session] = {"name": claims["preferred_username"], "member": member, "created": time.time()}
        return session

    def claims(self, id_token, nonce):
        if not isinstance(id_token, str):
            return None
        registry = jwt.JWTClaimsRegistry(
            leeway=CLOCK_LEEWAY,
            iss={"essential": True, "value": self.oidc["issuer"]},
            aud={"essential": True, "value": self.oidc["client_id"]},
            nonce={"essential": True, "value": nonce},
            exp={"essential": True},
        )
        try:
            keys = KeySet.import_key_set(self.fetch(self.discovery()["jwks_uri"]))
            token = jwt.decode(id_token, keys, algorithms=ID_TOKEN_ALGORITHMS)
            registry.validate(token.claims)
        except (JoseError, ValueError, TypeError):
            return None
        return token.claims

    def sweep(self):
        cutoff = time.time() - self.session_seconds
        with self.lock:
            self.sessions = {token: session for token, session in self.sessions.items() if session["created"] >= cutoff}

    def identity(self, token):
        """
        Args:
            token: Value of the session cookie, or None.

        Returns:
            {"name", "member"} of a live session, or None.
        """
        with self.lock:
            session = self.sessions.get(token or "")
            if session is not None and session["created"] < time.time() - self.session_seconds:
                del self.sessions[token]
                session = None
        return None if session is None else {"name": session["name"], "member": session["member"]}

    def logout(self, token):
        with self.lock:
            self.sessions.pop(token or "", None)
        query = urlencode({"client_id": self.oidc["client_id"], "post_logout_redirect_uri": self.oidc["logout_redirect"]})
        return f"{self.discovery()['end_session_endpoint']}?{query}"
