import hashlib
import hmac
import json
import threading
import time

from altcha import Payload, create_challenge, verify_solution

ALGORITHM = "PBKDF2/SHA-256"
MAXIMUM_PAYLOAD = 4096


class Captcha:
    def __init__(self, settings):
        self.key = hmac.new(settings["secret"], b"captcha", hashlib.sha256).hexdigest()
        self.cost = settings["limits"]["captcha_cost"]
        self.seconds = settings["limits"]["captcha_seconds"]
        self.lock = threading.Lock()
        self.used = {}

    def challenge(self):
        expires = int(time.time()) + self.seconds
        challenge = create_challenge(ALGORITHM, self.cost, expires_at=expires, hmac_secret=self.key)
        return json.dumps(challenge.to_dict())

    def verify(self, payload):
        """
        Args:
            payload: The widget's base64 form value, or None.

        Returns:
            True once per solved, unexpired challenge this process issued.
        """
        if not payload or len(payload) > MAXIMUM_PAYLOAD:
            return False
        if not verify_solution(payload, self.key).verified:
            return False
        parameters = Payload.from_base64(payload).challenge.parameters
        if not isinstance(parameters.expires_at, int):
            return False
        now = time.time()
        with self.lock:
            self.used = {nonce: expires for nonce, expires in self.used.items() if expires >= now}
            if parameters.nonce in self.used:
                return False
            self.used[parameters.nonce] = parameters.expires_at
        return True
