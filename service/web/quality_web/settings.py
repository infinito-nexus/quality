import json

REQUIRED = ("state_dir", "legal_dir", "secret_file", "public_url", "access", "limits", "rate_limits", "oidc")
MINIMUM_SECRET_BYTES = 32


def load(path):
    """
    Args:
        path: JSON configuration the role or the local compose stack renders.

    Returns:
        The configuration plus the secret read from its secret_file.
    """
    with open(path, encoding="utf-8") as handle:
        settings = json.load(handle)
    missing = [key for key in REQUIRED if key not in settings]
    if missing:
        raise SystemExit(f"web: {path} misses {', '.join(missing)}")
    with open(settings["secret_file"], "rb") as handle:
        secret = handle.read().strip()
    if len(secret) < MINIMUM_SECRET_BYTES:
        raise SystemExit(f"web: {settings['secret_file']} holds fewer than {MINIMUM_SECRET_BYTES} bytes")
    return {**settings, "secret": secret}
