import json

REQUIRED = (
    "state_dir",
    "legal_dir",
    "secret_file",
    "public_url",
    "controller",
    "resolvers",
    "host_log_days",
    "access",
    "limits",
    "rate_limits",
    "oidc",
)
CONTROLLER_FIELDS = ("name", "street", "postal_code", "city", "country", "email")
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
    controller = settings["controller"] if isinstance(settings["controller"], dict) else {}
    blank = [field for field in CONTROLLER_FIELDS if not str(controller.get(field) or "").strip()]
    if blank:
        raise SystemExit(f"web: {path} leaves controller {', '.join(blank)} empty")
    with open(settings["secret_file"], "rb") as handle:
        secret = handle.read().strip()
    if len(secret) < MINIMUM_SECRET_BYTES:
        raise SystemExit(f"web: {settings['secret_file']} holds fewer than {MINIMUM_SECRET_BYTES} bytes")
    return {**settings, "secret": secret}
