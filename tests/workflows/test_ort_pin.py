import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("ort_pin", ROOT / ".github" / "ort" / "pin.py")
pin = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pin)
REPOSITORY = "ghcr.io/oss-review-toolkit/ort"
OLD = f"{REPOSITORY}:99.1.0@sha256:{'1' * 64}\n"
NEW_DIGEST = f"sha256:{'2' * 64}"
TAGS = "/v2/oss-review-toolkit/ort/tags/list"
TOKEN_URL = "https://ghcr.io/token?scope=repository%3Aoss-review-toolkit%2Fort%3Apull&service=ghcr.io"


def registry(digest: str):
    """
    Args:
        digest: What the manifest HEAD of the newest release answers.

    Returns:
        A stub of pin.request over the token, two tag pages with date tags
        and a pre-release, and that manifest, plus the list of requests it saw.
    """
    answers = {
        ("GET", TOKEN_URL): ({}, b'{"token": "anonymous"}'),
        ("GET", f"https://ghcr.io{TAGS}?n=1000"): (
            {"Link": f'<{TAGS}?last=99.1.0&n=1000>; rel="next"'},
            json.dumps({"tags": ["20240416", "99.1.0", "9.9.9"]}).encode(),
        ),
        ("GET", f"https://ghcr.io{TAGS}?last=99.1.0&n=1000"): (
            {},
            json.dumps({"tags": ["100.0.0", "100.1.0-rc1", "latest", "20991231"]}).encode(),
        ),
        ("HEAD", "https://ghcr.io/v2/oss-review-toolkit/ort/manifests/100.0.0"): ({"Docker-Content-Digest": digest}, b""),
    }
    seen = []

    def fetch(method: str, url: str, headers: dict) -> tuple:
        seen.append((method, url, headers))
        return answers[(method, url)]

    return fetch, seen


def test_the_committed_pin_is_well_formed():
    assert pin.parsed((ROOT / ".github" / "ort" / "image").read_text(encoding="utf-8")).group("host", "name") == (
        "ghcr.io",
        "oss-review-toolkit/ort",
    )


def test_update_pins_the_newest_semver_release_by_its_digest(tmp_path):
    path = tmp_path / "image"
    path.write_text(OLD, encoding="utf-8")
    fetch, seen = registry(NEW_DIGEST)
    assert pin.rewrite(path, fetch) == f"{REPOSITORY}:100.0.0@{NEW_DIGEST}"
    assert path.read_text(encoding="utf-8") == f"{REPOSITORY}:100.0.0@{NEW_DIGEST}\n"
    head = seen[-1]
    assert head[0] == "HEAD" and head[2]["Authorization"] == "Bearer anonymous"
    assert {"application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json"} <= {
        kind.strip() for kind in head[2]["Accept"].split(",")
    }


@pytest.mark.parametrize("digest", ["sha256:abc", f"sha512:{'2' * 128}"])
def test_a_malformed_digest_fails_and_keeps_the_pin(tmp_path, digest):
    path = tmp_path / "image"
    path.write_text(OLD, encoding="utf-8")
    with pytest.raises(pin.PinError):
        pin.rewrite(path, registry(digest)[0])
    assert path.read_text(encoding="utf-8") == OLD


@pytest.mark.parametrize("text", [f"{REPOSITORY}@sha256:{'1' * 64}\n", f"{REPOSITORY}:latest@sha256:{'1' * 64}\n", OLD + OLD])
def test_check_refuses_a_pin_without_semver_and_digest(tmp_path, text):
    path = tmp_path / "image"
    path.write_text(text, encoding="utf-8")
    assert pin.main(["check", str(path)]) == 1


def test_only_ascii_semver_tags_without_a_trailing_newline_are_releases():
    assert pin.newest(["9.0.0\n", "١٠.0.0", "1.0.0"]) == "1.0.0"


def test_request_refuses_plain_http_before_any_connection():
    with pytest.raises(pin.PinError):
        pin.request("GET", "http://ghcr.io/token", {})
