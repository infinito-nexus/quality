import copy
import http.server
import io
import json
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import pytest

from quality import QualityError, db
from quality.cli import main
from quality.legal import index, registry
from quality.legal.checks import NO_DATA, REASONS
from quality.legal.dependencies import Dependency
from quality.legal.spdx import allowed
from quality.ruledata import load
from tests.integration.rules.test_legal import DEPENDENCY, SEED, judged, legal
from tests.integration.support import RULES, Target

REGISTRIES = registry.dependency_settings(load(RULES))["registries"]
DEPS_DEV = "https://api.deps.dev/v3/systems"
PACKAGIST = "https://repo.packagist.org/p2/acme/dual.json"
P2 = {
    "minified": "composer/2.0",
    "packages": {
        "acme/dual": [
            {"name": "acme/dual", "version": "v2.0.0", "license": ["MIT", "GPL-3.0-only"]},
            {"version": "v1.0.0"},
            {"version": "v0.9.0", "license": "__unset"},
        ]
    },
}
SHAPES = {
    f"{DEPS_DEV}/pypi/packages/apache-lib/versions/2.0": {"licenses": ["Apache-2.0"]},
    f"{DEPS_DEV}/npm/packages/%40scope%2Fboth/versions/1.0.0": {"licenses": ["MIT", "GPL-3.0-only"]},
    f"{DEPS_DEV}/go/packages/github.com%2Facme%2Fmod/versions/v1.2.0": {"licenses": ["BSD-3-Clause"]},
    PACKAGIST: P2,
    "https://rubygems.org/api/v2/rubygems/rack/versions/3.0.0.json": {"name": "rack", "licenses": ["MIT"]},
}
SHAPE_PINS = [
    ("PyPI", "apache-lib", "2.0"),
    ("npm", "@scope/both", "1.0.0"),
    ("Go", "github.com/acme/mod", "v1.2.0"),
    ("Packagist", "acme/dual", "v1.0.0"),
    ("RubyGems", "rack", "3.0.0"),
]
GPL_URL = f"{DEPS_DEV}/pypi/packages/gpl-lib/versions/1.0"
MISSING_URL = f"{DEPS_DEV}/pypi/packages/missing-lib/versions/2.0"
ODD_URL = f"{DEPS_DEV}/pypi/packages/odd-lib/versions/1.0"
EXACT_URL = f"{DEPS_DEV}/npm/packages/exact/versions/1.0.0"
REQUIREMENTS = "gpl-lib==1.0\nmissing-lib==2.0\n"
STAGED = "gpl-lib==1.0\nmissing-lib==2.0\nodd-lib==1.0\n"
UNANSWERED = "pinned package(s) without registry licence data"
PACKAGE_JSON = '{\n  "dependencies": {"ranged": "^1.0.0", "exact": "1.0.0"}\n}\n'


def pins(*triples: tuple) -> list:
    return [Dependency(ecosystem, name, version, None, None) for ecosystem, name, version in triples]


def served(responses: dict) -> tuple:
    """
    Args:
        responses: URL to the JSON document it answers, or to raw bytes.

    Returns:
        A fetch function that answers only those URLs, and the list of URLs it was asked for.
    """
    requested = []

    def fetch(url: str) -> bytes | None:
        requested.append(url)
        if url not in responses:
            return None
        body = responses[url]
        return body if isinstance(body, bytes) else json.dumps(body).encode()

    return fetch, requested


def test_each_registry_shape_becomes_an_index_entry():
    fetch, requested = served(SHAPES)
    packages, skipped = registry.lookup(pins(*SHAPE_PINS), REGISTRIES, fetch)
    assert packages == {
        "PyPI": {"apache-lib": {"2.0": "(Apache-2.0)"}},
        "npm": {"@scope/both": {"1.0.0": "(MIT) AND (GPL-3.0-only)"}},
        "Go": {"github.com/acme/mod": {"v1.2.0": "(BSD-3-Clause)"}},
        "Packagist": {"acme/dual": {"v1.0.0": "(MIT) OR (GPL-3.0-only)"}},
        "RubyGems": {"rack": {"3.0.0": "(MIT)"}},
    }
    assert sorted(requested) == sorted(SHAPES)
    assert skipped == []


def test_packagist_list_is_a_choice_and_any_other_list_needs_every_licence():
    packages = registry.lookup(pins(*SHAPE_PINS), REGISTRIES, served(SHAPES)[0])[0]
    assert allowed(packages["Packagist"]["acme/dual"]["v1.0.0"], {"MIT"}) is True
    assert allowed(packages["npm"]["@scope/both"]["1.0.0"], {"MIT"}) is False


def test_a_pin_the_registries_do_not_answer_gets_no_entry():
    responses = {
        f"{DEPS_DEV}/pypi/packages/empty-lib/versions/1.0": {"licenses": []},
        f"{DEPS_DEV}/pypi/packages/list-lib/versions/1.0": ["no", "document"],
        f"{DEPS_DEV}/pypi/packages/html-lib/versions/1.0": b"<html>rate limited</html>",
        PACKAGIST: P2,
    }
    fetch, requested = served(responses)
    unanswered = pins(
        ("PyPI", "missing-lib", "1.0"),
        ("PyPI", "empty-lib", "1.0"),
        ("PyPI", "list-lib", "1.0"),
        ("PyPI", "html-lib", "1.0"),
        ("Packagist", "acme/dual", "v0.9.0"),
        ("Packagist", "acme/dual", "v3.0.0"),
        ("Hackage", "base", "4.0"),
        ("npm", "../../escape", "1.0.0"),
    )
    assert registry.lookup(unanswered, REGISTRIES, fetch) == ({}, [f"8 {UNANSWERED}"])
    assert not any("escape" in url or "Hackage" in url for url in requested)


@pytest.mark.parametrize(
    "licenses",
    [["non-standard"], ["NOASSERTION"], ["Unknown"], ["MIT", "non-standard"], ["MIT/X11"], ["Apache License 2.0"]],
    ids=["non-standard", "noassertion", "unknown", "and-non-standard", "malformed-id", "free-text"],
)
def test_a_registry_value_that_is_no_spdx_licence_gets_no_entry(licenses):
    fetch = served({ODD_URL: {"licenses": licenses}})[0]
    assert registry.lookup(pins(("PyPI", "odd-lib", "1.0")), REGISTRIES, fetch) == ({}, [f"1 {UNANSWERED}"])


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda data: data["ecosystems"]["PyPI"].update(url="http://api.deps.dev/{name}/{version}"), "ecosystem PyPI url must use https"),
        (lambda data: data["ecosystems"]["npm"].update(shape="xml"), "ecosystem npm names shape 'xml'"),
        (lambda data: data["ecosystems"]["Go"].pop("url"), "ecosystem Go is missing key 'url'"),
        (lambda data: data.pop("max_packages"), "is missing key 'max_packages'"),
    ],
    ids=["plain-http", "unknown-shape", "no-url", "no-cap"],
)
def test_unsafe_or_incomplete_registry_settings_fail_before_any_request(change, message):
    settings = copy.deepcopy(REGISTRIES)
    change(settings)
    fetch, requested = served({})
    with pytest.raises(QualityError, match=message):
        registry.lookup(pins(("npm", "a", "1.0.0")), settings, fetch)
    assert requested == []


def test_package_cap_bounds_the_requests():
    responses = {f"{DEPS_DEV}/pypi/packages/lib-{n}/versions/1.0": {"licenses": ["MIT"]} for n in (1, 2, 3)}
    fetch, requested = served(responses)
    triples = [("PyPI", f"lib-{n}", "1.0") for n in (3, 1, 2)]
    packages, skipped = registry.lookup(pins(*triples, *triples), {**REGISTRIES, "max_packages": 2}, fetch)
    assert sorted(packages["PyPI"]) == ["lib-1", "lib-2"]
    assert len(requested) == 2
    assert skipped == ["1 pinned package(s) over the max_packages limit of 2"]


class Response(io.BytesIO):
    def __init__(self, body: bytes, url: str):
        super().__init__(body)
        self.url = url


def test_fetch_refuses_an_oversized_body_and_a_failure(monkeypatch):
    answers = {
        "https://r.test/ok": ("https://r.test/ok", b"1234"),
        "https://r.test/big": ("https://r.test/big", b"12345"),
    }
    timeouts = []

    class Opener:
        def open(self, url: str, timeout: int) -> Response:
            timeouts.append(timeout)
            if url not in answers:
                raise OSError("connection refused")
            return Response(answers[url][1], answers[url][0])

    monkeypatch.setattr(registry, "opener", lambda _environ: Opener())
    fetch = registry.fetcher({**REGISTRIES, "max_bytes": 4}, {})
    urls = [*answers, "https://r.test/down"]
    assert [fetch(url) for url in urls] == [b"1234", None, None]
    assert timeouts == [REGISTRIES["timeout"]] * len(urls)


class Redirecting(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        moved = self.path == "/moved"
        self.send_response(302 if moved else 200)
        if moved:
            self.send_header("Location", "/elsewhere")
        self.send_header("Content-Length", "0" if moved else "2")
        self.end_headers()
        if not moved:
            self.wfile.write(b"{}")

    def log_message(self, *_args) -> None:
        return None


def test_opener_follows_no_redirect():
    server = http.server.HTTPServer(("127.0.0.1", 0), Redirecting)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    moved = f"http://127.0.0.1:{server.server_port}/moved"
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(moved, timeout=5) as followed:
            assert followed.url.endswith("/elsewhere")
        with pytest.raises(urllib.error.HTTPError) as refused:
            registry.opener({}).open(moved, timeout=5)
        refused.value.close()
        assert refused.value.code == 302
    finally:
        server.shutdown()
        server.server_close()


def test_opener_takes_its_proxy_only_from_the_network_variables():
    built = registry.opener({"HTTPS_PROXY": "http://proxy.test:3128", "FTP_PROXY": "http://other.test", "GITHUB_TOKEN": "t"})
    handler = next(item for item in built.handlers if isinstance(item, urllib.request.ProxyHandler))
    assert handler.proxies == {"https": "http://proxy.test:3128"}


def offline_fetch(work: Path, *_args) -> None:
    (work / db.TRIVY_DIR).mkdir(exist_ok=True)
    (work / db.OSV_DIR).mkdir(exist_ok=True)


def updated(capsys, *argv: str) -> str:
    code = main(["db", "update", *argv])
    captured = capsys.readouterr()
    assert code == 0, captured.err
    return captured.err


def licence_state(bundle: Path) -> tuple:
    manifest = json.loads((bundle / db.MANIFEST).read_text(encoding="utf-8"))
    return manifest[db.LICENSE_KEY], (bundle / db.LICENSE_DIR / db.LICENSE_INDEX).read_bytes()


def source_with_staged_pins(path: Path) -> Target:
    """
    Args:
        path: Work tree to create.

    Returns:
        A repository whose HEAD pins gpl-lib and missing-lib, whose staging
        index drops missing-lib and adds exact and odd-lib, and whose work
        tree alone adds worktree-lib.
    """
    source = Target.create(path)
    source.write("requirements.txt", REQUIREMENTS)
    source.write("tests/requirements.txt", "test-only==1.0\n")
    source.commit()
    source.write("requirements.txt", "gpl-lib==1.0\n")
    source.write("package.json", PACKAGE_JSON)
    source.write("odd/requirements.txt", "odd-lib==1.0\n")
    source.stage()
    source.write("requirements-local.txt", "worktree-lib==1.0\n")
    return source


def test_db_update_with_licenses_lets_a_staged_check_judge_registry_licences(target, tmp_path, monkeypatch, capsys):
    source = source_with_staged_pins(tmp_path / "source")
    answers = {GPL_URL: {"licenses": ["GPL-3.0-only"]}, EXACT_URL: {"licenses": ["MIT"]}, ODD_URL: {"licenses": ["non-standard"]}}
    fetch, requested = served(answers)
    monkeypatch.setattr(db, "fetch_trivy", offline_fetch)
    monkeypatch.setattr(db, "fetch_osv", offline_fetch)
    monkeypatch.setattr(registry, "fetcher", lambda _registries, _environ: fetch)
    bundle = tmp_path / "bundle"
    errors = updated(capsys, "--db", str(bundle), "--licenses", str(source.path))
    assert errors == f"quality: unchecked: 2 {UNANSWERED}\n"
    assert sorted(requested) == sorted([GPL_URL, MISSING_URL, EXACT_URL, ODD_URL])
    assert index.read_index(bundle) == {"PyPI": {"gpl-lib": {"1.0": "(GPL-3.0-only)"}}, "npm": {"exact": {"1.0.0": "(MIT)"}}}
    built = licence_state(bundle)
    monkeypatch.setattr(registry, "fetcher", lambda *_args: pytest.fail("asked a registry without --licenses"))
    assert updated(capsys, "--db", str(bundle)) == ""
    assert licence_state(bundle) == built
    document = judged(target, "staged", SEED, {"requirements.txt": STAGED}, "--db", str(bundle))
    assert legal(document) == (50, 1, 2, [(DEPENDENCY, "requirements.txt", 1)])
    for row in (2, 3):
        assert f"unchecked: requirements.txt:{row}: {REASONS[NO_DATA]}" in document["notes"]


def test_db_update_refuses_to_carry_a_licence_index_that_does_not_match_its_digest(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(db, "fetch_trivy", offline_fetch)
    monkeypatch.setattr(db, "fetch_osv", offline_fetch)
    bundle = tmp_path / "bundle"
    (bundle / db.TRIVY_DIR).mkdir(parents=True)
    licenses = index.write_index(bundle, {"PyPI": {"a": {"1.0": "MIT"}}})
    db.write_manifest(bundle, datetime.now(timezone.utc), db.tree_digest(bundle), licenses)
    (bundle / db.LICENSE_DIR / db.LICENSE_INDEX).write_text('{"format": 1, "packages": {}}\n', encoding="utf-8")
    before = licence_state(bundle)
    assert main(["db", "update", "--db", str(bundle)]) == 2
    assert "does not match its digest: run `quality db update --licenses <repo>`" in capsys.readouterr().err
    assert licence_state(bundle) == before


def test_db_update_without_licenses_asks_no_registry_and_writes_no_index(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(db, "fetch_trivy", offline_fetch)
    monkeypatch.setattr(db, "fetch_osv", offline_fetch)
    monkeypatch.setattr(registry, "fetcher", lambda *_args: pytest.fail("asked a registry without --licenses"))
    assert updated(capsys, "--db", str(tmp_path / "bundle")) == ""
    assert index.read_index(tmp_path / "bundle") is None
    assert main(["db", "update", "--db", str(tmp_path / "other"), "--licenses", str(tmp_path / "absent")]) == 2
    assert "--licenses" in capsys.readouterr().err
    assert not (tmp_path / "other").exists()
