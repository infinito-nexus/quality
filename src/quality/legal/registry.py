import http.client
import json
import shutil
import ssl
import tempfile
import urllib.request
from pathlib import Path
from urllib.parse import quote

from quality import QualityError
from quality.db import network_variables
from quality.environment import open_repository
from quality.legal.checks import DEPENDENCY_LICENSE
from quality.legal.dependencies import format_of, read_dependencies
from quality.legal.spdx import expression_of, joined, well_formed
from quality.ruledata import BUILTIN, gitignore_spec, require
from quality.snapshot import materialize

HTTPS = "https://"
SETTINGS_WHERE = f"enforcer of builtin {DEPENDENCY_LICENSE}"
REGISTRIES_WHERE = f"registries of builtin {DEPENDENCY_LICENSE}"
UNSAFE_SEGMENTS = {"", ".", ".."}
MINIFIED = "composer/2.0"
UNSET = "__unset"
PROXY_SUFFIX = "_proxy"
CA_FILES = ("SSL_CERT_FILE", "NIX_SSL_CERT_FILE")
CA_DIR = "SSL_CERT_DIR"
FAILED_RESPONSE = (OSError, http.client.HTTPException, ValueError)
UNREADABLE_DOCUMENT = (ValueError, LookupError, TypeError, AttributeError, RecursionError)


class RefusedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args) -> None:
        return None


def dependency_settings(data) -> dict:
    """
    Args:
        data: Loaded rule data.

    Returns:
        The settings of the one enforcer bound to the dependency-license builtin.

    Raises:
        QualityError: No active rule or more than one names it.
    """
    found = [
        settings
        for rule in data.rules
        if isinstance(rule.enforcer, dict) and not rule.pending
        for settings in rule.enforcer.values()
        if settings.get(BUILTIN) == DEPENDENCY_LICENSE
    ]
    if len(found) != 1:
        raise QualityError(f"rule data: exactly one enforcer must name builtin {DEPENDENCY_LICENSE!r}")
    return found[0]


def licence_packages(data, path_value: str, repositories: list, environ: dict) -> tuple:
    """
    Args:
        data: Loaded rule data.
        path_value: Validated PATH git is resolved from.
        repositories: Local repositories whose HEAD and staged pins are looked up.
        environ: The caller's environment; only its network_variables()
            shape the requests.

    Returns:
        The write_index() packages map and one line per count of pins left
        without an entry.

    Raises:
        QualityError: A repository is no git work tree, or a registry
            setting is missing or unsafe.
    """
    settings = dependency_settings(data)
    registries = require(settings, "registries", SETTINGS_WHERE)
    scratch = Path(tempfile.mkdtemp(prefix="quality-")).resolve()
    pins = []
    try:
        for number, path in enumerate(repositories):
            pins += repository_pins(path, data, settings, scratch / str(number), path_value)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return lookup(pins, registries, fetcher(registries, environ))


def repository_pins(path: str, data, settings: dict, scratch: Path, path_value: str) -> list:
    """
    Args:
        path: Local repository named by --licenses.
        data: Loaded rule data with the git timeout, the blob limit and the kinds.
        settings: The dependency-license settings with `reads`, `exempt` and `formats`.
        scratch: Directory to create for its dependency files.
        path_value: Validated PATH git is resolved from.

    Returns:
        The runtime dependencies its HEAD or its staging index pins to an
        exact version and whose file names no licence for them, so a pin
        staged for the next commit is looked up before that commit.

    Raises:
        QualityError: The path is no directory or no git work tree.
    """
    if not Path(path).is_dir():
        raise QualityError(f"--licenses {path} is no directory")
    repo = open_repository(str(Path(path).absolute()), data.limit("git_timeout"), path_value, {})
    head = repo.head()
    sides = [repo.index_entries()]
    if head is not None:
        sides.append(repo.tree_entries(head))
    scratch.mkdir()
    reads = gitignore_spec(require(settings, "reads", SETTINGS_WHERE))
    exempt = gitignore_spec(require(settings, "exempt", SETTINGS_WHERE))
    formats = require(settings, "formats", SETTINGS_WHERE)
    found = []
    for number, side in enumerate(sides):
        entries = [entry for entry in side if reads.match_file(entry.path) and not exempt.match_file(entry.path)]
        snapshot = materialize(repo, entries, scratch / str(number), data.limit("blob_max_bytes"), data.kinds)
        found += pinned(snapshot, formats)
    return found


def pinned(snapshot, formats: dict) -> list:
    """
    Args:
        snapshot: Snapshot of dependency files.
        formats: Reader name to the file patterns it reads.

    Returns:
        The dependencies they pin to an exact version without naming their licence.
    """
    found = []
    for name in snapshot.paths():
        reader = format_of(name, formats)
        dependencies = None if reader is None else read_dependencies(reader, snapshot, name)
        if dependencies is not None:
            found += [item for item in dependencies if item.version and item.license is None]
    return found


def opener(environ: dict):
    """
    Args:
        environ: The caller's environment.

    Returns:
        A urllib opener whose proxies and trusted certificates come only from
        the network_variables() of that environment and that follows no
        redirect, so a request never leaves the host of its template.
    """
    passed = network_variables(environ)
    proxies = {
        name.lower().removesuffix(PROXY_SUFFIX): value
        for name, value in passed.items()
        if name.lower().endswith(PROXY_SUFFIX) and value
    }
    cafile = next((passed[name] for name in CA_FILES if passed.get(name)), None)
    context = ssl.create_default_context(cafile=cafile, capath=passed.get(CA_DIR))
    return urllib.request.build_opener(
        urllib.request.ProxyHandler(proxies), urllib.request.HTTPSHandler(context=context), RefusedRedirect()
    )


def fetcher(registries: dict, environ: dict):
    """
    Args:
        registries: The `registries` settings with the per-request `timeout`
            in seconds and the `max_bytes` of one response.
        environ: The caller's environment.

    Returns:
        A function from an https URL to the response body; None when the
        request fails, is redirected or the body exceeds max_bytes.
    """
    timeout = require(registries, "timeout", REGISTRIES_WHERE)
    limit = require(registries, "max_bytes", REGISTRIES_WHERE)
    open_url = opener(environ).open

    def fetch(url: str) -> bytes | None:
        try:
            with open_url(url, timeout=timeout) as response:
                body = response.read(limit + 1)
        except FAILED_RESPONSE:
            return None
        return body if len(body) <= limit else None

    return fetch


def checked_ecosystems(registries: dict) -> dict:
    """
    Args:
        registries: The `registries` settings.

    Returns:
        Its `ecosystems`: per ecosystem as osv-scanner names it the `url`
        template with {name} and {version} and the response `shape`.

    Raises:
        QualityError: A key is missing, a shape unknown or a url not https.
    """
    ecosystems = require(registries, "ecosystems", REGISTRIES_WHERE)
    for ecosystem, entry in ecosystems.items():
        where = f"{REGISTRIES_WHERE} ecosystem {ecosystem}"
        url, shape = require(entry, "url", where), require(entry, "shape", where)
        if shape not in SHAPES:
            raise QualityError(f"rule data: {where} names shape {shape!r} outside {', '.join(SHAPES)}")
        if not str(url).startswith(HTTPS):
            raise QualityError(f"rule data: {where} url must use https, not {url}")
    return ecosystems


def lookup(pins: list, registries: dict, fetch) -> tuple:
    """
    Args:
        pins: Dependencies with an exact version.
        registries: The `registries` settings with `max_packages`, the
            `unknown_values` registries give where they know no SPDX
            licence, and the checked_ecosystems().
        fetch: Function from an https URL to the response body, or None
            when the request failed.

    Returns:
        The write_index() packages map of every pin a registry names an
        SPDX licence for, and one line per count of the pins left out.

    Raises:
        QualityError: A setting is missing, a shape unknown or a url not https.
    """
    ecosystems = checked_ecosystems(registries)
    limit = require(registries, "max_packages", REGISTRIES_WHERE)
    unknown = {value.casefold() for value in require(registries, "unknown_values", REGISTRIES_WHERE)}
    unique = sorted({(pin.ecosystem, pin.name, pin.version) for pin in pins})
    packages = {}
    for ecosystem, name, version in unique[:limit]:
        expression = answer(ecosystems.get(ecosystem), name, version, fetch)
        if expression is not None and well_formed(expression, unknown):
            packages.setdefault(ecosystem, {}).setdefault(name, {})[version] = expression
    answered = sum(len(versions) for names in packages.values() for versions in names.values())
    return packages, skipped_lines(len(unique), limit, answered)


def skipped_lines(total: int, limit: int, answered: int) -> list:
    lines = []
    if total > limit:
        lines.append(f"{total - limit} pinned package(s) over the max_packages limit of {limit}")
    if min(total, limit) > answered:
        lines.append(f"{min(total, limit) - answered} pinned package(s) without registry licence data")
    return lines


def answer(entry: dict | None, name: str, version: str, fetch) -> str | None:
    """
    Args:
        entry: The ecosystem's registry settings, or None without a registry.
        name: Package name as gate.package_name() normalises it.
        version: Exact version.
        fetch: Function from an https URL to the response body, or None.

    Returns:
        The SPDX expression the registry names for that release, or None.
    """
    if entry is None or {*name.split("/"), version} & UNSAFE_SEGMENTS:
        return None
    parse, safe = SHAPES[entry["shape"]]
    body = fetch(entry["url"].format(name=quote(name, safe=safe), version=quote(version, safe="")))
    if body is None:
        return None
    try:
        return parse(json.loads(body), name, version)
    except UNREADABLE_DOCUMENT:
        return None


def licenses_field(document: dict, _name: str, _version: str) -> str | None:
    """
    Args:
        document: A deps.dev or RubyGems version document.
        _name: Unused.
        _version: Unused.

    Returns:
        Its `licenses` list as one expression that needs every listed
        licence, since such a list does not say whether it offers a choice.
    """
    return joined(document["licenses"], "AND")


def composer_release(document: dict, name: str, version: str) -> str | None:
    """
    Args:
        document: Packagist p2 metadata of one package.
        name: Its name.
        version: The release as composer.lock spells it.

    Returns:
        The release's `license` list as a choice among them, as composer
        documents it, or None without that release.
    """
    releases = document["packages"][name]
    if document.get("minified") == MINIFIED:
        releases = expanded(releases)
    for release in releases:
        if release.get("version") == version:
            return expression_of(release.get("license"))
    return None


def expanded(releases: list) -> list:
    """
    Args:
        releases: Releases of minified composer/2.0 metadata, each holding
            only the keys that differ from the release before it.

    Returns:
        Every release with all its keys; a key set to `__unset` is dropped.
    """
    current = {}
    found = []
    for release in releases:
        current = {key: value for key, value in {**current, **release}.items() if value != UNSET}
        found.append(current)
    return found


SHAPES = {"licenses": (licenses_field, ""), "composer": (composer_release, "/")}
