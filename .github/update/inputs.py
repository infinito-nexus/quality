import io
import json
import re
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

TIMEOUT = 60
PREFETCH_TIMEOUT = 1800
MAX_BYTES = 256 << 20
HTTPS = "https://"
REGISTRY_PREFIXES = ("https://registry.npmjs.org/", "https://files.pythonhosted.org/", "https://github.com/")
STABLE = re.compile(r"v?(\d+(?:\.\d+)*)")
INPUT = re.compile(r'inputs\.([\w-]+) = \{\s*url = "([^"]+)";')
NPM = re.compile(r"https://registry\.npmjs\.org/((?:@[\w.-]+/)?[\w.-]+)/-/[\w.-]+?-(\d+(?:\.\d+)*)\.tgz")
PYPI = re.compile(
    r"https://files\.pythonhosted\.org/packages/[0-9a-f]{2}/[0-9a-f]{2}/[0-9a-f]{60}/"
    r"([A-Za-z0-9_.]+?)-(\d+(?:\.\d+)*)(-[^/-]+-[^/-]+-[^/]+\.whl|\.tar\.gz)"
)
GITHUB = re.compile(r"https://github\.com/([\w.-]+)/([\w.-]+)/archive/refs/tags/(v?\d+(?:\.\d+)*)\.tar\.gz")
NIX_HASH = re.compile(r"sha256-[A-Za-z0-9+/]{43}=")
LOCK_FILE = "package-lock.json"


class UpdateError(Exception):
    pass


class HttpsOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        """
        Args:
            args: Request, response, code, message, headers and the target
                URL, as urllib passes them.

        Returns:
            The redirected request.

        Raises:
            UpdateError: The target URL is not https.
        """
        if not args[-1].startswith(HTTPS):
            raise UpdateError(f"refused a redirect away from https: {args[-1]}")
        return super().redirect_request(*args)


def fetch(url: str) -> bytes:
    """
    Args:
        url: An https URL.

    Returns:
        The body, at most MAX_BYTES, read within TIMEOUT seconds per request.

    Raises:
        UpdateError: The URL or a redirect is not https, the request fails or
            the body is too large.
    """
    if not url.startswith(HTTPS):
        raise UpdateError(f"refused a URL that is not https: {url}")
    opener = urllib.request.build_opener(HttpsOnly)
    try:
        with opener.open(url, timeout=TIMEOUT) as response:
            body = response.read(MAX_BYTES + 1)
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise UpdateError(f"{url} failed: {error}") from None
    if len(body) > MAX_BYTES:
        raise UpdateError(f"{url} answered more than {MAX_BYTES} bytes")
    return body


def document_of(get, url: str) -> dict:
    try:
        document = json.loads(get(url))
    except ValueError:
        raise UpdateError(f"{url} answered no JSON") from None
    if not isinstance(document, dict):
        raise UpdateError(f"{url} answered no JSON object")
    return document


def field(mapping, key: str, where: str):
    if not isinstance(mapping, dict) or key not in mapping:
        raise UpdateError(f"{where} lacks {key!r}")
    return mapping[key]


def text(mapping, key: str, where: str) -> str:
    value = field(mapping, key, where)
    if not isinstance(value, str) or not value:
        raise UpdateError(f"{where} gives no text for {key!r}")
    return value


def version_key(version: str) -> tuple | None:
    match = STABLE.fullmatch(version)
    return None if match is None else tuple(int(part) for part in match.group(1).split("."))


def newer(old_url: str, current: str, candidate: str, new_url: str) -> str:
    """
    Args:
        old_url: The pinned URL.
        current: Its version.
        candidate: The newest stable version the registry names.
        new_url: The URL of that version.

    Returns:
        The new URL when the candidate is newer, else the pinned one.

    Raises:
        UpdateError: The candidate is no stable release or its URL is not https.
    """
    if version_key(candidate) is None:
        raise UpdateError(f"{old_url}: the newest release {candidate!r} is no stable release")
    if not new_url.startswith(HTTPS):
        raise UpdateError(f"{old_url}: the registry names a URL that is not https: {new_url}")
    return new_url if version_key(candidate) > version_key(current) else old_url


def npm_url(match, get) -> str:
    package, current = match.group(1), match.group(2)
    where = f"npm package {package}"
    latest = document_of(get, f"https://registry.npmjs.org/{package}/latest")
    version = text(latest, "version", where)
    tarball = text(field(latest, "dist", where), "tarball", where)
    url = newer(match.group(0), current, version, tarball)
    found = NPM.fullmatch(tarball)
    if found is None or found.group(1) != package or found.group(2) != version:
        raise UpdateError(f"{where}: the tarball URL {tarball} does not name {package} {version}")
    return url


def unyanked(releases: dict, version: str) -> list:
    files = releases[version]
    if not isinstance(files, list):
        raise UpdateError(f"PyPI release {version} lists no files")
    return [item for item in files if isinstance(item, dict) and item.get("yanked") is False]


def newest_stable(releases, where: str) -> str:
    """
    Args:
        releases: The `releases` of a PyPI project document.
        where: The project, for the error.

    Returns:
        The highest stable version with at least one unyanked file.

    Raises:
        UpdateError: No such version.
    """
    if not isinstance(releases, dict):
        raise UpdateError(f"{where} lists no releases")
    stable = [version for version in releases if version_key(version) is not None and unyanked(releases, version)]
    if not stable:
        raise UpdateError(f"{where} has no stable release")
    return max(stable, key=version_key)


def pypi_url(match, get) -> str:
    project, current, suffix = match.group(1), match.group(2), match.group(3)
    name = re.sub(r"[-_.]+", "-", project).lower()
    where = f"PyPI project {name}"
    releases = field(document_of(get, f"https://pypi.org/pypi/{name}/json"), "releases", where)
    version = newest_stable(releases, where)
    wanted = f"{project}-{version}{suffix}"
    files = [item for item in unyanked(releases, version) if item.get("filename") == wanted]
    if len(files) != 1:
        raise UpdateError(f"{where} {version} has no single unyanked file {wanted}")
    url = text(files[0], "url", where)
    if PYPI.fullmatch(url) is None or not url.endswith(f"/{wanted}"):
        raise UpdateError(f"{where}: unexpected file URL {url}")
    return newer(match.group(0), current, version, url)


def github_url(match, get) -> str:
    owner, repo, current = match.group(1), match.group(2), match.group(3)
    where = f"GitHub repository {owner}/{repo}"
    release = document_of(get, f"https://api.github.com/repos/{owner}/{repo}/releases/latest")
    if field(release, "prerelease", where) is not False or field(release, "draft", where) is not False:
        raise UpdateError(f"{where}: its latest release is a draft or a pre-release")
    tag = text(release, "tag_name", where)
    url = f"https://github.com/{owner}/{repo}/archive/refs/tags/{tag}.tar.gz"
    return newer(match.group(0), current, tag, url)


RESOLVERS = ((NPM, npm_url), (PYPI, pypi_url), (GITHUB, github_url))


def resolved(url: str, get) -> str:
    """
    Args:
        url: URL of a flake input.
        get: Fetches a URL's body.

    Returns:
        The URL of the newest stable release of a versioned registry URL, the
        URL itself for any other input.

    Raises:
        UpdateError: A registry URL of no known shape, or a failed lookup.
    """
    for pattern, resolver in RESOLVERS:
        match = pattern.fullmatch(url)
        if match is not None:
            return resolver(match, get)
    if url.startswith(REGISTRY_PREFIXES):
        raise UpdateError(f"a registry URL of no known versioned shape: {url}")
    return url


def package_lock(archive: bytes) -> bytes:
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
        members = [
            member
            for member in bundle.getmembers()
            if member.isfile() and member.name.count("/") == 1 and member.name.endswith(f"/{LOCK_FILE}")
        ]
        if len(members) != 1:
            raise UpdateError(f"the archive holds no {LOCK_FILE} at its root")
        if members[0].size > MAX_BYTES:
            raise UpdateError(f"{LOCK_FILE} in the archive exceeds {MAX_BYTES} bytes")
        return bundle.extractfile(members[0]).read()


def npm_deps_hash(url: str, get, prefetch) -> str:
    """
    Args:
        url: Release archive of an npm project.
        get: Fetches a URL's body.
        prefetch: Returns the npmDepsHash of a package-lock.json path.

    Returns:
        The archive's npmDepsHash.

    Raises:
        UpdateError: The archive lacks the lock file or the hash is malformed.
    """
    lock = package_lock(get(url))
    with tempfile.TemporaryDirectory() as work:
        path = Path(work) / LOCK_FILE
        path.write_bytes(lock)
        found = prefetch(path)
    if NIX_HASH.fullmatch(found) is None:
        raise UpdateError(f"prefetch-npm-deps printed no hash for {url}")
    return found


def prefetch_npm_deps(path: Path) -> str:
    try:
        result = subprocess.run(
            ["prefetch-npm-deps", str(path)], capture_output=True, text=True, timeout=PREFETCH_TIMEOUT, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise UpdateError(f"prefetch-npm-deps failed: {error}") from None
    lines = result.stdout.split()
    if result.returncode != 0 or not lines:
        raise UpdateError(f"prefetch-npm-deps exited {result.returncode}")
    return lines[-1]


def rehashed(flake: str, name: str, url: str, get, prefetch) -> str:
    pattern = re.compile(rf'(src = inputs\.{re.escape(name)};\s*npmDepsHash = ")([^"]*)(")')
    if pattern.search(flake) is None:
        return flake
    value = npm_deps_hash(url, get, prefetch)
    return pattern.sub(lambda match: match.group(1) + value + match.group(3), flake, count=1)


def update(flake: str, get, prefetch) -> tuple:
    """
    Args:
        flake: Text of flake.nix.
        get: Fetches a URL's body.
        prefetch: Returns the npmDepsHash of a package-lock.json path.

    Returns:
        The text with every versioned registry input on its newest stable
        release and the npmDepsHash of each moved npm project recomputed, and
        one line per moved input.
    """
    moved = []
    for name, url in INPUT.findall(flake):
        new = resolved(url, get)
        if new != url:
            flake = rehashed(flake.replace(f'"{url}"', f'"{new}"'), name, new, get, prefetch)
            moved.append(f"{name}: {url} -> {new}")
    return flake, moved


def main(argv: list) -> int:
    """
    Args:
        argv: The path of flake.nix, alone.

    Returns:
        0 after rewriting the file, 1 on any failure, which leaves it unchanged.
    """
    if len(argv) != 1:
        print("usage: inputs.py <flake.nix>", file=sys.stderr)
        return 1
    path = Path(argv[0])
    try:
        flake, moved = update(path.read_text(encoding="utf-8"), fetch, prefetch_npm_deps)
    except UpdateError as error:
        print(f"inputs.py: {error}", file=sys.stderr)
        return 1
    path.write_text(flake, encoding="utf-8")
    for line in moved:
        print(line)
    if not moved:
        print("every versioned input is on its newest stable release")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
