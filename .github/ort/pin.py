import http.client
import json
import re
import sys
import urllib.parse
from pathlib import Path

PIN = re.compile(r"(?P<host>[a-z0-9.-]+)/(?P<name>[a-z0-9._/-]+):(?P<tag>[0-9]+\.[0-9]+\.[0-9]+)@(?P<digest>sha256:[0-9a-f]{64})")
RELEASE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
NEXT = re.compile(r'<(/v2/[^>]+)>;\s*rel="next"')
MANIFEST_TYPES = "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json"
HTTPS = "https://"
OK = 200
TIMEOUT = 30
MAX_BYTES = 4 << 20
MAX_PAGES = 100
PAGE_SIZE = 1000


class PinError(Exception):
    pass


def request(method: str, url: str, headers: dict) -> tuple:
    """
    Args:
        method: GET or HEAD.
        url: An https URL.
        headers: Request headers.

    Returns:
        The response headers and its body, over a certificate-checked
        connection that follows no redirect.

    Raises:
        PinError: The URL is not https, the answer is no 200, or its body
            exceeds MAX_BYTES.
    """
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise PinError(f"refused the non-https URL {url}")
    connection = http.client.HTTPSConnection(parts.hostname, parts.port, timeout=TIMEOUT)
    try:
        connection.request(method, urllib.parse.urlunsplit(("", "", parts.path, parts.query, "")), headers=headers)
        response = connection.getresponse()
        body = response.read(MAX_BYTES + 1)
    finally:
        connection.close()
    if response.status != OK:
        raise PinError(f"{url} answered {response.status}")
    if len(body) > MAX_BYTES:
        raise PinError(f"{url} answered more than {MAX_BYTES} bytes")
    return response.headers, body


def parsed(text: str) -> re.Match:
    """
    Args:
        text: Content of the pin file.

    Returns:
        The match of its one line: host, name, tag and digest.

    Raises:
        PinError: It is no <repository>:<semver>@sha256:<64 hex> pin.
    """
    found = PIN.fullmatch(text.strip())
    if found is None or text.count("\n") > 1:
        raise PinError("the pin file holds no <repository>:<semver>@sha256:<64 hex> line")
    return found


def field(body: bytes, key: str):
    """
    Args:
        body: A registry answer.
        key: Field of its JSON object.

    Returns:
        The field's value, or None without it.

    Raises:
        PinError: The answer is no JSON object.
    """
    document = json.loads(body)
    if not isinstance(document, dict):
        raise PinError("a registry answer is no JSON object")
    return document.get(key)


def token(host: str, name: str, fetch) -> str:
    query = urllib.parse.urlencode({"scope": f"repository:{name}:pull", "service": host})
    value = field(fetch("GET", f"{HTTPS}{host}/token?{query}", {})[1], "token")
    if not isinstance(value, str) or not value:
        raise PinError(f"{host} gave no anonymous pull token for {name}")
    return value


def tags(host: str, name: str, auth: dict, fetch) -> list:
    """
    Args:
        host: Registry host.
        name: Repository on it.
        auth: Authorization header of the pull token.
        fetch: request() or a stub of it.

    Returns:
        Every tag of the repository, across the pages its Link headers name.

    Raises:
        PinError: A page holds no list of tag names, or there are more than MAX_PAGES.
    """
    found = []
    path = f"/v2/{name}/tags/list?n={PAGE_SIZE}"
    for _page in range(MAX_PAGES):
        headers, body = fetch("GET", f"{HTTPS}{host}{path}", auth)
        page = field(body, "tags")
        if not isinstance(page, list) or not all(isinstance(tag, str) for tag in page):
            raise PinError(f"{host} answered a tag page without a list of tag names")
        found += page
        link = headers.get("Link")
        following = None if link is None else NEXT.search(link)
        if following is None:
            return found
        path = following.group(1)
    raise PinError(f"{host} lists more than {MAX_PAGES} pages of tags")


def newest(names: list) -> str:
    releases = [name for name in names if RELEASE.fullmatch(name)]
    if not releases:
        raise PinError("the repository has no <major>.<minor>.<patch> release tag")
    return max(releases, key=lambda name: tuple(int(part) for part in name.split(".")))


def digest(host: str, name: str, tag: str, context: tuple) -> str:
    auth, fetch = context
    headers = fetch("HEAD", f"{HTTPS}{host}/v2/{name}/manifests/{tag}", {**auth, "Accept": MANIFEST_TYPES})[0]
    value = headers.get("Docker-Content-Digest")
    if value is None or not DIGEST.fullmatch(value):
        raise PinError(f"{host} answered no sha256 digest for {name}:{tag}")
    return value


def rewrite(path: Path, fetch) -> str:
    """
    Args:
        path: The pin file.
        fetch: request() or a stub of it.

    Returns:
        The new pin, written to the file: the newest semver release of the
        pinned repository and the digest of its manifest list.

    Raises:
        PinError: The file or a registry answer is malformed.
    """
    current = parsed(path.read_text(encoding="utf-8"))
    host, name = current.group("host"), current.group("name")
    auth = {"Authorization": f"Bearer {token(host, name, fetch)}"}
    tag = newest(tags(host, name, auth, fetch))
    pin = f"{host}/{name}:{tag}@{digest(host, name, tag, (auth, fetch))}"
    path.write_text(f"{pin}\n", encoding="utf-8")
    return pin


def main(argv: list) -> int:
    """
    Args:
        argv: `check <pin file>` prints the pin when well-formed; `update <pin
            file>` rewrites it to the newest release first.

    Returns:
        0 on success, 1 on a malformed pin or registry answer, 2 on a usage error.
    """
    if len(argv) != 2 or argv[0] not in ("check", "update"):
        sys.stderr.write("usage: pin.py check|update <pin file>\n")
        return 2
    path = Path(argv[1])
    try:
        pin = rewrite(path, request) if argv[0] == "update" else parsed(path.read_text(encoding="utf-8")).group(0)
    except (PinError, OSError, ValueError) as error:
        sys.stderr.write(f"pin.py: {error}\n")
        return 1
    sys.stdout.write(f"{pin}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
