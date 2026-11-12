import fcntl
import hashlib
import json
import os
import shutil
import stat
import tempfile
import urllib.request
import zipfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from quality import QualityError
from quality.process import run
from quality.ruledata import RuleData, require

MANIFEST = "manifest.json"
FORMAT = 1
TRIVY_DIR = "trivy"
OSV_DIR = "osv"
CONTENT_DIRS = (TRIVY_DIR, OSV_DIR)
TIMESTAMP = "%Y-%m-%dT%H:%M:%SZ"
UPDATE_HINT = "run `quality db update`"
COPY_CHUNK = 1 << 20
NETWORK_VARIABLES = (
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "NIX_SSL_CERT_FILE",
)


@dataclass(frozen=True)
class Bundle:
    """
    Args:
        root: Bundle directory.
        date: Fetch time from the manifest.
        digest: Content digest from the manifest, verified when opened.
        handle: The manifest, open and shared-locked while the check runs;
            None for a bundle update() returns.
    """

    root: Path
    date: datetime
    digest: str
    handle: object

    def note(self) -> str:
        return f"vulnerability database: {self.date.strftime(TIMESTAMP)} {self.digest}"

    def trivy_cache(self) -> Path:
        return self.root / TRIVY_DIR

    def osv_cache(self) -> Path:
        return self.root / OSV_DIR


def location(option: str | None, environ: dict) -> Path:
    """
    Args:
        option: The --db value, or None.
        environ: The caller's environment.

    Returns:
        The bundle directory: --db, else $XDG_CACHE_HOME/quality/db.

    Raises:
        QualityError: Neither --db, an absolute XDG_CACHE_HOME nor an absolute HOME is given.
    """
    if option:
        return Path(option).absolute()
    cache = environ.get("XDG_CACHE_HOME", "")
    if os.path.isabs(cache):
        return Path(cache) / "quality" / "db"
    home = environ.get("HOME", "")
    if not os.path.isabs(home):
        raise QualityError("environment is missing key 'XDG_CACHE_HOME' and --db is not given")
    return Path(home) / ".cache" / "quality" / "db"


def write_manifest(root: Path, date: datetime, digest: str) -> None:
    document = {"format": FORMAT, "date": date.strftime(TIMESTAMP), "digest": digest}
    (root / MANIFEST).write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")


def unreadable(root: Path) -> QualityError:
    return QualityError(f"vulnerability database at {root} is unreadable: {UPDATE_HINT}")


def locked_manifest(root: Path):
    """
    Args:
        root: Bundle directory.

    Returns:
        The manifest file, open and shared-locked, still the one at root.

    Raises:
        QualityError: The manifest is missing, unreadable, or was replaced
            between opening and locking it.
    """
    path = root / MANIFEST
    try:
        handle = path.open("rb")
    except (FileNotFoundError, NotADirectoryError):
        raise QualityError(f"no vulnerability database at {root}: {UPDATE_HINT}") from None
    except OSError:
        raise unreadable(root) from None
    fcntl.flock(handle, fcntl.LOCK_SH)
    opened = os.fstat(handle.fileno())
    try:
        current = path.stat()
    except OSError:
        current = None
    if current is None or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
        handle.close()
        raise QualityError(f"vulnerability database at {root} was replaced while opening it: run the check again")
    return handle


def read_manifest(handle, root: Path) -> dict:
    try:
        document = json.loads(handle.read())
    except (OSError, ValueError):
        raise unreadable(root) from None
    if not isinstance(document, dict) or document.get("format") != FORMAT:
        raise QualityError(f"vulnerability database at {root} has another format: {UPDATE_HINT}")
    return document


def checked_bundle(root: Path, handle, max_age_days: int, now: datetime) -> Bundle:
    document = read_manifest(handle, root)
    try:
        date = datetime.strptime(document["date"], TIMESTAMP).replace(tzinfo=timezone.utc)
        digest = document["digest"]
    except (KeyError, TypeError, ValueError):
        raise unreadable(root) from None
    if date > now:
        raise QualityError(
            f"vulnerability database at {root} is dated {document['date']}, in the future: {UPDATE_HINT}"
        )
    if now - date > timedelta(days=max_age_days):
        raise QualityError(
            f"vulnerability database from {document['date']} is older than "
            f"{max_age_days} days: {UPDATE_HINT}"
        )
    try:
        actual = tree_digest(root)
    except OSError:
        raise unreadable(root) from None
    if actual != digest:
        raise QualityError(f"vulnerability database at {root} does not match its digest: {UPDATE_HINT}")
    return Bundle(root, date, digest, handle)


def open_bundle(root: Path, max_age_days: int, now: datetime) -> Bundle:
    """
    Args:
        root: Bundle directory.
        max_age_days: Age from limits.yml after which the bundle is refused.
        now: Current UTC time.

    Returns:
        The bundle, its content verified against the manifest digest and
        locked until the process ends. Its root is resolved once, before the
        digest.

    Raises:
        QualityError: The bundle is missing, a link, unreadable, dated in the
            future, older than the limit, or its content does not match its digest.
    """
    if root.is_symlink():
        raise QualityError(
            f"vulnerability database at {root} is a link, which can be retargeted after the digest: "
            "point --db at the directory itself"
        )
    root = root.resolve()
    handle = locked_manifest(root)
    try:
        return checked_bundle(root, handle, max_age_days, now)
    except QualityError:
        handle.close()
        raise


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(COPY_CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def content_files(root: Path) -> list:
    """
    Args:
        root: Bundle directory.

    Returns:
        Every file below the content directories, sorted.

    Raises:
        QualityError: An entry anywhere in the bundle is a symbolic link or
            neither a directory nor a regular file.
    """
    files = []
    for directory, folders, names in os.walk(root):
        for name in [*folders, *names]:
            path = Path(directory) / name
            mode = os.lstat(path).st_mode
            if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                raise QualityError(
                    f"vulnerability database at {root} holds {path.relative_to(root).as_posix()}, "
                    f"which is no regular file: {UPDATE_HINT}"
                )
        files += [Path(directory) / name for name in names]
    content = [root / name for name in CONTENT_DIRS]
    return sorted(path for path in files if any(path.is_relative_to(top) for top in content))


def tree_digest(root: Path) -> str:
    """
    Args:
        root: Bundle directory.

    Returns:
        One sha256 over the path and content digest of every file below the
        content directories.

    Raises:
        QualityError: The bundle holds a link or a special file.
    """
    outer = hashlib.sha256()
    for path in content_files(root):
        outer.update(f"{file_digest(path)}  {path.relative_to(root).as_posix()}\n".encode())
    return f"sha256:{outer.hexdigest()}"


def network_env(path_value: str, home: Path, environ: dict) -> dict:
    passed = {name: environ[name] for name in NETWORK_VARIABLES if name in environ}
    return {
        "PATH": path_value,
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home),
        "XDG_CACHE_HOME": str(home),
        "LC_ALL": "C.UTF-8",
        **passed,
    }


def fetch_trivy(work: Path, data: RuleData, path_value: str, environ: dict) -> None:
    settings = data.tool("trivy")
    binary = shutil.which("trivy", path=path_value)
    if binary is None:
        raise QualityError("missing tool: trivy")
    repository = require(settings, "db_repository", "tools.yml trivy")
    timeout = require(settings, "update_timeout", "tools.yml trivy")
    home = work / "home"
    home.mkdir()
    argv = [
        binary,
        "image",
        "--download-db-only",
        "--cache-dir",
        str(work / TRIVY_DIR),
        "--db-repository",
        repository,
        "--timeout",
        f"{timeout}s",
        "--no-progress",
        "--quiet",
        "--disable-telemetry",
        "--skip-version-check",
    ]
    result = run(argv, str(work), network_env(path_value, home, environ), timeout)
    shutil.rmtree(home)
    if result.code != 0:
        raise QualityError(f"trivy could not fetch {repository} (exit {result.code})")


def download(url: str, destination: Path, timeout: int) -> None:
    if not url.startswith("https://"):
        raise QualityError(f"rule data: osv-scanner offline_url must use https, not {url}")
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            with destination.open("wb") as stream:
                shutil.copyfileobj(response, stream, COPY_CHUNK)
    except OSError as error:
        raise QualityError(f"could not fetch {url}: {type(error).__name__}") from None
    if not zipfile.is_zipfile(destination):
        raise QualityError(f"{url} did not return a zip archive")


def fetch_osv(work: Path, data: RuleData) -> None:
    settings = data.tool("osv-scanner")
    url = require(settings, "offline_url", "tools.yml osv-scanner")
    layout = require(settings, "offline_path", "tools.yml osv-scanner")
    timeout = require(settings, "update_timeout", "tools.yml osv-scanner")
    for ecosystem in require(settings, "ecosystems", "tools.yml osv-scanner"):
        destination = work / OSV_DIR / layout.format(ecosystem=ecosystem)
        destination.parent.mkdir(parents=True, exist_ok=True)
        download(url.format(ecosystem=ecosystem), destination, timeout)


def refuse_foreign(root: Path) -> None:
    if root.is_symlink() or (root.exists() and not root.is_dir()):
        raise QualityError(f"{root} is not a directory, refusing to replace it")
    if root.is_dir() and any(root.iterdir()) and not (root / MANIFEST).is_file():
        raise QualityError(f"{root} holds no vulnerability database, refusing to replace it")


def exclusive_manifest(root: Path):
    """
    Args:
        root: Bundle directory about to be replaced.

    Returns:
        Its manifest, open and exclusively locked.

    Raises:
        QualityError: A running check holds the bundle open.
    """
    handle = (root / MANIFEST).open("rb")
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        handle.close()
        raise QualityError(
            f"vulnerability database at {root} is in use by a running check: {UPDATE_HINT} when it ends"
        ) from None
    return handle


def replace_bundle(work: Path, root: Path) -> None:
    if not (root / MANIFEST).is_file():
        retire(work, root)
        return
    with exclusive_manifest(root):
        retire(work, root)


def retire(work: Path, root: Path) -> None:
    if not root.exists():
        work.rename(root)
        return
    retired = root.with_name(f"{work.name}.retired")
    root.rename(retired)
    work.rename(root)
    shutil.rmtree(retired)


def update(root: Path, data: RuleData, path_value: str, environ: dict) -> Bundle:
    """
    Args:
        root: Bundle directory to create or replace.
        data: Rule data naming the trivy repository and the osv-scanner ecosystems.
        path_value: Validated PATH the tools are resolved from.
        environ: The caller's environment; only proxy and certificate variables pass.

    Returns:
        The new bundle. The old one stays in place until the new one is complete.

    Raises:
        QualityError: A fetch failed, root holds something else, or its
            directory is not writable, as in a read-only container whose
            mount point is root itself.
    """
    refuse_foreign(root)
    try:
        root.parent.mkdir(parents=True, exist_ok=True)
        work = Path(tempfile.mkdtemp(prefix=f".{root.name}.", dir=root.parent))
    except OSError as error:
        raise QualityError(
            f"cannot stage the update next to {root} ({error.strerror}), since only a rename "
            "in the same directory swaps it whole: point --db at a directory inside a writable one"
        ) from None
    try:
        fetch_trivy(work, data, path_value, environ)
        fetch_osv(work, data)
        date = datetime.now(timezone.utc).replace(microsecond=0)
        digest = tree_digest(work)
        write_manifest(work, date, digest)
        replace_bundle(work, root)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return Bundle(root, date, digest, None)
