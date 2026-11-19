import functools
import hashlib
import json
import os
import stat
from pathlib import Path

from quality import QualityError
from quality.db import (
    FORMAT,
    LICENSE_DIR,
    LICENSE_INDEX,
    LICENSE_KEY,
    MANIFEST,
    UPDATE_HINT,
    file_digest,
    location,
    locked_manifest,
    read_manifest,
    unreadable,
)

LATEST = "*"


def write_index(root: Path, packages: dict) -> str:
    """
    Args:
        root: Bundle directory.
        packages: Ecosystem as osv-scanner names it (PyPI, npm, Packagist,
            crates.io, Go, RubyGems) to package name as gate.package_name()
            normalises it, to version, to the SPDX expression its registry
            declares. The version `*` holds the licence every release shares;
            a release whose licence differs carries its own key.

    Returns:
        The file_digest() of the written index, for db.write_manifest().
    """
    path = root / LICENSE_DIR / LICENSE_INDEX
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"format": FORMAT, "packages": packages}, sort_keys=True) + "\n", encoding="utf-8")
    return file_digest(path)


def read_index(root: Path) -> dict | None:
    """
    Args:
        root: Bundle directory.

    Returns:
        The `packages` map of write_index(), verified against the manifest's
        licenses digest; None when root holds no bundle or the bundle no
        index. Licence data never ages, so a bundle of any date serves it and
        a scan of staged changes still needs no bundle.

    Raises:
        QualityError: The bundle is a link, or its index is no regular file,
            does not match the digest or holds no packages map.
    """
    if root.is_symlink():
        raise QualityError(f"vulnerability database at {root} is a link: point --db at the directory itself")
    if not (root / MANIFEST).is_file():
        return None
    root = root.resolve()
    with locked_manifest(root) as handle:
        expected = read_manifest(handle, root).get(LICENSE_KEY)
        data = None if expected is None else index_bytes(root / LICENSE_DIR / LICENSE_INDEX, root)
    if data is None:
        return None
    if f"sha256:{hashlib.sha256(data).hexdigest()}" != expected:
        raise QualityError(f"licence index at {root} does not match its digest: {UPDATE_HINT}")
    try:
        packages = json.loads(data)["packages"]
    except (ValueError, LookupError, TypeError):
        raise unreadable(root) from None
    if not isinstance(packages, dict):
        raise unreadable(root)
    return packages


def index_bytes(path: Path, root: Path) -> bytes:
    try:
        regular = stat.S_ISREG(os.lstat(path).st_mode)
        data = path.read_bytes() if regular else None
    except OSError:
        raise unreadable(root) from None
    if data is None:
        raise unreadable(root)
    return data


def source(option: str | None, environ: dict):
    """
    Args:
        option: The --db value, or None for the default location.
        environ: The caller's environment.

    Returns:
        A function without arguments that reads the index there on its first
        call and returns the same result on every later one.
    """
    return functools.cache(lambda: read_index(location(option, environ)))


def entry(mapping, key: str):
    return mapping.get(key) if isinstance(mapping, dict) else None


def license_of(packages: dict | None, ecosystem: str, name: str, version: str) -> str | None:
    """
    Args:
        packages: The read_index() map, or None.
        ecosystem: Ecosystem as osv-scanner names it.
        name: Package name as gate.package_name() normalises it.
        version: Exact version, or empty for a range.

    Returns:
        The SPDX expression of that release, else the one every release
        shares, else None.
    """
    versions = entry(entry(packages, ecosystem), name)
    found = entry(versions, version) if version else None
    if not isinstance(found, str):
        found = entry(versions, LATEST)
    return found if isinstance(found, str) and found else None
