#!/usr/bin/env kvb-quality-python
from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import time
from pathlib import Path

from verdict import WEIGHTS

CACHE = "security-cache"
CACHE_SECONDS = 24 * 3600
SCRIPTS = Path(__file__).resolve().parent
NOTHING = type(None)
SHAPE = {
    "severity": (str,), "rule": (str, NOTHING), "path": (str,), "line": (int, NOTHING),
    "sha1": (str, NOTHING), "context": (str, NOTHING),
}


def keyed(medusa: str, tree: Path, names: dict[str, str], missed: list[str], env: dict[str, str]) -> str:
    """Returns:
        the cache key of a scan: the sha256 over the name and content of
        every script of this skill, the resolved medusa binary with its mtime
        and size, PATH, the files not covered, every MEDUSA_* variable of env
        and the tree path, repository path, mode and content of every copied
        file.
    """
    binary = Path(medusa).resolve()
    info = binary.stat()
    key = hashlib.sha256()
    for script in sorted(SCRIPTS.glob("*.py")):
        key.update(f"{script.name}\0".encode() + hashlib.sha256(script.read_bytes()).digest())
    key.update(f"\0{binary}\0{info.st_mtime_ns}\0{info.st_size}\0{os.environ.get('PATH', '')}\0".encode())
    key.update("".join(f"{name}\0" for name in missed).encode() + b"\0")
    key.update("".join(f"{k}={v}\0" for k, v in sorted(env.items()) if k.startswith("MEDUSA_")).encode())
    for scratch, name in sorted(names.items()):
        path = tree / scratch
        key.update(f"{scratch}\0{name}\0{path.stat().st_mode & 0o777:o}\0".encode())
        key.update(hashlib.sha256(path.read_bytes()).digest())
    return key.hexdigest()


def shelf(root: Path) -> Path | None:
    """Returns:
        <root>/CACHE, created where missing, when it is a directory of the
        current user that neither group nor others may write, else None.
    """
    folder = root / CACHE
    try:
        folder.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = folder.lstat()
    except OSError:
        return None
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
        return None
    return folder


def shaped(found: object) -> bool:
    """Returns:
        whether found is a list of findings of SHAPE, each with a known severity.
    """
    return isinstance(found, list) and all(
        isinstance(f, dict) and f.keys() == SHAPE.keys() and all(isinstance(f[k], t) for k, t in SHAPE.items())
        and f["severity"] in WEIGHTS
        for f in found
    )


def recalled(folder: Path, key: str) -> list[dict] | None:
    """Returns:
        the findings cached under key, None for a missing, expired, foreign or
        malformed entry.
    """
    entry = folder / f"{key}.json"
    try:
        info = entry.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or time.time() - info.st_mtime > CACHE_SECONDS:
            return None
        found = json.loads(entry.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return found if shaped(found) else None


def remember(folder: Path, key: str, found: list[dict]) -> None:
    now = time.time()
    for old in folder.glob("*.json"):
        try:
            if now - old.lstat().st_mtime > CACHE_SECONDS:
                old.unlink()
        except OSError:
            continue
    try:
        descriptor, name = tempfile.mkstemp(dir=folder, prefix=".", suffix=".tmp")
    except OSError:
        return
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(found, handle)
        os.replace(name, folder / f"{key}.json")
    except OSError:
        Path(name).unlink(missing_ok=True)
