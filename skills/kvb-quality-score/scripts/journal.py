#!/usr/bin/env kvb-quality-python
"""
Environment:
    AGENTS_COUNCIL_ROOT, XDG_STATE_HOME, HOME: the council directory
        quality.agent.state resolves, shared by every agent on the host. The
        journal is its JOURNAL file, display data for the hub's burndown only,
        never a gate input.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import re
import subprocess
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import TypeVar
from urllib.parse import urlsplit

T = TypeVar("T")
LABELS = Path(__file__).resolve().parents[1] / "labels.json"
STATE = "quality.agent.state"
NOFOLLOW = "quality.agent.nofollow"
SCP = re.compile(r"(?:[^@/:]+@)?([^/:]+):(?!//)(.+)")
FILE_MODE = 0o600
LABEL_ERRORS = (OSError, ValueError, LookupError, TypeError, AttributeError)


def load_labels(path: Path) -> dict:
    """Args:
        path: a labels.json with "metrics" and "extras", each key mapped to
            {"emoji", "label", "former"}.

    Returns:
        The parsed file; metrics in block order.
    """
    return json.loads(path.read_text(encoding="utf-8"))


def journal_path() -> Path:
    """Returns:
        The JOURNAL file in the council root of quality.agent.state; OSError
        naming that module when it is missing or unusable.
    """
    return helper(STATE, lambda state: state.root() / state.JOURNAL)


def git(repo: Path | str, *args: str) -> str:
    """Args:
        repo: the directory git runs in.
        args: the git arguments.

    Returns:
        The stripped stdout, bytes outside UTF-8 replaced; LookupError naming
        the command and git's stderr on one line when git is missing, the
        directory is gone or git fails.
    """
    try:
        done = subprocess.run(["git", *args], cwd=repo, capture_output=True, encoding="utf-8", errors="replace", check=False)
    except OSError as error:
        raise LookupError(f"git {args[0]} in {repo}: {error}") from None
    if done.returncode != 0:
        raise LookupError(f"git {args[0]} in {repo}: {' '.join(done.stderr.split())}")
    return done.stdout.strip()


def git_read(repo: Path, *args: str) -> str | None:
    """Args:
        repo: the directory git runs in.
        args: the git arguments.

    Returns:
        The stdout of git(), or None when it raises.
    """
    try:
        return git(repo, *args)
    except LookupError:
        return None


def identity(url: str | None) -> str | None:
    """Args:
        url: a git remote URL: https, ssh, scp-like or a local path.

    Returns:
        host/path without .git for a hosted remote, so ssh, scp-like and https
        clones of one repository match; a local path unchanged; None for None.
    """
    if url is None:
        return None
    scp = SCP.fullmatch(url)
    if "://" in url:
        parts = urlsplit(url)
        host, path = parts.hostname, parts.path
    elif scp:
        host, path = scp.groups()
    else:
        return url
    if not host:
        return url
    return f"{host.lower()}/{path.strip('/').removesuffix('.git')}"


def origin(repo: Path) -> tuple[str | None, str | None]:
    """Args:
        repo: a directory inside a git work tree.

    Returns:
        (remote, path): the identity() of its origin remote and its top level
        path; None for what git cannot tell.
    """
    return identity(git_read(repo, "remote", "get-url", "origin")), git_read(repo, "rev-parse", "--show-toplevel")


def entry(time: int, place: tuple[str | None, str | None], branch: str | None, sha: str | None, scored: tuple[dict, str]) -> dict:
    """Args:
        time: epoch seconds: the render for score.py, the commit for backfill.py.
        place: origin() of the repository.
        branch: the branch the block belongs to.
        sha: the commit holding the block, None for a render.
        scored: (values, block): per metric key its number, None where the
            block shows none, and the message block text the digest covers.

    Returns:
        One journal row.
    """
    remote, path = place
    values, block = scored
    digest = hashlib.sha256(block.encode("utf-8")).hexdigest()
    return {"time": time, "remote": remote, "path": path, "branch": branch, "sha": sha, "values": values, "digest": digest}


def line(row: dict) -> str:
    return json.dumps(row, ensure_ascii=False) + "\n"


def unusable(name: str, error: Exception) -> OSError:
    return OSError(f"helper {name} unusable ({type(error).__name__}): install or update kvb-quality")


def helper(name: str, use: Callable[[ModuleType], T]) -> T:
    """Args:
        name: a module of quality.agent, imported on first use so that every
            layout of score.py but the journal works without it.
        use: what to do with it.

    Returns:
        The result of use; its OSError unchanged, any other failure importing
        or using the module as one OSError naming it, never a
        FileNotFoundError.
    """
    try:
        loaded = importlib.import_module(name)
    except Exception as error:
        raise unusable(name, error) from None
    try:
        return use(loaded)
    except OSError:
        raise
    except Exception as error:
        raise unusable(name, error) from None


def nofollow(use: Callable[[ModuleType], T]) -> T:
    """Args:
        use: what to do with quality.agent.nofollow.

    Returns:
        helper() of it.
    """
    return helper(NOFOLLOW, use)


def append(path: Path, rows: list[dict]) -> None:
    """Args:
        path: the journal in the council root, made with the helper's mode
            0o700; a linked root, a link, FIFO or other non-regular file there
            raises OSError without blocking.
        rows: the rows to append, one JSON line each, in one write.
    """
    text = "".join(line(row) for row in rows)

    def write(module: ModuleType) -> None:
        path.parent.mkdir(mode=module.DIRECTORY_MODE, parents=True, exist_ok=True)
        module.append(path.parent, path, text, FILE_MODE)

    nofollow(write)


def read(path: Path) -> str:
    """Args:
        path: the journal, guarded as for append(); a missing one raises
            FileNotFoundError.

    Returns:
        Its text, undecodable bytes replaced.
    """
    return nofollow(lambda module: module.read_text(path.parent, path))


def known(path: Path) -> set[tuple[str | None, str]]:
    """Args:
        path: the journal, read through read(); a missing one holds none.

    Returns:
        (remote, sha) of every row with a sha.
    """
    try:
        text = read(path)
    except FileNotFoundError:
        return set()
    keys = set()
    for row_line in text.splitlines():
        try:
            row = json.loads(row_line)
        except ValueError:
            continue
        if isinstance(row, dict) and isinstance(row.get("sha"), str):
            keys.add((row.get("remote"), row["sha"]))
    return keys
