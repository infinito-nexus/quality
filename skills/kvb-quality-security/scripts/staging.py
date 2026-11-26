#!/usr/bin/env kvb-quality-python
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import NoReturn

from rulebook import Rules, file_dropped, path_dropped, taken

SKIPPED = (".mjs", ".cjs")
ALIAS = ".js"
NAME_MAX = 255
NEUTRAL = "kvb-scan"


def fail(message: str) -> NoReturn:
    print(f"security: {message}", file=sys.stderr)
    sys.exit(2)


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=repo, capture_output=True, check=False)
    if result.returncode != 0:
        said = result.stderr.decode(errors="replace").strip()
        fail(said if said else f"git {args[0]} failed in {repo}")
    return result.stdout.decode(errors="replace")


def digest(text: str) -> str:
    return hashlib.sha1(text.encode()).hexdigest()


def changed(root: Path, base: str) -> list[str]:
    listed = git(root, "diff", "--no-renames", "-z", "--name-only", base, "--")
    listed += git(root, "ls-files", "-z", "--others", "--exclude-standard")
    return sorted({p for p in listed.split("\0") if p})


def alias(name: str, occupied: set[str]) -> str:
    """Returns:
        the tree path of name, whose suffix medusa skips: its file name with
        ALIAS appended, again while occupied holds that path, or the sha1 of
        name treated the same way when that file name would pass NAME_MAX bytes.
    """
    folder = Path(name).parent
    for stem in (Path(name).name, digest(name)):
        scratch = stem + ALIAS
        while (folder / scratch).as_posix() in occupied:
            scratch += ALIAS
        if len(os.fsencode(scratch)) <= NAME_MAX:
            break
    return (folder / scratch).as_posix()


def copy(root: Path, paths: list[str], tree: Path) -> dict[str, str]:
    """Returns:
        the tree path of every copied file mapped to its repository path.
    """
    names = {}
    top = root.resolve()
    occupied = set(paths) | {parent.as_posix() for name in paths for parent in Path(name).parents}
    for name in paths:
        source = root / name
        if source.is_symlink() or not source.resolve().is_relative_to(top) or not source.is_file():
            continue
        scratch = name
        if Path(name).suffix.lower() in SKIPPED:
            scratch = alias(name, occupied)
            occupied.add(scratch)
        target = tree / scratch
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        names[scratch] = name
    return names


def located(name: str, tree: Path) -> str:
    path = Path(name)
    if not path.is_absolute():
        path = tree / path if (tree / path).exists() else tree.parent / path
    try:
        return path.resolve().relative_to(tree.resolve()).as_posix()
    except ValueError:
        return name


def relocated(names: dict[str, str], tree: Path, found: Rules) -> dict[str, str]:
    """Args:
        names: copy() of the change, tree path to repository path.
        tree: the temporary tree medusa scans.
        found: medusa's rules.

    Returns:
        names after each file a path exclusion drops moved in tree to
        NEUTRAL/<sha1 of its repository path>/<its name>, or to
        NEUTRAL/<that sha1><its suffix> where medusa takes up only that; a file
        neither path makes taken, as one a file pattern drops, stays put.
    """
    moved = {}
    for scratch, name in names.items():
        target, path = scratch, PurePosixPath(scratch)
        if path_dropped(scratch, found) and not file_dropped(path, found):
            key = digest(name)
            candidates = (f"{NEUTRAL}/{key}/{path.name}", f"{NEUTRAL}/{key}{path.suffix}")
            target = next((candidate for candidate in candidates if taken(candidate, found)), scratch)
        if target != scratch:
            (tree / target).parent.mkdir(parents=True, exist_ok=True)
            (tree / scratch).rename(tree / target)
        moved[target] = name
    return moved


def sized(tree: Path) -> dict[str, tuple[int, int, int]]:
    """Returns:
        of every file in the tree by its tree path: its bytes, its LF bytes
        plus one as medusa's `lines_scanned` counts them, and its lines with
        CR, CRLF and LF as breaks, as medusa's scanners read them in text mode.
    """
    sizes = {}
    for path in sorted(p for p in tree.rglob("*") if p.is_file()):
        data = path.read_bytes()
        breaks = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n").count(b"\n")
        sizes[path.relative_to(tree).as_posix()] = (len(data), data.count(b"\n") + 1, breaks + 1)
    return sizes


def oversized(sizes: dict[str, tuple[int, int, int]], found: Rules) -> str | None:
    """Returns:
        the first file over medusa's file or line limit with the limit it breaks, else None.
    """
    for name, (size, _, lines) in sizes.items():
        if size > found.file_limit:
            return f"{name} has {size} bytes, over medusa's {found.file_limit} byte file limit"
        if lines > found.line_limit:
            return f"{name} has {lines} lines, over medusa's {found.line_limit} line regex limit"
    return None
