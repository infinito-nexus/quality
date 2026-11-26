#!/usr/bin/env kvb-quality-python
"""
Args:
    --repo: A directory inside the git work tree.
    --staged | --base REF: the lines the index adds against HEAD, or the
        working tree against REF; untracked files are in neither.
    --confirm PATH:LINE: an added Exception comment the agent confirmed as a
        real exception; repeatable.

Output:
    `<path>:<line>: <comment>` per added Exception comment not confirmed,
    then QUESTION.

Exit codes:
    0 none left unconfirmed, 1 unconfirmed ones listed, 2 usage or git error.
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

from quality.agent.diff import DiffError, added_lines, git

MARKER = re.compile(r"(?:#|//|/\*+|\{#|<!--|--|\"\"\"|''')\s*Exception:")
QUESTION = (
    "Is each line above a real exception, a concrete trip-wire the code cannot show? "
    "If it tells why the code is shaped this way, delete it and put the reason into the commit body; "
    "else rerun with --confirm <path>:<line> for each line."
)


def options(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="exceptions.py")
    parser.add_argument("--repo", required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--staged", action="store_true")
    mode.add_argument("--base")
    parser.add_argument("--confirm", action="append", default=[])
    return parser.parse_args(argv)


def lines(root: Path, path: str, staged: bool) -> list[str]:
    """
    Args:
        root: The work tree root.
        path: A path relative to it.
        staged: True reads the index, False the working tree.

    Returns:
        The file's lines, none for a file git or the disk cannot give.
    """
    if staged:
        shown = subprocess.run(["git", "show", f":{path}"], cwd=root, capture_output=True, check=False)
        data = shown.stdout if shown.returncode == 0 else b""
    else:
        try:
            data = (root / path).read_bytes()
        except OSError:
            data = b""
    return data.decode("utf-8", "replace").splitlines()


def unconfirmed(root: Path, args: argparse.Namespace) -> list[str]:
    """
    Returns:
        `<path>:<line>: <comment>` of every added line holding an Exception
        marker that --confirm does not name.
    """
    hits = []
    for path, numbers in sorted(added_lines(root, staged=args.staged, base=args.base).items()):
        text = lines(root, path, args.staged)
        for number in sorted(n for n in numbers if n <= len(text) and MARKER.search(text[n - 1])):
            if f"{path}:{number}" not in args.confirm:
                hits.append(f"{path}:{number}: {text[number - 1].strip()}")
    return hits


def main(argv: list[str]) -> int:
    args = options(argv)
    try:
        hits = unconfirmed(Path(git(Path(args.repo), "rev-parse", "--show-toplevel").strip()), args)
    except (DiffError, OSError) as error:
        print(f"exceptions: {error}", file=sys.stderr)
        return 2
    if hits:
        print("\n".join([*hits, QUESTION]))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
