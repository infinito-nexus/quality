from __future__ import annotations

import ast
import re
import subprocess
from pathlib import Path

HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
OPTIONS = (
    "--no-color",
    "--no-ext-diff",
    "--no-textconv",
    "--find-renames",
    "--unified=0",
    "--src-prefix=a/",
    "--dst-prefix=b/",
)


class DiffError(RuntimeError):
    pass


def revisions(staged: bool, base: str | None) -> list[str]:
    """
    Args:
        staged: True compares the index, False the working tree.
        base: The revision compared against; None compares against HEAD.

    Returns:
        The git diff arguments that select those two sides; the index against
        HEAD is `--cached` alone, so an unborn branch diffs its index against
        the empty tree.

    Raises:
        DiffError: base starts with `-`, so git would read it as an option.
    """
    if base is not None and base.startswith("-"):
        raise DiffError(f"not a revision: {base!r}")
    if staged:
        return ["--cached"] if base is None else ["--cached", base]
    return ["HEAD"] if base is None else [base]


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=repo, capture_output=True, check=False)
    if result.returncode != 0:
        raise DiffError(f"git {args[0]}: {result.stderr.decode('utf-8', 'replace').strip()}")
    return result.stdout.decode("utf-8", "replace")


def unquote(name: str) -> str:
    """
    Args:
        name: A path as git prints it in a diff header, C-quoted when it
            holds special bytes.

    Returns:
        The path, UTF-8 decoded, undecodable bytes replaced.
    """
    if name.startswith('"'):
        return ast.literal_eval(f"b{name}").decode("utf-8", "replace")
    return name


def new_path(row: str) -> str | None:
    """
    Args:
        row: A `+++ ` header line of a diff with OPTIONS.

    Returns:
        The path on the new side, None for /dev/null.
    """
    target = unquote(row[4:].removesuffix("\t"))
    return target[2:] if target.startswith("b/") else None


def parse(diff: str) -> dict[str, set[int]]:
    """
    Args:
        diff: Output of git diff with OPTIONS.

    Returns:
        Each path on the new side to the 1-based numbers of the lines the
        diff adds there; a deleted file and a binary change add none.
    """
    added: dict[str, set[int]] = {}
    path, line, header = None, 0, False
    for row in diff.split("\n"):
        if row.startswith("diff "):
            path, header = None, True
        elif header and row.startswith("+++ "):
            path = new_path(row)
        elif row.startswith("@@"):
            header = False
            hunk = HUNK.match(row)
            if hunk:
                line = int(hunk.group(1))
            else:
                path = None
        elif path and not header and row.startswith("+"):
            added.setdefault(path, set()).add(line)
            line += 1
    return added


def added_lines(repo: Path, *, staged: bool, base: str | None) -> dict[str, set[int]]:
    """
    Args:
        repo: A directory inside the git work tree.
        staged: True diffs the index (`git diff --cached`), False the working
            tree; untracked files are in neither diff.
        base: The revision the diff starts from; None starts from HEAD.

    Returns:
        Each changed path, relative to the work tree root, to the 1-based
        numbers of the lines the diff adds there.

    Raises:
        DiffError: git fails, or base starts with `-`.
    """
    return parse(git(repo, "diff", *OPTIONS, *revisions(staged, base), "--"))
