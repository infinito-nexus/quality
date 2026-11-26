import hashlib
import json
from collections import Counter
from pathlib import Path

from quality.agent import nofollow, state

REACH = 2
Key = tuple[str, str, str, str | None]


def digest(text: str) -> str:
    return hashlib.sha1(text.encode(), usedforsecurity=False).hexdigest()


def fingerprint(text: str, line: int | None) -> tuple[str | None, str | None]:
    """
    Args:
        text: Content of the finding's file.
        line: The finding's line, or None for a file-level finding.

    Returns:
        (sha1 of the stripped line, or of the whole text without a line,
        sha1 of the stripped lines up to REACH around it or None), the
        fingerprint an accepted row names; (None, None) for a line outside
        the text.
    """
    if line is None:
        return digest(text), None
    lines = text.splitlines()
    if not 1 <= line <= len(lines):
        return None, None
    around = lines[max(0, line - 1 - REACH) : line + REACH]
    return digest(lines[line - 1].strip()), digest("\n".join(row.strip() for row in around))


def parse(text: str, source: str) -> set[Key]:
    """
    Args:
        text: Content of an accepted-findings ledger, one JSON row per line.
        source: The ledger's name for the error message.

    Returns:
        (rule, path, sha1, context or None) of every row; ValueError naming
        source and line for a row without rule, path and sha1.
    """
    keys = set()
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
            keys.add((row["rule"], row["path"], row["sha1"], row.get("context")))
        except (ValueError, KeyError, TypeError, AttributeError):
            raise ValueError(f"{source}:{number}: want a JSON row with rule, path and sha1") from None
    return keys


def listing(root: Path) -> set[Key]:
    """
    Args:
        root: A state root holding the ledger under state.ACCEPTED.

    Returns:
        parse() of that ledger, read without following a link; a missing one
        holds none; OSError when it is unreadable.
    """
    path = root / state.ACCEPTED
    try:
        text = nofollow.read_text(root, path)
    except FileNotFoundError:
        return set()
    return parse(text, str(path))


def rows() -> set[Key]:
    """
    Returns:
        The rows of the shared ledger under the council root and of its kept
        copy under the host-only root.
    """
    return listing(state.root()) | listing(state.durable())


def accepted(keys: list[Key | None], reviewed: set[Key]) -> list[bool]:
    """
    Args:
        keys: (rule, path, sha1, context) per finding of one scan, None for
            a finding without a fingerprint.
        reviewed: The ledger's rows.

    Returns:
        A flag per key, True when a row accepts it: a row with context
        accepts that exact key, one without only while no other key of the
        scan shares its rule, path and sha1, so one row never hides a twin.
    """
    shared = Counter(key[:3] for key in keys if key is not None)
    return [
        key is not None and (key in reviewed or (shared[key[:3]] == 1 and (*key[:3], None) in reviewed))
        for key in keys
    ]
