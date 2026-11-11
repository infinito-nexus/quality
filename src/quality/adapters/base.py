import os
from dataclasses import dataclass


@dataclass(frozen=True, eq=False)
class Bound:
    binding: object
    files: list


@dataclass(frozen=True, eq=False)
class Command:
    """
    Args:
        prefix: Arguments before the files.
        files: The files of this command.
        bound: The bindings the files came from.
        log: The tool's stderr once it ran, for an adapter whose findings
            depend on what the tool logged.
        rescan: True for the second run over the files an adapter's first
            run could not read.
    """

    prefix: list
    files: list
    bound: list
    log: bytes = b""
    rescan: bool = False


def all_files(bound: list) -> list:
    return sorted({path for item in bound for path in item.files})


def relative(reported: str, root) -> str:
    return os.path.normpath(os.path.relpath(reported, root))


def known_path(reported: str, snapshot) -> str:
    """
    Args:
        reported: Path as a tool printed it, relative to the snapshot root.
        snapshot: Snapshot the tool ran on.

    Returns:
        The snapshot's own spelling of the path.

    Raises:
        KeyError: The tool named a path outside the snapshot.
    """
    if reported in snapshot.files:
        return reported
    # Exception: ruff prints a non-UTF-8 file name with U+FFFD, so the lossy
    # spelling is mapped back instead of treating the file as unknown.
    lossy = {os.fsencode(path).decode("utf-8", "replace"): path for path in snapshot.files}
    return lossy[reported]
