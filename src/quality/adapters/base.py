import os
from dataclasses import dataclass

from quality import QualityError
from quality.ruledata import require

PARTIAL_SCAN = "security.partial-scan"
THREAD_VARIABLES = ("GOMAXPROCS", "RAYON_NUM_THREADS")


def thread_environment(threads: int | None) -> dict:
    """
    Args:
        threads: Most threads each tool may run, from --threads, or None.

    Returns:
        The variables through which the Go tools (gitleaks, trivy,
        osv-scanner, actionlint) and ruff take the cap; none without a cap.
    """
    if threads is None:
        return {}
    return {name: str(threads) for name in THREAD_VARIABLES}


def thread_args(settings: dict, flag: str) -> list:
    """
    Args:
        settings: The tool's entry in tools.yml with the values of this run.
        flag: The tool's own option for its thread count.

    Returns:
        The option with the run's --threads value, or nothing without a cap.
    """
    threads = require(settings, "threads", "runtime")
    return [] if threads is None else [flag, str(threads)]


@dataclass(frozen=True, eq=False)
class Bound:
    """
    Args:
        binding: A rule bound to one tool.
        files: Paths the tool checks for that rule.
        kinds: Kinds of each of those paths, from extension, glob or shebang.
    """

    binding: object
    files: list
    kinds: dict


@dataclass(frozen=True, eq=False)
class Command:
    """
    Args:
        prefix: Arguments before the files.
        files: The files of this command.
        bound: The bindings the files came from.
        log: The tool's stderr once it ran.
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


def checked_rules(command: Command) -> list:
    return [item.binding.rule for item in command.bound if item.binding.rule.id != PARTIAL_SCAN]


def gap_rule(command: Command, path: str):
    """
    Args:
        command: The command that was to read the file.
        path: File the tool read only in part or not at all.

    Returns:
        The security.partial-scan rule bound to the file, or None.
    """
    return next(
        (item.binding.rule for item in command.bound if item.binding.rule.id == PARTIAL_SCAN and path in item.files),
        None,
    )


def refuse_non_utf8(tool: str, files: list) -> None:
    """
    Args:
        tool: Name for the error.
        files: Paths the tool would receive.

    Raises:
        QualityError: A name is not UTF-8.
    """
    if not all(map(utf8_name, files)):
        raise QualityError(f"{tool} cannot read a file whose name is not UTF-8")


def utf8_name(path: str) -> bool:
    try:
        os.fsencode(path).decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


@dataclass(frozen=True)
class Skipped:
    """
    Args:
        path: File a tool was given but did not check, or checked only in part.
        reason: Why, without file content.
    """

    path: str
    reason: str


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
    lossy = {os.fsencode(path).decode("utf-8", "replace"): path for path in snapshot.files}
    return lossy[reported]
