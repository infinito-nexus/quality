import json
import os
import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from quality import QualityError
from quality.adapters.base import Command, all_files
from quality.gate import code_hit
from quality.snapshot import BINARY

PATH = "path"
CONTENT = "content"
NAMED = "named"
STEM = "file"
WHOLE_NAMES = ("nuget.config",)
PLAIN_SUFFIX = re.compile(r"\.[A-Za-z0-9_+-]+")
WINDOW = 99_999
PEEK = 25_000
SNIFF = 32_774
LOG_LINE = re.compile(r"^\S+ (?P<level>[A-Z]{3}) (?P<message>.*)$")
EVENT = re.compile(
    r"^(?:scanning path|skipping (?P<skip>.+?)) "
    r'path=(?:"(?P<quoted>(?:[^"\\]|\\.)*)"|(?P<bare>\S+))$'
)
FAILURE_LEVELS = ("ERR", "FTL")
PATH_SKIPS = ("archive:", "file: global allowlist", "directory: global allowlist")
BINARY_SKIP = "binary file"
EMPTY_SKIP = "empty file"


@dataclass(frozen=True)
class Piece:
    offset: int
    data: bytes | None


def commands(bound: list, _settings: dict, config_file) -> list:
    """
    Args:
        bound: The rule with its files.
        _settings: Unused tool entry.
        config_file: Extends gitleaks' default rules and replaces .gitleaks.toml,
            GITLEAKS_CONFIG and GITLEAKS_CONFIG_TOML.

    Returns:
        One command in redact mode that ignores `gitleaks:allow`. Leaks exit 0,
        because gitleaks exits 1 on a fatal error, so that exit fails closed.
        The trace log names every file gitleaks read or skipped.
    """
    prefix = [
        "dir",
        "--no-banner",
        "--no-color",
        "--log-level",
        "trace",
        "--redact",
        "--ignore-gitleaks-allow",
        "--exit-code",
        "0",
        "--config",
        str(config_file),
        "--report-format",
        "json",
        "--report-path",
        "-",
    ]
    return [Command(prefix, all_files(bound), bound)]


def bounds(data: bytes, limit: int) -> list:
    """
    Args:
        data: Bytes of one file.
        limit: Most bytes one window may hold, more than twice PEEK.

    Returns:
        (start, end) of windows that overlap by at least PEEK bytes and start
        and end at line boundaries. A window ends inside a line only when no
        line ends in its last PEEK bytes, and the next one starts inside a
        line only when that line began at or before the current window's start.

    Raises:
        QualityError: The limit leaves no room past two overlaps, so the next
            window could start at or before the current one.
    """
    if limit <= 2 * PEEK:
        raise QualityError(f"gitleaks window of {limit} bytes must exceed twice the overlap")
    found = []
    start = 0
    while start + limit < len(data):
        cut = data.rfind(b"\n", start + limit - PEEK, start + limit)
        end = start + limit if cut < 0 else cut + 1
        found.append((start, end))
        before = data.rfind(b"\n", start, end - PEEK)
        start = end - PEEK if before < 0 else before + 1
    found.append((start, len(data)))
    return found


def spans(path: str, snapshot, padded: bool) -> list | None:
    """
    Args:
        path: Path of one file.
        snapshot: Snapshot holding it.
        padded: Leave room for SNIFF newlines before each window.

    Returns:
        (bytes, start, end) per window: the raw bytes and, for UTF-16 or
        UTF-32, also their UTF-8 form. None for a binary blob.
    """
    text = snapshot.text(path)
    if text is None:
        return None
    raw = snapshot.data(path)
    limit = WINDOW - SNIFF if padded else WINDOW
    return [
        (data, start, end)
        for data in ([raw] if raw == text else [raw, text])
        for start, end in bounds(data, limit)
    ]


def pieces(path: str, snapshot, padded: bool) -> list:
    """
    Args:
        path: Path of one file.
        snapshot: Snapshot holding it.
        padded: Put SNIFF newlines before each window.

    Returns:
        One piece per window, with the offset that turns a piece's line into
        the file's line. For a binary blob one piece without data.
    """
    found = spans(path, snapshot, padded)
    if found is None:
        return [Piece(0, None)]
    padding = b"\n" * SNIFF if padded else b""
    return [
        Piece(data.count(b"\n", 0, start) - len(padding), padding + data[start:end])
        for data, start, end in found
    ]


def operands(command: Command, snapshot, work) -> list:
    """
    Args:
        command: The chunk; `rescan` stages the padded second run.
        snapshot: Snapshot holding its files.
        work: Empty working directory of the run, removed afterwards.

    Returns:
        The ignore file location and the one directory gitleaks scans.
    """
    for index, path in enumerate(command.files):
        for number, piece in enumerate(pieces(path, snapshot, command.rescan)):
            folder = work / str(index) / str(number)
            own = folder / PATH / path
            own.parent.mkdir(parents=True)
            if piece.data is None:
                os.link(snapshot.root / path, own)
            else:
                own.write_bytes(piece.data)
            if command.rescan:
                stage_neutral(folder, own, piece, path)
    return ["--gitleaks-ignore-path", ".", "--", "."]


def stage_neutral(folder, own, piece: Piece, path: str) -> None:
    (folder / NAMED).mkdir()
    os.link(own, folder / NAMED / named_copy(path))
    if piece.data is not None:
        os.link(own, folder / CONTENT)


def named_copy(path: str) -> str:
    """
    Args:
        path: Path of one file.

    Returns:
        A name the default allowlist can only match by its suffix. A name
        ending in a WHOLE_NAMES entry keeps that entry, because gitleaks'
        nuget-config-password rule matches the whole name.
    """
    name = PurePosixPath(path).name
    whole = [kept for kept in WHOLE_NAMES if name.lower().endswith(kept)]
    if whole:
        return whole[0]
    suffix = PurePosixPath(name).suffix
    return STEM + suffix if PLAIN_SUFFIX.fullmatch(suffix) else STEM


def parse(stdout: bytes, command: Command, snapshot) -> list:
    """
    Args:
        stdout: gitleaks' JSON report.
        command: The chunk, with gitleaks' trace log.
        snapshot: Snapshot holding its files.

    Returns:
        One finding per file, line and rule from the own path copies. A file
        whose own path gitleaks skipped counts in the second run instead, and
        there by its neutral copies.
    """
    rule = command.bound[0].binding.rule
    skipped = skipped_own_paths(command, snapshot)
    layouts = {}
    hits = {}
    for item in json.loads(stdout):
        index, number, kind = PurePosixPath(item["File"]).parts[:3]
        index, number = int(index), int(number)
        if (kind == PATH) == (index in skipped):
            continue
        path = command.files[index]
        if index not in layouts:
            layouts[index] = pieces(path, snapshot, command.rescan)
        start = item["StartLine"]
        line = start + layouts[index][number].offset if start else None
        key = (path, line, item["RuleID"])
        hits.setdefault(key, code_hit(rule, path, line, item["RuleID"], snapshot))
    return list(hits.values())


def rescan(command: Command, snapshot) -> list:
    """
    Args:
        command: The first run's chunk, with gitleaks' trace log.
        snapshot: Snapshot holding its files.

    Returns:
        The files whose own path gitleaks skipped, for the padded second run.
    """
    return [command.files[index] for index in sorted(skipped_own_paths(command, snapshot))]


def skipped_own_paths(command: Command, snapshot) -> set:
    """
    Args:
        command: The chunk, with gitleaks' trace log.
        snapshot: Snapshot holding its files.

    Returns:
        The indices whose own path copies gitleaks skipped, other than binary
        blobs it skipped as binary.

    Raises:
        QualityError: gitleaks logged an error, named neither reading nor
            skipping a copy it was given, skipped text the runner gave it in
            the second run, or skipped a path for a reason no run covers.
    """
    expected, binary = expected_copies(command, snapshot)
    seen = copy_events(command.log)
    if set(seen) != expected:
        raise QualityError("gitleaks did not report on every file it was given")
    for (index, _, kind), skip in seen.items():
        if skip is not None and not tolerated(kind, skip, index in binary or not command.rescan):
            raise QualityError(f"gitleaks skipped text the runner gave it: {skip}")
    return {
        index for (index, _, kind), skip in seen.items() if kind == PATH and diverts(skip, index in binary)
    }


def diverts(skip: str | None, binary: bool) -> bool:
    """
    Args:
        skip: Why gitleaks skipped an own path copy, or None.
        binary: The file is a binary blob.

    Returns:
        True when another copy must read the file: always, except for a blob
        gitleaks skipped as binary, which no copy would read.
    """
    return skip is not None and not (binary and skip.startswith(BINARY_SKIP))


def copy_events(log: bytes) -> dict:
    """
    Args:
        log: gitleaks' trace log.

    Returns:
        For every (index, piece, kind) gitleaks named, the reason it skipped
        that copy, or None when it read it or found it empty.
    """
    seen = {}
    for event in events(log):
        raw = event["bare"] if event["bare"] is not None else event["quoted"]
        parts = raw.split("/", 3)
        if len(parts) >= 3 and parts[0].isdigit() and parts[1].isdigit():
            key = (int(parts[0]), int(parts[1]), parts[2])
            skip = None if event["skip"] == EMPTY_SKIP else event["skip"]
            seen[key] = seen.get(key) or skip
    return seen


def tolerated(kind: str, skip: str, sniffed: bool) -> bool:
    """
    Args:
        kind: The copy gitleaks skipped.
        skip: Its reason.
        sniffed: A binary skip is expected: the blob is binary, or the run
            is the first, whose skipped text the second run pads.

    Returns:
        True for a skip the runner covers.
    """
    if kind == CONTENT:
        return False
    return skip.startswith(PATH_SKIPS) or (sniffed and skip.startswith(BINARY_SKIP))


def expected_copies(command: Command, snapshot) -> tuple:
    """
    Args:
        command: The chunk gitleaks ran on.
        snapshot: Snapshot holding its files.

    Returns:
        Every (index, piece, kind) operands wrote, and the indices of binary blobs.
    """
    expected = set()
    binary = set()
    for index, path in enumerate(command.files):
        found = spans(path, snapshot, command.rescan)
        if found is None:
            binary.add(index)
        for number in range(1 if found is None else len(found)):
            expected.add((index, number, PATH))
            if command.rescan:
                expected.add((index, number, NAMED))
            if command.rescan and found is not None:
                expected.add((index, number, CONTENT))
    return expected, binary


def unread(command: Command, snapshot) -> dict:
    """
    Args:
        command: The chunk gitleaks ran on.
        snapshot: Snapshot holding its files.

    Returns:
        Path to reason for every binary blob, since no text rule reads it.
    """
    return {path: BINARY for path in command.files if snapshot.text(path) is None}


def events(stderr: bytes) -> list:
    """
    Args:
        stderr: gitleaks' trace log.

    Returns:
        The match of every line that names reading or skipping a copy.

    Raises:
        QualityError: gitleaks logged an error.
    """
    found = []
    for text in stderr.decode("utf-8", "replace").splitlines():
        line = LOG_LINE.match(text)
        if line is not None and line["level"] in FAILURE_LEVELS:
            raise QualityError("gitleaks logged an error")
        event = EVENT.match(line["message"]) if line is not None else None
        if event is not None:
            found.append(event)
    return found
