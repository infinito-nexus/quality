import json
import re
from pathlib import PurePosixPath

from quality import QualityError
from quality.adapters.base import Command, all_files, thread_args
from quality.legal.origin import Scan, licence_files, origin_hits
from quality.ruledata import require

INPUT = "in"
STEM = "file"
SUFFIX = re.compile(r"\.[A-Za-z0-9]{1,16}")
SPDX_ID = "1-spdx-id"
ORIGIN_KINDS = ("is_license_text", "is_license_notice")
TIMEOUT = "ERROR: Processing interrupted: timeout after "
ERROR_PATH = "Path: "


def commands(bound: list, settings: dict, _empty_file) -> list:
    """
    Args:
        bound: The legal.foreign-* rules with their files.
        settings: The tool's entry in tools.yml with the values of this run.
        _empty_file: Unused.

    Returns:
        One command reporting licence detections at or above the
        `license_score` of tools.yml, the kind of each licence rule that
        matched, and copyright holders as JSON on stdout. --processes carries
        the run's thread cap.
    """
    prefix = [
        "--license",
        "--copyright",
        "--license-references",
        "--strip-root",
        "--quiet",
        *thread_args(settings, "--processes"),
        "--license-score",
        str(require(settings, "license_score", "tools.yml scancode")),
        "--json",
        "-",
        "--",
    ]
    return [Command(prefix, all_files(bound), bound)]


def staged(command: Command, snapshot) -> list:
    return list(dict.fromkeys([*command.files, *licence_files(command, snapshot)]))


def staged_name(path: str) -> str:
    """
    Args:
        path: A file of the chunk.

    Returns:
        The name its copy goes by: a fixed stem, so that no name scancode
        skips as a version control file (.gitignore, .gitattributes, CVS)
        hides a file, plus the file's suffix when it is plain, for scancode's
        type guess.
    """
    suffix = PurePosixPath(path).suffix
    return STEM + suffix if SUFFIX.fullmatch(suffix) else STEM


def operands(command: Command, snapshot, work) -> list:
    """
    Args:
        command: One chunk.
        snapshot: Snapshot holding its files.
        work: Empty working directory of the run, removed afterwards.

    Returns:
        The one input folder, holding each file of the chunk and the nearest
        licence file of each as <index>/<staged_name()>. A binary blob is
        staged empty.
    """
    for index, path in enumerate(staged(command, snapshot)):
        folder = work / INPUT / str(index)
        folder.mkdir(parents=True)
        text = snapshot.text(path)
        (folder / staged_name(path)).write_bytes(b"" if text is None else text)
    return [INPUT]


def carries_licence(match: dict, rules: dict) -> bool:
    """
    Args:
        match: One match of a licence detection.
        rules: Identifier to rule of the report's license_rule_references.

    Returns:
        Whether the match is a licence text or notice, which a file holding
        licensed material carries. An SPDX identifier, which
        legal.license-declared judges, and a reference, tag or intro, which
        only names a licence, are not. scancode renames the synthetic rule of
        an SPDX identifier in its references, so that matcher is told apart by
        name; any other rule the references lack raises KeyError.
    """
    if match["matcher"] == SPDX_ID:
        return False
    rule = rules[match["rule_identifier"]]
    return any(rule[kind] for kind in ORIGIN_KINDS)


def timed_out(entry: dict) -> bool:
    """
    Args:
        entry: One file of scancode's JSON report.

    Returns:
        Whether scancode reported errors for it and every one is its per-file
        timeout.
    """
    errors = entry["scan_errors"]
    return bool(errors) and all(TIMEOUT in error for error in errors)


def scan_of(entry: dict, rules: dict) -> Scan | None:
    """
    Args:
        entry: One file of scancode's JSON report.
        rules: Identifier to rule of the report's license_rule_references.

    Returns:
        Its licence detections holding a licence text or notice as (SPDX
        expression, first line of such a match) and its copyright holders as
        (holder, line); None when scancode timed out on it.

    Raises:
        QualityError: scancode could not scan the file for another reason.
    """
    if timed_out(entry):
        return None
    if entry["scan_errors"]:
        raise QualityError("scancode could not scan a file, so it stays unchecked")
    found = [
        (item["license_expression_spdx"], [match["start_line"] for match in item["matches"] if carries_licence(match, rules)])
        for item in entry["license_detections"]
    ]
    licences = [(expression, min(lines)) for expression, lines in found if lines]
    holders = [(item["holder"], item["start_line"]) for item in entry["holders"]]
    return Scan(licences, holders)


def parse(stdout: bytes, command: Command, snapshot) -> list:
    """
    Args:
        stdout: scancode's JSON report.
        command: The command that produced it.
        snapshot: Snapshot the files came from.

    Returns:
        The findings of legal.origin.origin_hits() over the files of this
        chunk, a file scancode timed out on mapped to None; a file of the
        chunk the report leaves out raises KeyError there.

    Raises:
        QualityError: scancode wrote no report, or reported an error other
            than a per-file timeout.
    """
    try:
        document = json.loads(stdout)
    except ValueError as error:
        raise QualityError("scancode wrote no report, so its files stay unchecked") from error
    timeouts = {f"{ERROR_PATH}{INPUT}/{entry['path']}" for entry in document["files"] if timed_out(entry)}
    if any(set(header["errors"]) - timeouts for header in document["headers"]):
        raise QualityError("scancode reported an error, so a file stays unchecked")
    paths = staged(command, snapshot)
    rules = {rule["identifier"]: rule for rule in document["license_rule_references"]}
    scanned = {
        paths[int(PurePosixPath(entry["path"]).parts[0])]: scan_of(entry, rules)
        for entry in document["files"]
        if entry["type"] == "file"
    }
    return origin_hits(command, snapshot, scanned)
