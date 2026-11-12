import json
import os

from quality import QualityError
from quality.adapters.base import (
    Command,
    checked_rules,
    gap_rule,
    known_path,
    refuse_non_utf8,
    thread_args,
)
from quality.gate import code_hit, unread_hit
from quality.ruledata import require

UNPARSED = ("Syntax error", "Other syntax error", "Lexical error")
PARTIAL = "PartialParsing"


def files_per_config(bound: list, configs: dict) -> dict:
    """
    Args:
        bound: The rule with its files and their kinds.
        configs: Rule file per kind from tools.yml.

    Returns:
        The files of each rule file, so a script is parsed only in its own language.

    Raises:
        QualityError: A kind of the binding has no rule file.
    """
    grouped = {}
    for item in bound:
        for kind in sorted(item.binding.kinds):
            config = require(configs, kind, "tools.yml semgrep configs")
            files = [path for path in item.files if kind in item.kinds[path]]
            grouped.setdefault(config, set()).update(files)
    return {config: sorted(files) for config, files in grouped.items() if files}


def commands(bound: list, settings: dict, _empty_file) -> list:
    """
    Args:
        bound: The rule with its files.
        settings: The tool's entry in tools.yml with the paths of this run.
        _empty_file: Unused; --config replaces every configuration Semgrep would discover.

    Returns:
        One command per rule file, reading only this repository's rules.
        --scan-unknown-extensions, because Semgrep skips a script named on the
        command line whose name has no known extension, such as bin/app. The
        environment turns metrics and the version check off, and HOME is a
        scratch directory. --jobs carries the run's thread cap.
    """
    rules_dir = require(settings, "rules_dir", "runtime")
    grouped = files_per_config(bound, require(settings, "configs", "tools.yml semgrep"))
    result = []
    for config, files in sorted(grouped.items()):
        refuse_non_utf8("semgrep", files)
        prefix = [
            "scan",
            *thread_args(settings, "--jobs"),
            "--config",
            str(rules_dir / config),
            "--scan-unknown-extensions",
            "--metrics=off",
            "--disable-version-check",
            "--disable-nosem",
            "--no-git-ignore",
            "--no-rewrite-rule-ids",
            "--max-target-bytes=0",
            "--json",
            "--quiet",
            "--",
        ]
        result.append(Command(prefix, files, bound))
    return result


def reported_path(reported: str, snapshot) -> str:
    return known_path(os.path.normpath(reported), snapshot)


def gap_hit(command: Command, path: str, snapshot):
    """
    Args:
        command: The command that read the file.
        path: File Semgrep read only in part or not at all.
        snapshot: Snapshot the file came from.

    Returns:
        One file-level security.partial-scan finding, because Semgrep names a
        few error locations, not the lines it skipped, so no line can be waived
        on its own; only a path entry in .qualityignore.yml waives it.

    Raises:
        QualityError: No security.partial-scan binding covers the file, so the
            gap would pass unseen.
    """
    rule = gap_rule(command, path)
    if rule is None:
        raise QualityError(f"semgrep could not read all of {path}, so it stays unchecked")
    return code_hit(rule, path, None, "semgrep could not read all of this file", snapshot)


def read_errors(errors: list, snapshot) -> tuple:
    """
    Args:
        errors: The errors of Semgrep's JSON report.
        snapshot: Snapshot the files came from.

    Returns:
        The files Semgrep could not parse at all, and those it read only in part.

    Raises:
        QualityError: An error other than a file it could not parse.
    """
    unread = set()
    partial = set()
    for error in errors:
        kind = error["type"] if isinstance(error["type"], str) else error["type"][0]
        if kind in UNPARSED:
            unread.add(reported_path(error["path"], snapshot))
        elif kind == PARTIAL:
            partial.add(reported_path(error["path"], snapshot))
        else:
            raise QualityError("semgrep reported an error, so a file stays unchecked")
    return unread, partial


def parse(stdout: bytes, command: Command, snapshot) -> list:
    """
    Args:
        stdout: Semgrep's JSON report.
        command: The command that produced it.
        snapshot: Snapshot the files came from.

    Returns:
        One finding per match, plus one per file Semgrep could not parse at all,
        since a syntax error would otherwise hide every match in it. A file it
        read only in part, which valid code such as a class `static {` block
        causes, or did not scan, gets one file-level security.partial-scan finding.

    Raises:
        QualityError: Semgrep reported an error other than a file it could not parse,
            such as a rule timeout that would leave a file unchecked.
    """
    document = json.loads(stdout)
    rule = (checked_rules(command) or [command.bound[0].binding.rule])[0]  # nocheck: clean.default-value -- the bound rule when no checked rule ran
    unread, partial = read_errors(document["errors"], snapshot)
    scanned = {reported_path(path, snapshot) for path in document["paths"].get("scanned", [])}
    partial |= {path for path in command.files if path not in scanned}
    hits = [
        code_hit(rule, reported_path(item["path"], snapshot), item["start"]["line"], item["check_id"], snapshot)
        for item in document["results"]
    ]
    gaps = [gap_hit(command, path, snapshot) for path in sorted(partial)]
    return hits + [unread_hit(rule, path) for path in sorted(unread)] + gaps
