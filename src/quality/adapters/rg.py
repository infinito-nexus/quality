import base64
import json
import os
import re

from quality.adapters.base import Command, known_path, thread_args
from quality.gate import code_hit
from quality.ruledata import require
from quality.shellview import code_view


def commands(bound: list, settings: dict, _empty_file) -> list:
    """
    Args:
        bound: Rules with their files.
        settings: The tool's entry in tools.yml with the values of this run.
        _empty_file: Unused.

    Returns:
        One command per rule. A rule setting `multiline` lets its pattern span
        lines; a rule setting `pcre2` gets look-around. --threads carries the
        run's thread cap.
    """
    return [
        Command(
            [
                "--no-config",
                *thread_args(settings, "--threads"),
                "--no-ignore",
                "--hidden",
                "--json",
                *(["--multiline"] if item.binding.settings.get("multiline") else []),
                *(["--pcre2"] if item.binding.settings.get("pcre2") else []),
                "--regexp",
                require(item.binding.settings, "pattern", f"enforcer of {item.binding.rule.id}"),
                "--",
            ],
            item.files,
            [item],
        )
        for item in bound
    ]


def operands(command: Command, snapshot, work) -> list:
    """
    Args:
        command: One chunk.
        snapshot: Snapshot holding its files.
        work: Empty working directory of the run, removed afterwards.

    Returns:
        The files under their own paths in the working directory: the
        code_view() copy when the rule sets `code_view` with its `levels` and
        `window`, else a hard link.
    """
    binding = command.bound[0].binding
    view = binding.settings.get("code_view")
    for path in command.files:
        staged = work / path
        staged.parent.mkdir(parents=True, exist_ok=True)
        if view:
            where = f"code_view of {binding.rule.id}"
            levels, window = require(view, "levels", where), require(view, "window", where)
            staged.write_bytes(code_view(snapshot.data(path), levels, window))
        else:
            os.link(snapshot.root / path, staged)
    return list(command.files)


def reported_bytes(field: dict) -> bytes:
    return field["text"].encode() if "text" in field else base64.b64decode(field["bytes"])


def reported_path(data: dict) -> str:
    return os.fsdecode(reported_bytes(data["path"]))


def match_rows(data: dict) -> list:
    """
    Args:
        data: One match event of ripgrep's JSON output.

    Returns:
        The line each match starts on.
    """
    text = reported_bytes(data["lines"])
    first = data["line_number"]
    return sorted({first + text[: item["start"]].count(b"\n") for item in data["submatches"]} or {first})  # nocheck: clean.default-value -- an event without submatches starts on its first line


def inside_comment(pattern: str, snapshot, path: str, row: int) -> bool:
    comment = snapshot.comment(path, row)
    return comment is not None and re.search(pattern, comment) is not None


def parse(stdout: bytes, command: Command, snapshot) -> list:
    binding = command.bound[0].binding
    pattern = binding.settings["pattern"]
    hits = []
    for line in stdout.splitlines():
        event = json.loads(line)
        if event["type"] != "match":
            continue
        path = known_path(reported_path(event["data"]), snapshot)
        comment_only = binding.settings.get("comment_only")
        for row in match_rows(event["data"]):
            if not comment_only or inside_comment(pattern, snapshot, path, row):
                hits.append(code_hit(binding.rule, path, row, "", snapshot))
    return hits
