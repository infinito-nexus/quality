import base64
import json
import os
import re

from quality.adapters.base import Command, known_path
from quality.gate import code_hit
from quality.ruledata import require


def commands(bound: list, _settings: dict, _empty_file) -> list:
    """
    Args:
        bound: Rules with their files.
        _settings: Unused tool entry.
        _empty_file: Unused; ripgrep needs no empty configuration.

    Returns:
        One command per rule.
    """
    return [
        Command(
            [
                "--no-config",
                "--no-ignore",
                "--hidden",
                "--json",
                "--regexp",
                require(item.binding.settings, "pattern", f"enforcer of {item.binding.rule.id}"),
                "--",
            ],
            item.files,
            [item],
        )
        for item in bound
    ]


def reported_path(data: dict) -> str:
    path = data["path"]
    return path["text"] if "text" in path else os.fsdecode(base64.b64decode(path["bytes"]))


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
        row = event["data"]["line_number"]
        comment_only = binding.settings.get("comment_only")
        if not comment_only or inside_comment(pattern, snapshot, path, row):
            hits.append(code_hit(binding.rule, path, row, "", snapshot))
    return hits
