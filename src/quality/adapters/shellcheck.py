import json

from quality.adapters.base import Command, all_files, known_path
from quality.gate import code_hit


def commands(bound: list, _settings: dict, _empty_file) -> list:
    """
    Args:
        bound: The rule with its files.
        _settings: Unused tool entry.
        _empty_file: Unused.

    Returns:
        One command. Without --external-sources shellcheck follows no `source`.
    """
    return [Command(["--norc", "--format=json1", "--color=never", "--"], all_files(bound), bound)]


def parse(stdout: bytes, command: Command, snapshot) -> list:
    rule = command.bound[0].binding.rule
    return [
        code_hit(
            rule,
            known_path(item["file"], snapshot),
            item["line"],
            f"SC{item['code']} {item['message']}",
            snapshot,
        )
        for item in json.loads(stdout)["comments"]
    ]
