import json
import os

from quality.adapters.base import Command, all_files, known_path
from quality.gate import code_hit


def commands(bound: list, _settings: dict, empty_file) -> list:
    """
    Args:
        bound: The rule with its files.
        _settings: Unused tool entry.
        empty_file: Replaces the .github/actionlint.yaml.

    Returns:
        One command, with the shellcheck and pyflakes helpers disabled.
    """
    prefix = [
        "-no-color",
        "-format",
        "{{json .}}",
        "-config-file",
        str(empty_file),
        "-shellcheck",
        "",
        "-pyflakes",
        "",
        "--",
    ]
    return [Command(prefix, all_files(bound), bound)]


def parse(stdout: bytes, command: Command, snapshot) -> list:
    rule = command.bound[0].binding.rule
    return [
        code_hit(
            rule,
            known_path(os.path.normpath(item["filepath"]), snapshot),
            item["line"],
            f"{item['kind']} {item['message']}",
            snapshot,
        )
        for item in json.loads(stdout)
    ]
