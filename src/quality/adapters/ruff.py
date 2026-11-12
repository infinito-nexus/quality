import json

from quality import QualityError
from quality.adapters.base import Command, all_files, known_path, relative
from quality.gate import code_hit
from quality.ruledata import require


def commands(bound: list, settings: dict, _empty_file) -> list:
    """
    Args:
        bound: Rules with their files.
        settings: The tool's entry in tools.yml.
        _empty_file: Unused.

    Returns:
        One command.
    """
    codes = sorted({code for item in bound for code in item.binding.settings.get("codes", ())})
    prefix = [
        "check",
        "--isolated",
        "--no-cache",
        "--ignore-noqa",
        "--no-respect-gitignore",
        "--no-force-exclude",
        "--no-fix",
        "--output-format",
        "json",
        "--target-version",
        require(settings, "target_version", "tools.yml ruff"),
        "--select",
        ",".join(codes),
        "--",
    ]
    return [Command(prefix, all_files(bound), bound)]


def code_index(bound: list) -> dict:
    index = {}
    for item in bound:
        settings = item.binding.settings
        for code in (*settings.get("codes", ()), *settings.get("always_reported", ())):
            index[code] = item.binding
    return index


def parse(stdout: bytes, command: Command, snapshot) -> list:
    index = code_index(command.bound)
    hits = []
    for item in json.loads(stdout):
        binding = index.get(item["code"])
        if binding is None:
            raise QualityError("ruff reported a code outside the selected rules")
        unless = binding.settings.get("unless_message")
        if unless is not None and unless in item["message"]:
            continue
        path = known_path(relative(item["filename"], snapshot.root), snapshot)
        hits.append(
            code_hit(binding.rule, path, item["location"]["row"], item["message"], snapshot)
        )
    return hits
