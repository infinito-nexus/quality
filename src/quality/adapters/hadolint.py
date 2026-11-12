import json
import re
from pathlib import PurePosixPath

from quality.adapters.base import Command, all_files
from quality.gate import code_hit
from quality.ruledata import require

PRAGMA = re.compile(
    rb"^(?:\xef\xbb\xbf)?[ \t\r]*#[ \t]*hadolint\b[^\r\n]*", re.IGNORECASE | re.MULTILINE
)


def commands(bound: list, settings: dict, config_file) -> list:
    """
    Args:
        bound: The rule with its files.
        settings: The tool's entry in tools.yml with the values of this run.
        config_file: Replaces .hadolint.yaml, .hadolint.yml and
            $XDG_CONFIG_HOME/hadolint.yaml.

    Returns:
        One command that ignores `# hadolint ignore=` pragmas. --no-fail
        leaves exit 1 to errors, so it fails closed. The run's --threads
        value goes to hadolint's own runtime as +RTS -N.
    """
    threads = require(settings, "threads", "runtime")
    runtime = [] if threads is None else ["+RTS", f"-N{threads}", "-RTS"]
    prefix = [
        *runtime,
        "--config",
        str(config_file),
        "--no-fail",
        "--no-color",
        "--disable-ignore-pragma",
        "--format",
        "json",
    ]
    return [Command(prefix, all_files(bound), bound)]


def operands(command: Command, snapshot, work) -> list:
    """
    Args:
        command: One chunk.
        snapshot: Snapshot holding them.
        work: Empty working directory of the run, removed afterwards.

    Returns:
        The copies hadolint lints, as <index>/<name>. A binary blob is staged
        empty, since the security.binary-code rule judges it instead.
    """
    # Exception: no flag refuses a `hadolint shell=powershell` pragma, which
    # switches every ShellCheck check off, so each copy turns its pragma lines
    # into bare comments and keeps its line numbers. hadolint also honours one
    # after any byte order mark or a lone carriage return at the start of a
    # file, so UTF-16 and UTF-32 reach it as UTF-8 first.
    staged = []
    for index, path in enumerate(command.files):
        copy = f"{index}/{PurePosixPath(path).name}"
        (work / str(index)).mkdir()
        text = snapshot.text(path)
        (work / copy).write_bytes(b"" if text is None else PRAGMA.sub(b"#", text))
        staged.append(copy)
    return ["--", *staged]


def parse(stdout: bytes, command: Command, snapshot) -> list:
    rule = command.bound[0].binding.rule
    return [
        code_hit(
            rule,
            command.files[int(PurePosixPath(item["file"]).parts[0])],
            item["line"],
            f"{item['code']} {item['message']}",
            snapshot,
        )
        for item in json.loads(stdout)
    ]
