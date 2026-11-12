import json
import tempfile
from pathlib import Path

from quality.adapters.base import (
    Command,
    Skipped,
    all_files,
    known_path,
    relative,
    utf8_name,
)
from quality.gate import code_hit
from quality.ruledata import require

REPORT = "jscpd-report.json"
OUTPUT_FLAG = "--output"


def commands(bound: list, settings: dict, _empty_file) -> list:
    """
    Args:
        bound: Rules with their files.
        settings: The tool's entry in tools.yml with the paths of this run.
        _empty_file: Unused; jscpd needs a JSON document, so empty_json replaces
            the .jscpd.json and package.json jscpd would read.

    Returns:
        One command per rule, with the rule's token minimum, over the files whose
        names are UTF-8, since jscpd aborts on any other; parse() names the rest.
        The report lands in a fresh scratch directory outside the snapshot.
    """
    found = []
    for item in bound:
        enforcer = item.binding.settings
        output = tempfile.mkdtemp(prefix="jscpd-", dir=require(settings, "work_dir", "runtime"))
        prefix = [
            "--config",
            str(require(settings, "empty_json", "runtime")),
            "--min-tokens",
            str(require(enforcer, "min_tokens", f"enforcer of {item.binding.rule.id}")),
            "--min-lines",
            str(require(enforcer, "min_lines", f"enforcer of {item.binding.rule.id}")),
            "--max-size",
            require(settings, "max_size", "tools.yml jscpd"),
            "--absolute",
            "--reporters",
            "json",
            OUTPUT_FLAG,
            output,
            "--no-gitignore",
            "--no-colors",
            "--no-tips",
            "--silent",
            "--",
        ]
        found.append(Command(prefix, sorted(filter(utf8_name, item.files)), [item]))
    return found


def read_report(command: Command) -> dict:
    report = Path(command.prefix[command.prefix.index(OUTPUT_FLAG) + 1]) / REPORT
    try:
        data = report.read_bytes()
        report.unlink()
    except OSError:
        raise ValueError("jscpd wrote no report") from None
    return json.loads(data)


def parse(_stdout: bytes, command: Command, snapshot) -> list:
    """
    Args:
        _stdout: Unused; the report is the JSON file jscpd wrote.
        command: The command naming the report directory.
        snapshot: Snapshot the files came from.

    Returns:
        One finding at the start of each fragment of each clone, and the files
        left out for their names.
    """
    rule = command.bound[0].binding.rule
    hits = []
    for clone in read_report(command)["duplicates"]:
        for side in (clone["firstFile"], clone["secondFile"]):
            path = known_path(relative(side["name"], snapshot.root), snapshot)
            hits.append(code_hit(rule, path, side["start"], clone["format"], snapshot))
    left_out = sorted(set(all_files(command.bound)) - set(command.files))
    return hits + [Skipped(path, "jscpd cannot read a name that is not UTF-8") for path in left_out]
