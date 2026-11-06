import csv
import io
import os

from quality import QualityError
from quality.adapters.base import Command, all_files, known_path
from quality.gate import metric_hit
from quality.ruledata import require

CSV_COLUMNS = {"nloc": 0, "ccn": 1, "parameters": 3}
FILE_COLUMN = 6
FUNCTION_COLUMN = 7
START_COLUMN_FROM_END = -2


def commands(bound: list, _settings: dict, empty_file) -> list:
    """
    Args:
        bound: Metric rules with their files.
        _settings: Unused tool entry.
        empty_file: Replaces the ./whitelizard.txt lizard would read.

    Returns:
        One command, with no .gitignore lookup.
    """
    for item in bound:
        rule = item.binding.rule
        field = require(item.binding.settings, "field", f"enforcer of {rule.id}")
        if field not in CSV_COLUMNS:
            raise QualityError(f"rule {rule.id}: lizard has no field {field!r}")
    files = all_files(bound)
    # Exception: lizard's CSV leaves quotes in file names unescaped, so a crafted
    # name could move columns and report its functions under another file.
    if any('"' in path for path in files):
        raise QualityError("lizard cannot report a file name holding a double quote")
    prefix = ["--csv", "-i", "-1", "--no-gitignore", "-W", str(empty_file), "--"]
    return [Command(prefix, files, bound)]


def parse(stdout: bytes, command: Command, snapshot) -> list:
    text = stdout.decode("utf-8", "surrogateescape")
    hits = []
    for row in csv.reader(io.StringIO(text)):
        path = known_path(os.path.normpath(row[FILE_COLUMN]), snapshot)
        for item in command.bound:
            rule = item.binding.rule
            value = int(row[CSV_COLUMNS[item.binding.settings["field"]]])
            if value > rule.metric["limit"]:
                start = int(row[START_COLUMN_FROM_END])
                hits.append(metric_hit(rule, path, start, value, row[FUNCTION_COLUMN]))
    return hits
