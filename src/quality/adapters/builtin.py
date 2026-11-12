import json
import re
from collections import Counter

import yaml

from quality import QualityError
from quality.gate import code_hit, metric_hit
from quality.ruledata import require

ROOT_FOLDER = "."
SEPARATOR = re.compile(r"[_-]")
CONTINUATION = "\\"
YAML_LOADER = yaml.CSafeLoader if yaml.__with_libyaml__ else yaml.SafeLoader


def file_lines(item, snapshot) -> list:
    """
    Args:
        item: Bound rule with its files.
        snapshot: Snapshot holding the files.

    Returns:
        One metric finding per file over the limit.
    """
    rule = item.binding.rule
    hits = []
    for path in item.files:
        value = snapshot.line_count(path)
        if value > rule.metric["limit"]:
            hits.append(metric_hit(rule, path, None, value, ""))
    return hits


def inline_scripts(item, snapshot) -> list:
    """
    Args:
        item: Bound rule with its workflow files.
        snapshot: Snapshot holding the files.

    Returns:
        One metric finding per `run:` block over the limit of logical lines,
        keyed by job and step id, name or position.
    """
    rule = item.binding.rule
    hits = []
    for path in item.files:
        for entity, row, script in workflow_scripts(snapshot.data(path)):
            value = logical_lines(script)
            if value > rule.metric["limit"]:
                hits.append(metric_hit(rule, path, row, value, entity))
    return hits


def workflow_scripts(data: bytes) -> list:
    """
    Args:
        data: Workflow file content.

    Returns:
        (entity, line, script) per `run:` step. Each node is visited once, so
        aliases cannot multiply the work.
    """
    try:
        root = yaml.compose(data, Loader=yaml.SafeLoader)
    except yaml.YAMLError:
        return []
    found = []
    seen = set()
    for job, node in mapping_items(mapping_value(root, "jobs")):
        steps = mapping_value(node, "steps") if first_visit(seen, node) else None
        if steps is not None and first_visit(seen, steps):
            found += job_scripts(job, steps, seen)
    return found


def job_scripts(job: str, steps, seen: set) -> list:
    found = []
    for index, step in enumerate(sequence_items(steps)):
        run = mapping_value(step, "run") if first_visit(seen, step) else None
        if isinstance(run, yaml.ScalarNode):
            label = scalar(mapping_value(step, "id")) or scalar(mapping_value(step, "name"))
            found.append((f"{job}/{label or index}", run.start_mark.line + 1, run.value))
    return found


def first_visit(seen: set, node) -> bool:
    if id(node) in seen:
        return False
    seen.add(id(node))
    return True


def mapping_value(node, key: str):
    for name, value in mapping_items(node):
        if name == key:
            return value
    return None


def mapping_items(node) -> list:
    if not isinstance(node, yaml.MappingNode):
        return []
    return [(name.value, value) for name, value in node.value if isinstance(name, yaml.ScalarNode)]


def sequence_items(node) -> list:
    return node.value if isinstance(node, yaml.SequenceNode) else []


def scalar(node) -> str | None:
    return node.value if isinstance(node, yaml.ScalarNode) else None


def logical_lines(script: str) -> int:
    """
    Args:
        script: Shell text of one `run:` block.

    Returns:
        Lines that are neither blank nor a comment, with backslash continuations
        counted once.
    """
    count = 0
    continued = False
    for line in script.splitlines():
        text = line.strip()
        if continued:
            continued = text.endswith(CONTINUATION)
        elif text and not text.startswith("#"):
            count += 1
            continued = text.endswith(CONTINUATION)
    return count


def tree_children(snapshot) -> dict:
    """
    Args:
        snapshot: Snapshot of a whole tree or index.

    Returns:
        Folder path, `.` for the root, to a map of each direct item name to
        whether it is a file. Unread, symlinked and gitlinked entries count.
    """
    children = {}
    for path in [*snapshot.files, *snapshot.unchecked, *snapshot.irregular]:
        parts = path.split("/")
        for depth, name in enumerate(parts):
            folder = "/".join(parts[:depth]) or ROOT_FOLDER
            children.setdefault(folder, {})[name] = depth == len(parts) - 1
    return children


def changed_folders(paths: list) -> list:
    """
    Args:
        paths: Changed paths, old and new names alike.

    Returns:
        Every folder whose direct items a change can alter: each ancestor of
        each path, the root included.
    """
    folders = {ROOT_FOLDER}
    for path in paths:
        parts = path.split("/")[:-1]
        folders.update("/".join(parts[:depth]) for depth in range(1, len(parts) + 1))
    return sorted(folders)


def folder_items(rule, children: dict, folders: list) -> list:
    limit = rule.metric["limit"]
    return [
        metric_hit(rule, folder, None, len(children[folder]), "")
        for folder in folders
        if len(children.get(folder, ())) > limit
    ]


def prefix_groups(rule, children: dict, folders: list) -> list:
    exempt = require(rule.metric, "exempt", f"metric of {rule.id}")
    hits = []
    for folder in folders:
        groups = Counter(
            prefix
            for name, is_file in children.get(folder, {}).items()
            if is_file and (prefix := name_prefix(name, exempt)) is not None
        )
        hits += [
            metric_hit(rule, folder, None, size, prefix)
            for prefix, size in sorted(groups.items())
            if size > rule.metric["limit"]
        ]
    return hits


def name_prefix(name: str, exempt: list) -> str | None:
    """
    Args:
        name: File name.
        exempt: Prefixes that never form a group, such as test.

    Returns:
        The text before the first `_` or `-`, or None when that text is empty,
        as for dunder names, numeric or exempt, or the name has no separator.
    """
    pieces = SEPARATOR.split(name, maxsplit=1)
    prefix = pieces[0]
    if len(pieces) < 2 or not prefix or prefix.isdigit() or prefix in exempt:
        return None
    return prefix


def json_error(data: bytes) -> tuple:
    """
    Args:
        data: File content.

    Returns:
        (broken, line) from the standard library's JSON parser; the line is
        None where the bytes are no valid Unicode.
    """
    try:
        json.loads(data)
    except UnicodeDecodeError:
        return True, None
    except json.JSONDecodeError as error:
        return True, error.lineno
    except RecursionError:
        raise QualityError("a JSON file nests too deep to parse") from None
    return False, None


def yaml_error(data: bytes) -> tuple:
    """
    Args:
        data: File content.

    Returns:
        (broken, line) from composing every document, which covers syntax and
        aliases but constructs nothing, so custom tags such as `!vault` pass.
    """
    try:
        for _ in yaml.compose_all(data, Loader=YAML_LOADER):
            pass
    except yaml.MarkedYAMLError as error:
        return True, None if error.problem_mark is None else error.problem_mark.line + 1
    except yaml.YAMLError:
        return True, None
    return False, None


def utf8_error(data: bytes) -> tuple:
    """
    Args:
        data: File content.

    Returns:
        (broken, None) where the bytes are no UTF-8, which ast-grep skips
        without a word, so no structural rule would see the file.
    """
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return True, None
    return False, None


def uncounted_line_breaks(item, snapshot) -> list:
    """
    Args:
        item: Bound rule with its files. Its settings list under `breaks`
            the pattern of each line break, with the `kinds` whose language
            ends a line there, or every bound kind where it names none.
        snapshot: Snapshot holding the files.

    Returns:
        One finding per file whose text holds such a break, on the
        LF-counted line of the first one: ast-grep, ripgrep and the nocheck
        lookup count no line there, so code after it shares the line of a
        comment.
    """
    breaks = require(item.binding.settings, "breaks", f"enforcer of {item.binding.rule.id}")
    hits = []
    for path in item.files:
        data = snapshot.text(path)
        text = "" if data is None else data.decode("utf-8", "replace")
        found = break_pattern(breaks, snapshot.kinds_of(path)).search(text)
        if found is not None:
            row = text.count("\n", 0, found.start()) + 1
            hits.append(code_hit(item.binding.rule, path, row, "", snapshot))
    return hits


def break_pattern(breaks: list, kinds: frozenset) -> re.Pattern:
    return re.compile("|".join(entry["pattern"] for entry in breaks if "kinds" not in entry or kinds & set(entry["kinds"])))


def syntax(parser):
    def check(item, snapshot) -> list:
        hits = []
        for path in item.files:
            broken, line = parser(snapshot.data(path))
            if broken:
                hits.append(code_hit(item.binding.rule, path, line, parser.__name__, snapshot))
        return hits

    return check


BUILTINS = {
    "file-lines": file_lines,
    "inline-script": inline_scripts,
    "uncounted-line-break": uncounted_line_breaks,
    "json-syntax": syntax(json_error),
    "yaml-syntax": syntax(yaml_error),
    "utf-8": syntax(utf8_error),
}


def run_builtin(item, snapshot) -> list:
    name = item.binding.settings["builtin"]
    if name not in BUILTINS:
        raise QualityError(f"rule {item.binding.rule.id}: unknown builtin {name!r}")
    return BUILTINS[name](item, snapshot)
