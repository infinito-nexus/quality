import json
import re
from pathlib import Path

import yaml

from quality import QualityError
from quality.adapters import phpmode
from quality.adapters.base import Command, all_files, thread_args
from quality.gate import code_hit
from quality.ruledata import (
    COMMENTS,
    NOCHECK_NAMES,
    PLACEHOLDERS,
    RULE_DIR,
    filled,
    read_yaml,
    require,
)
from quality.suppress import language_patterns

CONFIG_NAME = "sgconfig.yml"
SHARED_FILE = "shared.yml"
RULE_SEPARATOR = "/"
INCOMPLETE = "coding.parse-incomplete"
IGNORE_SOURCES = ("hidden", "dot", "exclude", "global", "parent", "vcs")
FLAGS = [
    "--json=stream",
    "--include-metadata",
    "--color",
    "never",
    "--custom-languages",
    "ignore",
    *[flag for source in IGNORE_SOURCES for flag in ("--no-ignore", source)],
]
SUPPRESSION = re.compile(rb"ast-grep-ignore")
NEUTRAL = b"ast_grep_ignore"
SHEBANG = re.compile(rb"\A#!(?!\[)[^\r\n]*")
BLANK = re.compile(r"\s*")
HOSTS = {"php": phpmode.unhosted}


def language_of(item) -> str:
    return require(item.binding.settings, "language", f"enforcer of {item.binding.rule.id}")


def commands(bound: list, settings: dict, empty_file: Path) -> list:
    """
    Args:
        bound: Rules with their files, one binding per language.
        settings: The tool's entry in tools.yml, its rule_dir already absolute
            and the comment patterns under `placeholders`.
        empty_file: File in the run's scratch directory; each language's
            composed rule file is written beside it.

    Returns:
        One command per language, run in a work directory that `operands`
        fills, so ast-grep never searches the target for an sgconfig.yml.
    """
    rule_dir = Path(require(settings, RULE_DIR, "tools.yml ast-grep"))
    per_language = {}
    for item in bound:
        per_language.setdefault(language_of(item), []).append(item)
    found = []
    for language, items in sorted(per_language.items()):
        wanted = {item.binding.rule.id for item in items} | {INCOMPLETE}
        documents = [doc for doc in composed(rule_dir, language, settings) if prefix(doc["id"]) in wanted]
        target = empty_file.with_name(f"ast-grep-{language}.yml")
        target.write_text("\n---\n".join(json.dumps(doc) for doc in documents), encoding="utf-8")
        argv = ["scan", "--config", CONFIG_NAME, "--rule", str(target), *FLAGS, *thread_args(settings, "--threads"), "--"]
        found.append(Command(argv, all_files(items), items))
    return found


def prefix(rule_id: str) -> str:
    return rule_id.split(RULE_SEPARATOR, 1)[0]


def rule_file(rule_dir: Path, language: str) -> Path:
    found = sorted(rule_dir.glob(f"*/{language}.yml"))
    if len(found) != 1:
        raise QualityError(f"rule data: ast-grep needs exactly one {language}.yml under {rule_dir.name}")
    return found[0]


def composed(rule_dir: Path, language: str, settings: dict) -> list:
    """
    Args:
        rule_dir: Directory of the ast-grep rule files.
        language: ast-grep language name.
        settings: The tool's entry in tools.yml with the comment patterns,
            comments.yml and the nocheck names.

    Returns:
        The language file's documents, then every shared document that lists
        the language or lists none, filled with the comment patterns, the
        directives this language's tools read, and the language's comment
        kinds, root kind and legitimately empty kinds.
    """
    shared = read_yaml(rule_dir / SHARED_FILE)
    facts = require(require(shared, "languages", SHARED_FILE), language, f"{SHARED_FILE} languages")
    comments = require(settings, COMMENTS, "tools.yml ast-grep")
    names = require(settings, NOCHECK_NAMES, "tools.yml ast-grep")
    fill = {
        **require(settings, PLACEHOLDERS, "tools.yml ast-grep"),
        **language_patterns(comments, names, language),
        "@comment": [{"kind": kind} for kind in require(facts, "comments", f"{SHARED_FILE} {language}")],
        "@root": require(facts, "root", f"{SHARED_FILE} {language}"),
        "@empty": [{"kind": kind} for kind in require(facts, "empty", f"{SHARED_FILE} {language}")],
    }
    try:
        own = list(yaml.safe_load_all(rule_file(rule_dir, language).read_bytes()))
    except yaml.YAMLError:
        raise QualityError(f"rule data: ast-grep {language}.yml is not valid YAML") from None
    common = [
        {**{key: value for key, value in filled(doc, fill).items() if key != "languages"}, "language": language}
        for doc in require(shared, "documents", SHARED_FILE)
        if "languages" not in doc or language in doc["languages"]
    ]
    return own + common


def prepared(data: bytes) -> bytes:
    return SUPPRESSION.sub(NEUTRAL, SHEBANG.sub(b"", data, count=1))


def operands(command: Command, snapshot, work: Path) -> list:
    """
    Args:
        command: One chunk of a language's command.
        snapshot: Snapshot holding its files.
        work: Empty working directory of the run, removed afterwards.

    Returns:
        The copies ast-grep scans, named by their index in the chunk. The
        configuration maps every name to the language, because kinds.yml
        already chose it by extension, shebang or template suffix. A
        language ast-grep parses without its host, PHP without its HTML,
        gets its host blanked first.
    """
    language = language_of(command.bound[0])
    (work / CONFIG_NAME).write_text(json.dumps({"languageGlobs": {language: ["*"]}}), encoding="utf-8")
    copies = [str(index) for index in range(len(command.files))]
    for copy, path in zip(copies, command.files):
        data = prepared(snapshot.data(path))
        (work / copy).write_bytes(HOSTS[language](data) if language in HOSTS else data)
    return copies


def owners(items: list) -> dict:
    found = {}
    for item in items:
        found.setdefault(item.binding.rule.id, (item.binding.rule, set()))[1].update(item.files)
    return found


def decodes(data: bytes) -> bool:
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def bound_node(match: dict, name: str) -> dict | None:
    return match.get("metaVariables", {}).get("single", {}).get(name)


def first_line(node: dict) -> int:
    return node["range"]["start"]["line"] + 1


def reported_rows(match: dict) -> list:
    """
    Args:
        match: One ast-grep match.

    Returns:
        The line of a bound `$AT`, for a zero-width node inside the match,
        else the match's first line. An unreadable region reports every line
        from there to the end of the region, or for a missing node to the end
        of the top-level item `$TOP` that holds it, so a nocheck waives one
        line and never the code around it.
    """
    at = bound_node(match, "AT")
    first = first_line(at if at is not None else match)
    if prefix(match["ruleId"]) != INCOMPLETE:
        return [first]
    top = bound_node(match, "TOP")
    region = top if top is not None else match
    end = region["range"]["end"]
    last = end["line"] if end["column"] or end["line"] == region["range"]["start"]["line"] else end["line"] - 1
    return list(range(first, max(first, last + 1) + 1))


def broken(snapshot, path: str, above: dict, row: int) -> bool:
    """
    Args:
        snapshot: Snapshot holding the file.
        path: The file.
        above: The opening comment the match follows.
        row: First line of the match.

    Returns:
        True where the opener does not carry the match: code precedes the
        opener on its line, or a blank line lies between the two.
    """
    lines = snapshot.lines(path)
    start = above["range"]["start"]
    if not BLANK.fullmatch(lines[start["line"]][: start["column"]]):
        return True
    return any(BLANK.fullmatch(lines[index]) for index in range(above["range"]["end"]["line"] + 1, row - 1))


def placed(entry: dict, match: dict, lines: list) -> bool:
    """
    Args:
        entry: A directive a tool reads only at one place: its pattern and
            either `trailing` or the first and last lines it may stand on.
        match: The comment ast-grep matched.
        lines: Lines of the file.

    Returns:
        True where the comment is that directive at its place.
    """
    if not re.fullmatch(entry["pattern"], match["text"]):
        return False
    start = match["range"]["start"]
    if entry["position"] == "trailing":
        return not BLANK.fullmatch(lines[start["line"]][: start["column"]])
    window = entry["position"]
    return start["line"] < window["first"] or start["line"] >= len(lines) - window["last"]


def stands(match: dict, snapshot, path: str, row: int) -> bool:
    """
    Args:
        match: One ast-grep match with its rule's metadata.
        snapshot: Snapshot holding the file.
        path: The file.
        row: Line the match reports.

    Returns:
        False where the rule's `unless` pattern matches the whole matched
        text, which needs Python's lookahead and backreferences, where the
        comment is a directive at the only place its tool reads it, or where
        a bound `$ABOVE` still carries the match; no ast-grep rule sees these.
    """
    metadata = match.get("metadata", {})
    if "unless" in metadata and re.fullmatch(metadata["unless"], match["text"]):
        return False
    if any(placed(entry, match, snapshot.lines(path)) for entry in metadata.get("positional", [])):
        return False
    above = bound_node(match, "ABOVE")
    return above is None or broken(snapshot, path, above, row)


def parse(stdout: bytes, command: Command, snapshot) -> list:
    """
    Args:
        stdout: ast-grep's JSON stream.
        command: The chunk that ran, its copies named by index.
        snapshot: Snapshot holding the files.

    Returns:
        The findings, on the lines reported_rows names. A file the parser
        could not read in full, or that is no UTF-8 and so skipped by ast-grep, is recorded in
        the snapshot's `unparsed` for every language; it is a finding only
        where coding.parse-incomplete binds the language, which leaves out
        the languages a full parser reports, because tree-sitter grammars lag
        their languages.
    """
    rules = owners(command.bound)
    hits = []
    for line in stdout.splitlines():
        match = json.loads(line)
        path = command.files[int(match["file"])]
        owner = rules.get(prefix(match["ruleId"]))
        rows = reported_rows(match)
        if prefix(match["ruleId"]) == INCOMPLETE:
            snapshot.unparsed.add(path)
        if owner is not None and path in owner[1] and stands(match, snapshot, path, rows[0]):
            hits.extend(code_hit(owner[0], path, row, match["ruleId"], snapshot) for row in rows)
    snapshot.unparsed.update(path for path in command.files if not decodes(snapshot.data(path)))
    return hits
