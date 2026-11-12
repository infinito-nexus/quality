import fnmatch
import hashlib
import json
import os
import posixpath
import re
import shlex
import shutil

from quality import QualityError
from quality.adapters.base import Command, checked_rules, known_path, relative
from quality.gate import package_hit, package_name
from quality.ruledata import gitignore_spec

SCANNED = re.compile(rb"^Scanned (/[^\n]+) file and found [0-9]+ packages?\r?$", re.M)
EXTRACTION = re.compile(rb"^Error during extraction: \(extracting as [^)\n]*\) ([^\n]*(?:\n\t[^\n]*)*)$", re.M)
JOINED = b"\n\t"
OPENED = re.compile(rb'^openAndExtractFromFile\("((?:[^"\\\n]|\\[^\n])*)"\): [^\n]*$', re.M)
GO_ESCAPE = re.compile(rb"\\(?:x([0-9A-Fa-f]{2})|u([0-9A-Fa-f]{4})|U([0-9A-Fa-f]{8})|(.))", re.S)
GO_ESCAPES = {b"a": b"\a", b"b": b"\b", b"f": b"\f", b"n": b"\n", b"r": b"\r", b"t": b"\t", b"v": b"\v"}
REQUIREMENTS = "requirements.txt"
REQUIREMENTS_NAME = "*requirements*.txt"
INCLUDE_OPTIONS = ("--requirement", "--constraint", "-r", "-c")
CONTINUATION = re.compile(r"\\\r?\n")
COMMENT = re.compile(r"(?:^|\s+)#.*$")
BOM = chr(0xFEFF)
FOLLOWED_BY_OSV = "-r"


def parser_for(item, path: str) -> str | None:
    """
    Args:
        item: A rule bound to osv-scanner with its lockfiles.
        path: One of those lockfiles.

    Returns:
        The parser the enforcer's parse_as names, or None.
    """
    for pattern, parser in item.binding.settings.get("parse_as", {}).items():
        if gitignore_spec([pattern]).match_file(path):
            return parser
    return None


def commands(bound: list, _settings: dict, empty_file) -> list:
    """
    Args:
        bound: The rule with its lockfiles.
        _settings: Unused tool entry.
        empty_file: Replaces the osv-scanner.toml.

    Returns:
        Offline commands: no resolution, no deps.dev, local databases only. One
        for every lockfile osv-scanner knows by name, one per lockfile it is told
        how to parse.
    """
    prefix = [
        "scan",
        "source",
        "--offline",
        "--offline-vulnerabilities",
        "--no-resolve",
        "--no-ignore",
        "--allow-no-lockfiles",
        "--config",
        str(empty_file),
        "--verbosity",
        "info",
        "--format",
        "json",
    ]
    parsers = {}
    for item in bound:
        for path in item.files:
            parsers.setdefault(path, parser_for(item, path))
    named = [path for path, parser in sorted(parsers.items()) if parser is None]
    result = [Command(prefix, named, bound)] if named else []
    return result + [Command(prefix, [path], bound) for path, parser in sorted(parsers.items()) if parser is not None]


def parsed_as(command: Command, path: str) -> str | None:
    return next((parser for item in command.bound if path in item.files and (parser := parser_for(item, path))), None)


def operands(command: Command, snapshot, _work) -> list:
    """
    Args:
        command: One chunk.
        snapshot: Snapshot holding its files.
        _work: Unused working directory.

    Returns:
        A `--lockfile` flag for each file of the chunk osv-scanner is told how
        to parse, which is also named after `--`, and one for every file its
        requirements files include; then `--` and the files. A flag names a
        file whose path holds a comma by a copy, see staged().
    """
    forced = [f"--lockfile={parser}:{flag_path(snapshot, path)}" for path in command.files if (parser := parsed_as(command, path))]
    included = passed(command, snapshot, includes_of(command, snapshot))
    flags = forced + [f"--lockfile={REQUIREMENTS}:{flag_path(snapshot, path)}" for path in included]
    return [*flags, "--", *(str(snapshot.root / path) for path in command.files)]


def staged(snapshot, path: str):
    """
    Args:
        snapshot: Snapshot holding the file.
        path: A lockfile whose path holds a comma.

    Returns:
        Where its copy goes: a name without a comma in a directory beside the
        snapshot root.
    """
    digest = hashlib.sha256(os.fsencode(path)).hexdigest()
    return snapshot.root.with_name(f"{snapshot.root.name}.osv") / f"{digest}.txt"


def flag_path(snapshot, path: str):
    if "," not in path:
        return snapshot.root / path
    copy = staged(snapshot, path)
    copy.parent.mkdir(mode=0o700, exist_ok=True)
    shutil.copyfile(snapshot.root / path, copy)
    return copy


def passed(command: Command, snapshot, graph: dict) -> list:
    return sorted(path for path in graph if path not in command.files and readable(snapshot, path))


def readable(snapshot, path: str) -> bool:
    return path in snapshot.files and path not in snapshot.links


def requirements_files(command: Command) -> list:
    return [
        path
        for path in command.files
        if parsed_as(command, path) == REQUIREMENTS or fnmatch.fnmatchcase(posixpath.basename(path), REQUIREMENTS_NAME)
    ]


def includes_of(command: Command, snapshot) -> dict:
    """
    Args:
        command: One chunk.
        snapshot: Snapshot holding its files.

    Returns:
        Every file the chunk's requirements files include with `-r`,
        `--requirement`, `-c` or `--constraint`, directly or through another
        include, resolved against the including file's name as pip does and
        through symlinks as the system does, mapped to the files of the chunk
        that reach it. A path outside the snapshot root starts with `../` or
        `/`.
    """
    graph = {}
    for path in requirements_files(command):
        pending, seen = [(path, path)], {path}
        while pending:
            named, current = pending.pop()
            if not readable(snapshot, current):
                continue
            for target in include_targets(snapshot.data(current)):
                spelled = posixpath.normpath(posixpath.join(posixpath.dirname(named), target))
                resolved = followed(spelled, snapshot)
                graph.setdefault(resolved, set()).add(path)
                if resolved not in seen:
                    seen.add(resolved)
                    pending.append((spelled, resolved))
    return graph


def followed(path: str, snapshot) -> str:
    """
    Args:
        path: An include as pip names it, relative to the snapshot root.
        snapshot: Snapshot holding the files, a symlink as its target text.

    Returns:
        The file the path names once every symlink in it, a file or a
        directory, is replaced by its target, through every further link:
        outside the root it starts with `../` or `/`, and in a loop it keeps a
        link. Any other path unchanged.
    """
    hops = set()
    while (link := linked_prefix(path, snapshot)) and link not in hops:
        hops.add(link)
        target = os.fsdecode(snapshot.data(link))
        path = posixpath.normpath(posixpath.join(posixpath.dirname(link), target, path[len(link) + 1 :]))
    return path


def linked_prefix(path: str, snapshot) -> str:
    parts = path.split("/")
    prefixes = ("/".join(parts[:count]) for count in range(1, len(parts) + 1))
    return next((prefix for prefix in prefixes if prefix in snapshot.links), "")


def logical_lines(data: bytes) -> list:
    """
    Args:
        data: Content of one requirements file.

    Returns:
        Its lines as pip reads them: without a UTF-8 byte order mark, with
        continued lines joined and comments dropped, stripped.
    """
    text = CONTINUATION.sub("", data.decode("utf-8", "surrogateescape").removeprefix(BOM))
    return [COMMENT.sub("", line).strip() for line in text.splitlines()]


def include_targets(data: bytes) -> list:
    """
    Args:
        data: Content of one requirements file.

    Returns:
        The value of every include option, in each form pip reads: `-r f`,
        `-rf`, `--requirement f` and `--requirement=f`, and the same for `-c`
        and `--constraint`, unquoted as pip does, see logical_lines().
    """
    targets = []
    for line in logical_lines(data):
        words = option_words(line)
        for word, following in zip(words, [*words[1:], ""]):
            targets += [value for value in [included_by(word, following)] if value]
    return targets


def own_openings(command: Command, snapshot, graph: dict) -> set:
    """
    Args:
        command: One chunk.
        snapshot: Snapshot holding its files.
        graph: Its includes, see includes_of().

    Returns:
        Every file osv-scanner opens itself for a `-r` line of a requirements
        file it reads, the rest of the line, placed as placed() does, beside
        that file and, for one it reads from a copy, see staged(), beside the
        copy.
    """
    openings = set()
    for path in [*requirements_files(command), *graph]:
        if readable(snapshot, path):
            for line in logical_lines(snapshot.data(path)):
                if line.startswith(FOLLOWED_BY_OSV):
                    rest = line.removeprefix(FOLLOWED_BY_OSV).strip()
                    openings.update(placed(directory, rest) for directory in read_from(snapshot, path))
    return openings


def read_from(snapshot, path: str) -> list:
    directories = [snapshot.root / posixpath.dirname(path)]
    return [*directories, staged(snapshot, path).parent] if "," in path else directories


def option_words(line: str) -> list:
    if not line.startswith("-"):
        return []
    try:
        return shlex.split(line)
    except ValueError:
        return line.split()


def included_by(word: str, following: str) -> str:
    for option in INCLUDE_OPTIONS:
        if word == option:
            return following
        glued = f"{option}=" if option.startswith("--") else option
        if word.startswith(glued):
            return word[len(glued) :]
    return ""


def owners_of(path: str, command: Command, graph: dict) -> set:
    return ({path} & set(command.files)) | graph.get(path, set())


def parse(stdout: bytes, command: Command, snapshot) -> list:
    """
    Args:
        stdout: osv-scanner's JSON report.
        command: The command that produced it.
        snapshot: Snapshot the lockfiles came from.

    Returns:
        One file-level finding per vulnerable package and lockfile, carrying its
        name and vulnerability ids; a package of an included file counts for
        every file of the command including it. None when only
        security.partial-scan is bound.
    """
    rules = checked_rules(command)
    if not rules:
        return []
    rule = rules[0]
    graph = includes_of(command, snapshot)
    given = spellings(command, snapshot, graph)
    found = {}
    for result in json.loads(stdout)["results"]:
        path = source_path(result["source"]["path"], given, snapshot)
        for package in result["packages"]:
            if package["vulnerabilities"]:
                name = package_name(package["package"].get("ecosystem", ""), package["package"]["name"])
                for owner in owners_of(path, command, graph) or {path}:  # nocheck: clean.default-value -- a lockfile no file of the command includes owns its packages
                    ids = found.setdefault((owner, name), set())
                    ids.update(vulnerability["id"] for vulnerability in package["vulnerabilities"])
    return [package_hit(rule, path, None, name, ids) for (path, name), ids in sorted(found.items())]


def source_path(reported: str, given: dict, snapshot) -> str:
    spelled = os.fsencode(reported)
    if spelled in given:
        return given[spelled]
    return known_path(relative(reported, snapshot.root), snapshot)


def spellings(command: Command, snapshot, graph: dict) -> dict:
    """
    Args:
        command: One chunk.
        snapshot: Snapshot holding its files.
        graph: Its includes, see includes_of().

    Returns:
        Every absolute path osv-scanner was given, as it prints it, mapped to
        the file of the snapshot: each file of the command and each include
        passed, under the root, and for a path holding a comma its copy too.
    """
    given = {}
    for path in [*command.files, *passed(command, snapshot, graph)]:
        given[os.fsencode(os.path.join(snapshot.root, path))] = path
        if "," in path:
            given[os.fsencode(staged(snapshot, path))] = path
    return given


def unparsed(result, command: Command, _settings: dict, snapshot) -> list:
    """
    Args:
        result: The finished run of one command.
        command: The command naming the lockfiles.
        _settings: Unused.
        snapshot: Snapshot the lockfiles came from.

    Returns:
        The lockfiles of the command osv-scanner did not confirm as scanned,
        or named in an extraction error, together with every file including a
        file it did not confirm or named, such as an include that is missing or
        outside the snapshot root, on any exit code.

    Raises:
        QualityError: An extraction error names neither a file of the command
            under the snapshot root nor one of its includes, nor a file
            osv-scanner opens itself in place of an include passed, see
            own_openings(), or osv-scanner neither confirmed nor named any of
            them, as when it crashes.
    """
    graph = includes_of(command, snapshot)
    paths = {*command.files, *graph}
    given = spellings(command, snapshot, graph)
    scanned = {given[path] for path in SCANNED.findall(result.stderr) if path in given}
    named = named_in_errors(result.stderr, places_of(snapshot, paths, given), own_openings(command, snapshot, graph))
    if not scanned and not named:
        raise QualityError(f"osv-scanner confirmed no lockfile and exited {result.code}")
    gaps = {owner for path in [*named, *(paths - scanned)] for owner in owners_of(path, command, graph)}
    return [path for path in command.files if path in gaps]


def places_of(snapshot, paths: set, given: dict) -> dict:
    places = {placed(snapshot.root, path): path for path in paths}
    return places | {spelled.removeprefix(b"/"): path for spelled, path in given.items()}


def named_in_errors(stderr: bytes, places: dict, openings: set) -> list:
    tails = [tail for block in EXTRACTION.findall(stderr) for tail in block.split(JOINED) if tail.strip()]
    named = [extracted(tail, places) for tail in tails]
    opened = [GO_ESCAPE.sub(unescaped, quoted) for quoted in OPENED.findall(stderr)]
    return named + [placed_path(path, places) for path in opened if path in places or path not in openings]


def placed(root, path: str) -> bytes:
    return os.fsencode(os.path.normpath(os.path.join(root, path))).removeprefix(b"/")


def extracted(tail: bytes, places: dict) -> str:
    named = [place for place in places if tail.startswith(place + b": ")]
    if not named:
        raise QualityError("osv-scanner printed an extraction error outside this check, so its report cannot be trusted")
    return places[max(named, key=len)]


def placed_path(path: bytes, places: dict) -> str:
    if path not in places:
        raise QualityError("osv-scanner printed an extraction error outside this check, so its report cannot be trusted")
    return places[path]


def unescaped(match) -> bytes:
    hexadecimal, short, long, simple = match.groups()
    if hexadecimal:
        return bytes([int(hexadecimal, 16)])
    if short or long:
        return chr(min(int(short or long, 16), 0x10FFFF)).encode("utf-8", "replace")
    return GO_ESCAPES.get(simple, simple)  # nocheck: clean.default-value -- Go keeps any other escaped character as written
