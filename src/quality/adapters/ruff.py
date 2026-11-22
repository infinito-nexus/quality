import ast
import json
import posixpath

from quality import QualityError
from quality.adapters.base import Command, all_files, known_path, relative
from quality.gate import code_hit
from quality.ruledata import require

PYTHON_SUFFIXES = (".py", ".pyi", ".pyw", ".ipynb")
NOTEBOOK_SUFFIX = ".ipynb"
SOURCE_ROOTS = ("", "src/")
PACKAGE_MARKERS = ("__init__.py", "__init__.pyi")
UNPARSED = (SyntaxError, ValueError, RecursionError, MemoryError)


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


def opens(bound: list, snapshot) -> set:
    """
    Args:
        bound: Rules with their files.
        snapshot: Snapshot ruff runs in. Under --isolated its root is the
            project root, and `.` and `src` are the source roots.

    Returns:
        The files ruff looks up on disk besides its own: the package marker
        of each folder above one of them, for INP001 and same-package
        imports, and each module file or package marker an absolute import
        of theirs names by any leading part under either source root, for
        the first-party section of I001. Every Python file of the snapshot
        when one of them is a notebook, does not parse, or holds an import
        spelled in other than ASCII.
    """
    files = all_files(bound)
    names = imported_names(files, snapshot)
    if names is None:
        return {path for path in snapshot.paths() if path.endswith(PYTHON_SUFFIXES)}
    markers = {posixpath.join(folder, marker) for path in files for folder in folders_above(path) for marker in PACKAGE_MARKERS}
    return markers | {candidate for name in names for candidate in module_files(name)}


def folders_above(path: str) -> list:
    parts = path.split("/")[:-1]
    return ["/".join(parts[:count]) for count in range(len(parts) + 1)]


def module_files(name: str) -> set:
    """
    Args:
        name: Dotted module name of an absolute import.

    Returns:
        Under each source root, every leading part of the name as a module
        file and as a package marker, in each Python suffix.
    """
    parts = name.split(".")
    found = set()
    for count in range(1, len(parts) + 1):
        stem = "/".join(parts[:count])
        for root in SOURCE_ROOTS:
            found.update(f"{root}{stem}{suffix}" for suffix in PYTHON_SUFFIXES)
            found.update(f"{root}{stem}/__init__{suffix}" for suffix in PYTHON_SUFFIXES)
    return found


def imported_names(files: list, snapshot) -> set | None:
    names = set()
    for path in files:
        found = None if path.endswith(NOTEBOOK_SUFFIX) else imports_of(snapshot.data(path))
        if found is None:
            return None
        names |= found
    return names


def imports_of(data: bytes) -> set | None:
    """
    Args:
        data: Content of one Python file.

    Returns:
        The module each absolute import names, for `from a import b` also
        `a.b`. None when the file is not UTF-8, does not parse, or an import
        statement holds a character other than ASCII.
    """
    try:
        source = data.decode("utf-8-sig")
        tree = ast.parse(source)
    except UNPARSED:
        return None
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if not ast.get_source_segment(source, node).isascii():
                return None
            names |= import_names(node)
    return names


def import_names(node) -> set:
    if isinstance(node, ast.Import):
        return {alias.name for alias in node.names}
    if node.level:
        return set()
    return {node.module, *(f"{node.module}.{alias.name}" for alias in node.names)}


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
