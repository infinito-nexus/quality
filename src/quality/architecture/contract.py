import os
import re
import sys
from dataclasses import dataclass

import yaml

from quality import QualityError

PATH = ".quality/architecture.yml"
PYTHON = "python"
JAVASCRIPT = "javascript"
SECTION_KEYS = {
    PYTHON: ("source", "packages", "layers", "forbidden"),
    JAVASCRIPT: ("source", "layers", "forbidden"),
}
FORBIDDEN_KEYS = ("from", "to")
MODULE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*")
ROOT = "."
VERSION_FLAG = "--version"


@dataclass(frozen=True)
class Section:
    """
    Args:
        source: Directory, relative to the repository root, the section's
            code lives under; `.` for the root.
        packages: Root packages of a Python section, empty for JavaScript.
        rules: Forbidden imports as pairs of importers and imported: one per
            layer naming every layer above it, then each declared entry.
    """

    source: str
    packages: tuple
    rules: tuple


def fail(where: str, problem: str) -> QualityError:
    return QualityError(f"{PATH}: {where} {problem}")


def exact_keys(raw, keys: tuple, where: str) -> None:
    """
    Args:
        raw: A mapping read from the file.
        keys: Every key it must hold, and the only ones it may.
        where: Its place in the file, for the error.

    Raises:
        QualityError: The value is no mapping, or a key is missing or unknown.
    """
    if not isinstance(raw, dict):
        raise fail(where, f"must be a mapping of {', '.join(keys)}")
    for key in keys:
        if key not in raw:
            raise fail(where, f"is missing key {key!r}")
    for key in raw:
        if key not in keys:
            raise fail(where, f"has unknown key {key!r}")


def relative_dir(value, where: str) -> str:
    """
    Args:
        value: A path read from the file.
        where: Its key, for the error.

    Returns:
        The path: `.` or a normalised relative POSIX path that leaves no
        directory and starts with no dash.

    Raises:
        QualityError: Any other value.
    """
    plain = isinstance(value, str) and value and "\\" not in value and not value.startswith(("/", "-"))
    if not plain or (value != ROOT and os.path.normpath(value) != value) or value.startswith(".."):
        raise fail(where, "must be a relative path inside the repository, such as src or web/app")
    return value


def within(path: str, root: str) -> bool:
    return root == ROOT or path == root or path.startswith(f"{root}/")


def names(raw, where: str, check, required: bool) -> tuple:
    """
    Args:
        raw: A list read from the file.
        where: Its key, for the error.
        check: Validates one entry, given the entry and its key.
        required: True refuses an empty list.

    Returns:
        The validated entries.

    Raises:
        QualityError: The value is no list, an empty one where one is
            required, or an entry fails the check.
    """
    if not isinstance(raw, list) or (required and not raw):
        raise fail(where, "must be a non-empty list" if required else "must be a list")
    return tuple(check(entry, f"{where}[{index}]") for index, entry in enumerate(raw))


def module_name(value, where: str) -> str:
    if not isinstance(value, str) or MODULE.fullmatch(value) is None:
        raise fail(where, "must be a dotted Python module name")
    return value


def package_name(value, where: str) -> str:
    """
    Args:
        value: A root package read from the file.
        where: Its key, for the error.

    Returns:
        The package.

    Raises:
        QualityError: It is no top-level module name, or one of the standard
            library, which lint-imports would import in its place.
    """
    if module_name(value, where) != value.partition(".")[0]:
        raise fail(where, "must be a top-level package name")
    if value in sys.stdlib_module_names:
        raise fail(where, f"names {value!r}, a standard library module lint-imports would load from the repository")
    return value


def layer_rules(layers: tuple) -> list:
    return [((layer,), layers[:index]) for index, layer in enumerate(layers) if index]


def forbidden_rules(raw, where: str, check) -> list:
    if not isinstance(raw, list):
        raise fail(where, "must be a list")
    rules = []
    for index, entry in enumerate(raw):
        place = f"{where}[{index}]"
        exact_keys(entry, FORBIDDEN_KEYS, place)
        rules.append((names(entry["from"], f"{place}.from", check, True), names(entry["to"], f"{place}.to", check, True)))
    return rules


def python_section(raw: dict) -> Section:
    source = relative_dir(raw["source"], "python.source")
    packages = names(raw["packages"], "python.packages", package_name, True)
    rules = layer_rules(names(raw["layers"], "python.layers", module_name, False))
    rules += forbidden_rules(raw["forbidden"], "python.forbidden", module_name)
    if not rules:
        raise fail(PYTHON, "declares no layer rule and no forbidden import")
    for importers, imported in rules:
        for module in importers + imported:
            if module.partition(".")[0] not in packages:
                raise fail(PYTHON, f"names module {module!r} outside python.packages")
    return Section(source, packages, tuple(rules))


def javascript_section(raw: dict) -> Section:
    source = relative_dir(raw["source"], "javascript.source")
    rules = layer_rules(names(raw["layers"], "javascript.layers", relative_dir, False))
    rules += forbidden_rules(raw["forbidden"], "javascript.forbidden", relative_dir)
    for importers, imported in rules:
        for path in importers + imported:
            if path == ROOT or not within(path, source):
                raise fail(JAVASCRIPT, f"names path {path!r} outside javascript.source")
    return Section(source, (), tuple(rules))


BUILDERS = {PYTHON: python_section, JAVASCRIPT: javascript_section}


def parse(data: bytes) -> dict:
    """
    Args:
        data: Content of .quality/architecture.yml.

    Returns:
        The declared sections by language, python and javascript, each one
        present only when the file declares it.

    Raises:
        QualityError: The file is no YAML mapping of at least one language,
            or a key is missing, unknown or malformed; the error names it.
    """
    try:
        document = yaml.safe_load(data)
    except yaml.YAMLError:
        raise QualityError(f"{PATH} is no valid YAML") from None
    if not isinstance(document, dict) or not document:
        raise QualityError(f"{PATH} must map {PYTHON} or {JAVASCRIPT} to its contract")
    for name in document:
        if name not in BUILDERS:
            raise QualityError(f"{PATH} has unknown key {name!r}, expected {PYTHON} or {JAVASCRIPT}")
    sections = {}
    for name, raw in document.items():
        exact_keys(raw, SECTION_KEYS[name], name)
        sections[name] = BUILDERS[name](raw)
    return sections


def read(snapshot) -> dict:
    """
    Args:
        snapshot: Snapshot holding .quality/architecture.yml.

    Returns:
        The sections parse() reads from it.

    Raises:
        QualityError: The file is a symlink or malformed.
    """
    if PATH in snapshot.links:
        raise QualityError(f"{PATH} must be a regular file")
    return parse(snapshot.data(PATH))


def operands_for(name: str, prepare):
    """
    Args:
        name: Language whose section the tool checks.
        prepare: Stages the section's input in the empty working directory
            of the run and returns the tool's arguments, given section,
            snapshot and that directory.

    Returns:
        An adapter's operands(command, snapshot, work): those arguments, or
        those of a version call when the file declares no section of that
        language.
    """

    def operands(_command, snapshot, work) -> list:
        sections = read(snapshot)
        if name not in sections:
            return [VERSION_FLAG]
        return prepare(sections[name], snapshot, work)

    return operands


def staged_path(path: str, source: str) -> str | None:
    """
    Args:
        path: Path relative to the repository root.
        source: A section's source directory.

    Returns:
        The path relative to the source directory, or None outside it.
    """
    if source == ROOT:
        return path
    return path[len(source) + 1 :] if path.startswith(f"{source}/") else None
