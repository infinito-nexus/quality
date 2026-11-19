import json
import re
import tomllib
from dataclasses import dataclass

from quality.gate import package_name
from quality.legal.spdx import expression_of
from quality.ruledata import gitignore_spec

REQUIREMENT = re.compile(r"^\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[[^\]]*\])?\s*(?:===?\s*([^\s;,#]+))?")
SKIPPED_LINE = re.compile(r"^\s*(?:$|#|-|\.|/)|://")
EXACT_SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
LOCK_KEY = re.compile(r'^\s*"((?:[^"\\]|\\.)*node_modules/(?:[^"\\]|\\.)*)"\s*:')
COMPOSER_NAME = re.compile(r'^\s*"name"\s*:\s*"([^"]+)"')
NODE_MODULES = "node_modules/"
PYPI = "PyPI"
NPM = "npm"
PACKAGIST = "Packagist"
NPM_RUNTIME = ("dependencies", "optionalDependencies")


@dataclass(frozen=True)
class Dependency:
    """
    Args:
        ecosystem: Ecosystem as osv-scanner names it.
        name: Package name as gate.package_name() normalises it.
        version: Exact version, or empty for a range.
        license: SPDX expression the file itself declares, or None.
        row: Line declaring the package, or None.
    """

    ecosystem: str
    name: str
    version: str
    license: str | None
    row: int | None


def format_of(path: str, formats: dict) -> str | None:
    """
    Args:
        path: Dependency file relative to the snapshot root.
        formats: Reader name to the file patterns it reads.

    Returns:
        The first reader whose patterns match the path, or None.
    """
    return next((name for name, patterns in formats.items() if gitignore_spec(patterns).match_file(path)), None)


def read_dependencies(reader: str, snapshot, path: str) -> list | None:
    """
    Args:
        reader: Name from format_of().
        snapshot: Snapshot holding the file.
        path: The file.

    Returns:
        The runtime dependencies it declares; build-, test- and dev-only ones
        are left out. None when the file does not parse.
    """
    try:
        return READERS[reader](snapshot, path)
    except (ValueError, LookupError, TypeError, AttributeError):
        return None


def first_rows(lines: list, pattern: re.Pattern) -> dict:
    rows = {}
    for row, line in enumerate(lines, 1):
        found = pattern.match(line)
        if found is not None:
            rows.setdefault(found.group(1), row)
    return rows


def row_of(lines: list, needle: str) -> int | None:
    return next((row for row, line in enumerate(lines, 1) if needle in line), None)


def requirement(text: str, row: int | None) -> Dependency | None:
    found = REQUIREMENT.match(text)
    if found is None:
        return None
    return Dependency(PYPI, package_name(PYPI, found.group(1)), found.group(2) or "", None, row)


def requirements(snapshot, path: str) -> list:
    found = []
    for row, line in enumerate(snapshot.lines(path), 1):
        text = re.split(r"(?:^|\s)#", line, maxsplit=1)[0]
        dependency = None if SKIPPED_LINE.search(text) else requirement(text, row)
        if dependency is not None:
            found.append(dependency)
    return found


def pyproject(snapshot, path: str) -> list:
    document = tomllib.loads(snapshot.data(path).decode("utf-8"))
    declared = document.get("project", {}).get("dependencies", [])
    lines = snapshot.lines(path)
    found = [requirement(text, row_of(lines, text)) for text in declared if isinstance(text, str)]
    return [dependency for dependency in found if dependency is not None]


def package_json(snapshot, path: str) -> list:
    document = json.loads(snapshot.data(path))
    lines = snapshot.lines(path)
    return [
        Dependency(NPM, name, spec if EXACT_SEMVER.match(spec) else "", None, row_of(lines, f'"{name}"'))
        for section in NPM_RUNTIME
        for name, spec in document.get(section, {}).items()
        if isinstance(spec, str)
    ]


def package_lock(snapshot, path: str) -> list:
    packages = json.loads(snapshot.data(path))["packages"]
    rows = first_rows(snapshot.lines(path), LOCK_KEY)
    return [
        Dependency(NPM, key.rsplit(NODE_MODULES, 1)[1], str(entry.get("version", "")), expression_of(entry.get("license")), rows.get(key))
        for key, entry in packages.items()
        if NODE_MODULES in key and not entry.get("dev") and not entry.get("link")
    ]


def composer_lock(snapshot, path: str) -> list:
    packages = json.loads(snapshot.data(path))["packages"]
    rows = first_rows(snapshot.lines(path), COMPOSER_NAME)
    return [
        Dependency(
            PACKAGIST,
            package_name(PACKAGIST, entry["name"]),
            str(entry.get("version", "")),
            expression_of(entry.get("license")),
            rows.get(entry["name"]),
        )
        for entry in packages
    ]


READERS = {
    "requirements": requirements,
    "pyproject": pyproject,
    "package-json": package_json,
    "package-lock": package_lock,
    "composer-lock": composer_lock,
}
