import os
import re
from pathlib import Path

from quality import QualityError
from quality.adapters.base import Command
from quality.architecture import contract
from quality.gate import code_hit

CONFIG = "contracts.ini"
SUMMARY = re.compile(r"Contracts: \d+ kept, \d+ broken\.")
BROKEN_IMPORT = re.compile(r"(?<!\S)- (\S+) -> (\S+) \(([^)]*)\)")
UNKNOWN_LINE = "l.?"
LINE_PREFIX = "l."
PYTHON_SUFFIX = ".py"
PACKAGE_FILE = "__init__.py"


def commands(bound: list, _settings: dict, _empty_file) -> list:
    """
    Args:
        bound: The architecture rule with .quality/architecture.yml.
        _settings: Unused tool entry.
        _empty_file: Unused.

    Returns:
        One command; operands() stages its input and arguments.
    """
    return [Command([], [contract.PATH], bound)]


def indented(modules: tuple) -> list:
    return [f"    {module}" for module in modules]


def config_text(section: contract.Section) -> str:
    """
    Args:
        section: The python section of the contract.

    Returns:
        An import-linter configuration with one forbidden contract per rule,
        each judging direct imports only, so every finding is one import.
    """
    lines = ["[importlinter]", "root_packages =", *indented(section.packages), ""]
    for index, (importers, imported) in enumerate(section.rules):
        lines += [
            f"[importlinter:contract:{index}]",
            f"name = rule {index}",
            "type = forbidden",
            "source_modules =",
            *indented(importers),
            "forbidden_modules =",
            *indented(imported),
            "allow_indirect_imports = True",
            "",
        ]
    return "\n".join(lines)


def stage(snapshot, section: contract.Section, work: Path) -> None:
    """
    Args:
        snapshot: Snapshot holding the files.
        section: The python section of the contract.
        work: Working directory lint-imports runs in.

    Raises:
        QualityError: A root package holds no Python file.
    """
    found = set()
    for path in snapshot.paths():
        inner = contract.staged_path(path, section.source)
        if inner is None or path in snapshot.links or not path.endswith(PYTHON_SUFFIX):
            continue
        package = inner.partition("/")[0]
        if package in section.packages and "/" in inner:
            staged = work / inner
            staged.parent.mkdir(parents=True, exist_ok=True)
            os.link(snapshot.file(path), staged)
            found.add(package)
    for package in section.packages:
        if package not in found:
            raise QualityError(f"{contract.PATH}: python.packages names {package!r}, but python.source holds no Python file of it")


def prepared(section: contract.Section, snapshot, work: Path) -> list:
    """
    Args:
        section: The python section of the contract.
        snapshot: Snapshot holding the files.
        work: Working directory lint-imports runs in.

    Returns:
        The arguments of a check of the root packages, staged by name in the
        working directory, the only directory lint-imports adds to its import
        path.
    """
    stage(snapshot, section, work)
    (work / CONFIG).write_text(config_text(section), encoding="utf-8")
    return ["--no-cache", "--no-logo", "--config", CONFIG]


operands = contract.operands_for(contract.PYTHON, prepared)


def module_path(module: str, section: contract.Section, snapshot) -> str:
    """
    Args:
        module: Importing module as lint-imports names it.
        section: The python section of the contract.
        snapshot: Snapshot the module came from.

    Returns:
        The module's file in the snapshot.

    Raises:
        KeyError: No file of the snapshot is that module.
    """
    prefix = "" if section.source == contract.ROOT else f"{section.source}/"
    base = prefix + module.replace(".", "/")
    for candidate in (base + PYTHON_SUFFIX, f"{base}/{PACKAGE_FILE}"):
        if candidate in snapshot.files:
            return candidate
    raise KeyError(module)


def line_numbers(text: str) -> list:
    return [None if item == UNKNOWN_LINE else int(item.removeprefix(LINE_PREFIX)) for item in text.split(", ")]


def parse(stdout: bytes, command: Command, snapshot) -> list:
    """
    Args:
        stdout: lint-imports' report, lines wrapped wherever its console chose.
        command: The command that produced it.
        snapshot: Snapshot the files came from.

    Returns:
        One finding per line of each forbidden import, at the importing file.

    Raises:
        QualityError: The report lacks its contract summary, so the check did
            not finish.
    """
    sections = contract.read(snapshot)
    if contract.PYTHON not in sections:
        return []
    text = " ".join(stdout.decode("utf-8", "replace").split())
    if SUMMARY.search(text) is None:
        raise QualityError(f"lint-imports could not check the python contract of {contract.PATH}")
    rule = command.bound[0].binding.rule
    seen = set()
    hits = []
    for importer, imported, lines in BROKEN_IMPORT.findall(text):
        path = module_path(importer, sections[contract.PYTHON], snapshot)
        for line in line_numbers(lines):
            if (path, line, imported) not in seen:
                seen.add((path, line, imported))
                hits.append(code_hit(rule, path, line, f"{importer} -> {imported}", snapshot))
    return hits
