#!/usr/bin/env kvb-quality-python
from __future__ import annotations

import ast
import operator
import os
import re
import shutil
import subprocess
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath
from typing import NamedTuple

RULES = {
    "core/parallel.py": {
        "FILE_SCANNERS": dict, "special_exact_names": set, "special_prefixes": tuple, "env_suffix": str,
        "ai_context_dir_names": set, "MAX_SCAN_FILE_SIZE": int,
    },
    "scanners/base.py": {"MAX_RULE_SCAN_LINES": int},
    "config.py": {"exclude_paths": list, "exclude_files": list},
}
OPERATIONS = {ast.Mult: operator.mul, ast.Add: operator.add, ast.Sub: operator.sub}
WILD = re.compile(r"[*?\[]")
LOCATE = (
    "import importlib.util\n"
    "spec = importlib.util.find_spec('medusa')\n"
    "print(*(spec.submodule_search_locations or []) if spec else [], sep='\\n')\n"
)
LOCATE_SECONDS = 60


class Rules(NamedTuple):
    extensions: frozenset
    names: frozenset
    prefixes: tuple
    suffix: str
    folders: frozenset
    file_limit: int
    line_limit: int
    paths: tuple
    files: tuple


def shebang(medusa: str) -> list[str]:
    """Returns:
        the words of the medusa script's shebang line, none for a script
        without one or an unreadable one.
    """
    try:
        head = Path(medusa).resolve().read_bytes().split(b"\n", 1)[0].decode()
    except (OSError, UnicodeDecodeError):
        return []
    return head[2:].split() if head.startswith("#!") else []


def interpreter(medusa: str) -> list[str] | None:
    """Returns:
        the interpreter command of the medusa script's shebang, its `env`
        program looked up on PATH, else None.
    """
    words = shebang(medusa)
    if words and Path(words[0]).name == "env":
        named = [word for word in words[1:] if not word.startswith("-") and "=" not in word]
        program = shutil.which(named[0]) if named else None
        words = [program, *words[words.index(named[0]) + 1:]] if program else []
    return words or None


def package(medusa: str, work: Path, env: dict[str, str]) -> Path | None:
    """Returns:
        the folder of the medusa package that medusa's own interpreter imports
        with medusa's environment, else None.
    """
    command = interpreter(medusa)
    if command is None:
        return None
    try:
        result = subprocess.run(
            [*command, "-c", LOCATE], cwd=work, stdin=subprocess.DEVNULL, capture_output=True, check=False,
            env=env, timeout=LOCATE_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    folders = result.stdout.decode(errors="replace").splitlines() if result.returncode == 0 else []
    return Path(folders[0]) if folders and folders[0] else None


def factory_body(node: ast.expr | None) -> ast.expr | None:
    """Returns:
        the body of the lambda a field call hands as default_factory, else None.
    """
    if not isinstance(node, ast.Call):
        return None
    factory = [keyword.value for keyword in node.keywords if keyword.arg == "default_factory"]
    return factory[0].body if factory and isinstance(factory[0], ast.Lambda) else None


def arithmetic(node: ast.BinOp) -> int:
    """Returns:
        the integer product, sum or difference of two literal integers;
        raises ValueError for anything else.
    """
    left, right = literal(node.left), literal(node.right)
    if type(left) is not int or type(right) is not int:
        raise ValueError("not an integer")
    return OPERATIONS[type(node.op)](left, right)


def literal(node: ast.expr | None) -> object:
    """Returns:
        the value of a literal, of an integer product, sum or difference, or of
        a field's default_factory lambda; raises ValueError for anything else.
    """
    if isinstance(node, ast.BinOp) and type(node.op) in OPERATIONS:
        return arithmetic(node)
    body = factory_body(node)
    if body is not None:
        return literal(body)
    if node is None:
        raise ValueError("assigned more than once or not at all")
    return ast.literal_eval(node)


def assignments(tree: ast.AST, names: dict[str, type]) -> dict[str, ast.expr | None]:
    """Returns:
        the value node of each of names the module tree assigns, None for one
        it assigns more than once.
    """
    found = {}
    for node in ast.walk(tree):
        target = node.targets[0] if isinstance(node, ast.Assign) and len(node.targets) == 1 else None
        target = node.target if isinstance(node, ast.AnnAssign) and node.value else target
        if isinstance(target, ast.Name) and target.id in names:
            found[target.id] = None if target.id in found else node.value
    return found


def assigned(path: Path, names: dict[str, type]) -> dict[str, object]:
    """Returns:
        the value of each name assigned exactly once in the module at path,
        checked against its type; raises ValueError for any other.
    """
    found = assignments(ast.parse(path.read_text(encoding="utf-8")), names)
    values = {name: literal(found.get(name)) for name in names}
    if any(type(values[name]) is not kind or kind in (str, int) and not values[name] for name, kind in names.items()):
        raise ValueError("a rule of an unexpected shape")
    return values


def rules(folder: Path | None) -> Rules | None:
    """Returns:
        medusa's RULES from its package folder, else None when one is missing.
    """
    try:
        values = {name: value for file, names in RULES.items() for name, value in assigned(folder / file, names).items()}
    except (OSError, SyntaxError, ValueError, TypeError):
        return None
    strings = (*values["FILE_SCANNERS"], *values["special_exact_names"], *values["special_prefixes"],
               *values["ai_context_dir_names"], *values["exclude_paths"], *values["exclude_files"])
    if not all(isinstance(item, str) and item for item in strings):
        return None
    return Rules(
        frozenset(values["FILE_SCANNERS"]), frozenset(values["special_exact_names"]), values["special_prefixes"],
        values["env_suffix"], frozenset(values["ai_context_dir_names"]), values["MAX_SCAN_FILE_SIZE"],
        values["MAX_RULE_SCAN_LINES"], tuple(path.rstrip("/") for path in values["exclude_paths"]),
        tuple(values["exclude_files"]),
    )


def capped(folder: Path) -> int | None:
    """Returns:
        the plain number medusa's core/parallel.py assigns PER_SCANNER_TIMEOUT, its
        fixed cap that ignores the scanner timeout knob, else None.
    """
    try:
        return assigned(folder / "core" / "parallel.py", {"PER_SCANNER_TIMEOUT": int})["PER_SCANNER_TIMEOUT"]
    except (OSError, SyntaxError, ValueError, TypeError):
        return None


def typed(path: PurePosixPath, found: Rules) -> bool:
    extension = os.path.splitext(path.name)[1].lower()
    return (
        extension in found.extensions or path.name in found.names or path.name.startswith(found.prefixes)
        or path.name.endswith(found.suffix)
        or (len(path.parts) == 2 and path.parts[0] in found.folders and extension == ".md")
    )


def path_dropped(name: str, found: Rules) -> bool:
    """Returns:
        whether a path exclusion of medusa drops this tree path: a part equal to
        or matching a path pattern, or a path pattern anywhere inside it, as
        medusa's find_scannable_files matches them.
    """
    return any(
        part == pattern or WILD.search(pattern) and fnmatchcase(part, pattern)
        for part in PurePosixPath(name).parts for pattern in found.paths
    ) or any(pattern in name or WILD.search(pattern) and fnmatchcase(name, f"*{pattern}*") for pattern in found.paths)


def file_dropped(path: PurePosixPath, found: Rules) -> bool:
    return any(fnmatchcase(path.name, pattern) for pattern in found.files)


def taken(name: str, found: Rules) -> bool:
    """Returns:
        whether medusa's find_scannable_files takes up a file of this tree path:
        a type it scans, and no exclusion that drops it.
    """
    path = PurePosixPath(name)
    return typed(path, found) and not path_dropped(name, found) and not file_dropped(path, found)
