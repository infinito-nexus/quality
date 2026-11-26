import ast
import posixpath
import re
from dataclasses import dataclass

SOURCE_ROOTS = ("", "src/")
TEST_MODULE = re.compile(r"(?:^|/)(?:tests?/|test_[^/]*\.py$|[^/]*_test\.py$|conftest\.py$)")
TEST_FILE = re.compile(r"(?:^|/)(?:test_[^/]*|[^/]*_test)\.py$")
NESTED = (ast.If, ast.Try)
LOOKUP_DEPTH = 6


@dataclass(eq=False)
class Module:
    """
    Args:
        path: Snapshot path of the file.
        package: Dotted package the module lies in.
        functions: Top-level function name to its node.
        classes: Top-level class name to its node.
        imports: Local name to (dotted module, imported name or None).
        assignments: Top-level assignments in source order.
    """

    path: str
    package: str
    functions: dict
    classes: dict
    imports: dict
    assignments: list

    @property
    def test(self) -> bool:
        return TEST_MODULE.search(self.path) is not None


def package_of(path: str) -> str:
    folder = posixpath.dirname(path)
    for root in SOURCE_ROOTS:
        if root and folder.startswith(root):
            folder = folder[len(root) :]
    return folder.replace("/", ".")


def absolute(package: str, node: ast.ImportFrom) -> str:
    if not node.level:
        return node.module or ""
    parts = package.split(".") if package else []
    parts = parts[: len(parts) - node.level + 1] if node.level > 1 else parts
    return ".".join([*parts, *([node.module] if node.module else [])])


def module_alias(alias) -> tuple:
    root = alias.name.split(".")[0]
    return (alias.asname, alias.name) if alias.asname else (root, root)


def imported_names(package: str, node) -> dict:
    if isinstance(node, ast.Import):
        return {local: (dotted, None) for local, dotted in map(module_alias, node.names)}
    base = absolute(package, node)
    return {alias.asname or alias.name: (base, alias.name) for alias in node.names}


def collect(module: Module, statements: list) -> None:
    for node in statements:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            module.functions[node.name] = node
        elif isinstance(node, ast.ClassDef):
            module.classes[node.name] = node
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            module.imports.update(imported_names(module.package, node))
        elif isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            module.assignments.append(node)
        elif isinstance(node, NESTED):
            collect(module, nested_statements(node))


def nested_statements(node) -> list:
    handlers = [statement for handler in getattr(node, "handlers", []) for statement in handler.body]
    return [*node.body, *handlers, *node.orelse, *getattr(node, "finalbody", [])]


class Index:
    """
    Args:
        snapshot: Snapshot whose Python files the index parses on demand.
    """

    def __init__(self, snapshot):
        self.snapshot = snapshot
        self.parsed = {}

    def module(self, path: str) -> Module | None:
        """
        Args:
            path: Snapshot path of a Python file.

        Returns:
            Its parsed module, or None when the file is absent, no text or
            no valid Python.
        """
        if path not in self.parsed:
            self.parsed[path] = self.parse(path)
        return self.parsed[path]

    def parse(self, path: str) -> Module | None:
        if path not in self.snapshot.files:
            return None
        data = self.snapshot.text(path)
        try:
            tree = ast.parse(data or b"")
        except (SyntaxError, ValueError, RecursionError):
            return None
        module = Module(path, package_of(path), {}, {}, {}, [])
        collect(module, tree.body)
        return module

    def find(self, dotted: str) -> Module | None:
        relative = dotted.replace(".", "/")
        for root in SOURCE_ROOTS:
            for candidate in (f"{root}{relative}.py", f"{root}{relative}/__init__.py"):
                module = self.module(candidate) if relative else None
                if module is not None:
                    return module
        return None

    def lookup(self, module: Module, name: str, depth: int) -> tuple | None:
        """
        Args:
            module: Module the name is used in.
            name: A top-level name of it.
            depth: Import hops taken so far.

        Returns:
            ("function"|"class", module, node), ("module", module) or
            ("constant", module, name), following imports into other files of
            the snapshot; None for anything outside it.
        """
        if name in module.functions:
            return ("function", module, module.functions[name])
        if name in module.classes:
            return ("class", module, module.classes[name])
        if name in module.imports and depth < LOOKUP_DEPTH:
            return self.imported(*module.imports[name], depth)
        if any(name in assigned_names(node) for node in module.assignments):
            return ("constant", module, name)
        return None

    def imported(self, dotted: str, name: str | None, depth: int) -> tuple | None:
        target = self.find(dotted)
        if name is None:
            return None if target is None else ("module", target)
        found = None if target is None else self.lookup(target, name, depth + 1)
        if found is None:
            submodule = self.find(f"{dotted}.{name}")
            return None if submodule is None else ("module", submodule)
        return found


def assigned_names(node) -> set:
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    return {name.id for target in targets for name in ast.walk(target) if isinstance(name, ast.Name)}
