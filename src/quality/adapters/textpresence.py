import ast
import posixpath

from quality.adapters.pychecks import DIFFERENT, POSITIVE, Analyzer, classify
from quality.adapters.pylabels import PATH, TEMP, TEMP_NAME, call_name
from quality.adapters.pymodules import TEST_FILE, Index, Module
from quality.adapters.pyprogram import Program, Scope, parameters
from quality.gate import code_hit

PATCHES = ("patch", "mock")


def fixture(node) -> bool:
    return any("fixture" in ast.unparse(item) for item in node.decorator_list)


def parametrized(names) -> list:
    if isinstance(names, ast.Constant) and isinstance(names.value, str):
        return [name.strip() for name in names.value.split(",")]
    if isinstance(names, (ast.List, ast.Tuple)):
        return [item.value for item in names.elts if isinstance(item, ast.Constant)]
    return []


def tests(module: Module) -> list:
    found = [(None, node) for name, node in module.functions.items() if name.startswith("test")]
    for cls in module.classes.values():
        found += [(cls, node) for node in cls.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test")]
    return found


def patched(function) -> bool:
    return any(call_name(item.func if isinstance(item, ast.Call) else item) in PATCHES for item in function.decorator_list)


class Tests(Program):

    def fixtures(self, module: Module) -> dict:
        folder = posixpath.dirname(module.path)
        chain = [module]
        while True:
            conftest = self.index.module(posixpath.join(folder, "conftest.py"))
            chain += [conftest] if conftest is not None else []
            if not folder:
                break
            folder = posixpath.dirname(folder)
        found = {}
        for owner in reversed(chain):
            found.update({name: (owner, node) for name, node in owner.functions.items() if fixture(node)})
        return found

    def parametrize_taints(self, module: Module, function) -> dict:
        analyzer = Analyzer(self, Scope(module, None, 0), dict(self.module_env(module)), {})
        found = {}
        for decorator in function.decorator_list:
            if isinstance(decorator, ast.Call) and call_name(decorator.func) == "parametrize" and len(decorator.args) > 1:
                found.update(dict.fromkeys(parametrized(decorator.args[0]), analyzer.taint(decorator.args[1])))
        return found

    def parameter_taints(self, module: Module, function) -> dict:
        found = self.parametrize_taints(module, function)
        fixtures = self.fixtures(module)
        for name in parameters(function):
            if name in fixtures and name not in found:
                owner, node = fixtures[name]
                found[name] = self.summary(Scope(owner, None, 1), node, ()).ret
            elif TEMP_NAME.match(name):
                found[name] = frozenset({TEMP, PATH})
        return found

    def flagged(self, path: str) -> list:
        """
        Args:
            path: A test file of the snapshot.

        Returns:
            The def line of each test whose assertions are all presence
            checks on read text, one of them positive, and which runs,
            writes or patches nothing.
        """
        module = self.index.module(path)
        if module is None:
            return []
        found = []
        for cls, function in tests(module):
            try:
                hit = self.presence_only(module, cls, function)
            except RecursionError:
                hit = False
            found += [function.lineno] if hit else []
        return found

    def presence_only(self, module: Module, cls, function) -> bool:
        if patched(function):
            return False
        env = dict(self.module_env(module))
        env.update(self.parameter_taints(module, function))
        attrs = self.class_attrs(module, cls) if cls is not None else {}
        analyzer = Analyzer(self, Scope(module, cls, 0), env, attrs)
        analyzer.block(function.body)
        verdicts = {classify(check) for check in analyzer.checks}
        return not analyzer.acts and POSITIVE in verdicts and DIFFERENT not in verdicts


def text_presence(item, snapshot) -> list:
    """
    Args:
        item: Bound rule with its Python files.
        snapshot: Snapshot holding them and the modules they import.

    Returns:
        One finding on the def line of each test that only checks that read
        text holds something.
    """
    program = Tests(Index(snapshot))
    rule = item.binding.rule
    return [code_hit(rule, path, line, "", snapshot) for path in item.files if TEST_FILE.search(path) for line in program.flagged(path)]
