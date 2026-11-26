import ast
import sys
from dataclasses import dataclass

from quality.adapters.pychecks import Analyzer
from quality.adapters.pylabels import (
    ARG,
    CODE,
    CROSS,
    EMPTY,
    EVALUATOR_NAME,
    HANDLE,
    KEYED,
    NAMED,
    ORDERED,
    OTHER,
    PARSE_NAME,
    PATH,
    READER_NAME,
    RUN,
    RUN_NAME,
    SELF,
    SHAPED,
    STRUCT,
    TAGS,
    TEMP,
    TEXT,
    call_name,
    texts,
)
from quality.adapters.pymodules import Index, Module

DEPTH = 5
ABSTRACT = frozenset({PATH, TEMP, HANDLE, RUN, STRUCT})
ARG_TEXT = f"{TEXT}~"
SETUPS = ("setUp", "setUpClass", "setup_method", "setup_class", "asyncSetUp", "__init__")
PROPERTIES = ("property", "cached_property")


@dataclass(frozen=True)
class Scope:
    """
    Args:
        module: Module of the analysed body.
        cls: Class whose method it is, or None.
        depth: Calls between the test and this body.
    """

    module: Module
    cls: object
    depth: int


@dataclass(frozen=True)
class Summary:
    """
    Args:
        ret: Taint of what the function returns, ARG labels standing for
            its parameters.
        plain: The presence tags of the returned expressions themselves,
            without those of the conditions around the return.
        checks: Taint of each assertion it makes.
        acts: True where it runs, writes or patches anything.
        test: True where it lives in a test module.
        cut: True where a call below it went past the depth bound, so the
            summary is not kept.
    """

    ret: frozenset
    plain: frozenset
    checks: tuple
    acts: bool
    test: bool
    cut: bool


BLANK = Summary(EMPTY, EMPTY, (), False, False, False)
CUT = Summary(EMPTY, EMPTY, (), False, False, True)


def parameters(function) -> list:
    arguments = function.args
    names = [item.arg for item in [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]]
    return names + [item.arg for item in (arguments.vararg, arguments.kwarg) if item is not None]


def substitute(taint, actual: dict, site: str) -> frozenset:
    """
    Args:
        taint: Taint inside a callee.
        actual: Parameter name to the taint of its argument at the call.
        site: Label for what the callee read itself.

    Returns:
        The taint at the call site.
    """
    found = set()
    for label in taint:
        if label.startswith(ARG):
            found |= actual.get(label[len(ARG) :], frozenset())
        elif label != ARG_TEXT:
            found.add(site if label.startswith(TEXT) else label)
    return frozenset(found)


def abstract(taint) -> frozenset:
    return (taint & ABSTRACT) | (frozenset({ARG_TEXT}) if texts(taint) else EMPTY)


def acted(summary: Summary, statement: bool) -> bool:
    if summary.test:
        return summary.acts or (statement and not summary.checks)
    return statement


def loaded(found, label: str) -> frozenset | None:
    """
    Args:
        found: Taint a production loader returns at the call site.
        label: Text label for the call.

    Returns:
        The read text it loads with STRUCT added, the call's own label where
        it loads a path or what a helper of its own made, or None where it
        loads neither.
    """
    if texts(found):
        return (found - TAGS - {CROSS}) | {STRUCT}
    return (found - TAGS - {CROSS, CODE}) | {STRUCT, label} if found & {PATH, CODE} else None


def returned(found, summary: Summary, name: str, label: str) -> frozenset:
    """
    Args:
        found: Taint of the callee's return at the call site.
        summary: The callee's summary.
        name: The callee's name.
        label: Text label for the call.

    Returns:
        The taint of the call's value: RUN added where a test helper lexes or
        evaluates a condition or an order, or production code runs, STRUCT
        where production code loads read text or a file, without the shape
        of its own conditions, the text replaced by CODE where production
        code not named for reading made it, since a check on it tests that
        code.
    """
    if summary.test:
        return found | (OTHER if EVALUATOR_NAME.search(name) else EMPTY)
    found = found - {NAMED, KEYED, SHAPED, ORDERED}
    load = loaded(found, label) if PARSE_NAME.search(name) else None
    if load is not None:
        return load
    named = OTHER if RUN_NAME.search(name) else EMPTY
    if texts(found) and not READER_NAME.search(name):
        return (found - texts(found) - TAGS - {CROSS}) | {CODE} | named
    return (found - TAGS - {CROSS}) | (summary.plain if texts(found) else EMPTY) | named


class Program:
    """
    Args:
        index: Parsed Python modules of the snapshot.
    """

    def __init__(self, index: Index):
        self.index = index
        self.summaries = {}
        self.envs = {}
        self.attributes = {}
        self.globals = {}

    def module_env(self, module: Module) -> dict:
        if module.path not in self.envs:
            self.envs[module.path] = {}
            analyzer = Analyzer(self, Scope(module, None, 0), self.envs[module.path], {})
            for node in module.assignments:
                analyzer.stmt_Assign(node) if isinstance(node, ast.Assign) else analyzer.stmt_AnnAssign(node)
        return self.envs[module.path]

    def global_taint(self, module: Module, name: str) -> frozenset:
        key = (module.path, name)
        if key not in self.globals:
            self.globals[key] = EMPTY
            self.globals[key] = self.resolved_global(module, name)
        return self.globals[key]

    def resolved_global(self, module: Module, name: str) -> frozenset:
        env = self.module_env(module)
        if name in env:
            return env[name]
        found = self.index.lookup(module, name, 0)
        if found is None or found[0] != "constant":
            return EMPTY
        return self.global_taint(found[1], name)

    def member_taint(self, module: Module, owner: str, attr: str) -> frozenset | None:
        found = self.index.lookup(module, owner, 0)
        if found is None or found[0] != "module":
            return None
        return self.global_taint(found[1], attr)

    def foreign(self, module: Module, name: str) -> bool:
        """
        Args:
            module: Module the name is used in.
            name: A top-level name of it.

        Returns:
            True where the name is an imported module of the code under test:
            one of the snapshot that is no test module, or a third-party one.
        """
        if name not in module.imports:
            return False
        found = self.index.lookup(module, name, 0)
        if found is None:
            return module.imports[name][0].split(".")[0] not in sys.stdlib_module_names
        return found[0] == "module" and not found[1].test

    def class_attrs(self, module: Module, cls) -> dict:
        key = (module.path, cls.name)
        if key not in self.attributes:
            self.attributes[key] = {}
            self.attributes[key] = self.collect_attrs(module, cls)
        return self.attributes[key]

    def collect_attrs(self, module: Module, cls) -> dict:
        attrs = {}
        for base_module, base in self.bases(module, cls):
            attrs.update(self.class_attrs(base_module, base))
        scope = Scope(module, cls, 0)
        body = Analyzer(self, scope, dict(self.module_env(module)), attrs)
        body.block([node for node in cls.body if isinstance(node, (ast.Assign, ast.AnnAssign))])
        attrs.update({name: taint for name, taint in body.env.items() if name not in self.module_env(module)})
        for node in cls.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.method_attrs(scope, node, attrs)
        return attrs

    def method_attrs(self, scope: Scope, node, attrs: dict) -> None:
        decorators = {call_name(item) for item in node.decorator_list}
        if node.name not in SETUPS and not node.name.startswith("setUp") and not decorators & {"fixture", *PROPERTIES}:
            return
        analyzer = Analyzer(self, scope, dict(self.module_env(scope.module)), attrs)
        analyzer.block(node.body)
        for name, taint in analyzer.own.items():
            attrs[name] = attrs.get(name, frozenset()) | taint
        if decorators & set(PROPERTIES):
            attrs[node.name] = attrs.get(node.name, frozenset()) | analyzer.ret

    def bases(self, module: Module, cls) -> list:
        found = []
        for base in cls.bases:
            name = base.id if isinstance(base, ast.Name) else call_name(base)
            target = self.index.lookup(module, name, 0) if name else None
            if target is not None and target[0] == "class" and target[2] is not cls:
                found.append((target[1], target[2]))
        return found

    def method(self, module: Module, cls, name: str, depth: int) -> tuple | None:
        for node in cls.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
                return (Scope(module, cls, depth + 1), node, True)
        for base_module, base in self.bases(module, cls):
            found = self.method(base_module, base, name, depth)
            if found is not None:
                return found
        return None

    def resolve(self, analyzer, call) -> tuple | None:
        """
        Args:
            analyzer: Analyzer of the calling body.
            call: The call.

        Returns:
            (scope, function, is_method) for a function or method of the
            snapshot, ("class", module, node) for a class, or None.
        """
        func, scope = call.func, analyzer.scope
        if isinstance(func, ast.Name):
            return self.target(self.index.lookup(scope.module, func.id, 0), scope.depth)
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            return self.attribute_target(analyzer, func.value.id, func.attr)
        return None

    def attribute_target(self, analyzer, owner: str, attr: str) -> tuple | None:
        scope = analyzer.scope
        if owner in SELF and scope.cls is not None:
            return self.method(scope.module, scope.cls, attr, scope.depth)
        if owner in analyzer.env:
            return None
        found = self.index.lookup(scope.module, owner, 0)
        if found is not None and found[0] == "module":
            return self.target(self.index.lookup(found[1], attr, 0), scope.depth)
        if found is not None and found[0] == "class":
            return self.method(found[1], found[2], attr, scope.depth)
        return None

    def target(self, found, depth: int) -> tuple | None:
        if found is None:
            return None
        if found[0] == "function":
            return (Scope(found[1], None, depth + 1), found[2], False)
        return found if found[0] == "class" else None

    def invoke(self, analyzer, call, target, statement: bool) -> frozenset:
        """
        Args:
            analyzer: Analyzer of the calling body; it takes the callee's
                assertions and acts.
            call: The call.
            target: What resolve() returned for it.
            statement: True where the call's value is discarded.

        Returns:
            The taint of the call's value.
        """
        if target[0] == "class":
            analyzer.acts = analyzer.acts or statement
            return analyzer.arguments(call) if target[1].test else OTHER
        scope, function, is_method = target
        actual = self.arguments(analyzer, call, function, is_method)
        summary = self.summary(scope, function, tuple(sorted((name, abstract(taint)) for name, taint in actual.items())))
        first = ast.unparse(call.args[0]) if call.args else ""
        label = f"{TEXT}{scope.module.path}:{function.name}({first})"
        analyzer.cut = analyzer.cut or summary.cut
        if summary.test:
            analyzer.checks += [substitute(check, actual, label) for check in summary.checks]
        analyzer.acts = analyzer.acts or acted(summary, statement)
        return returned(substitute(summary.ret, actual, label), summary, function.name, label)

    def arguments(self, analyzer, call, function, is_method: bool) -> dict:
        names = parameters(function)
        if is_method and names and names[0] in SELF:
            names = names[1:]
        actual = {}
        for position, argument in enumerate(call.args):
            if position < len(names) and not isinstance(argument, ast.Starred):
                actual[names[position]] = analyzer.taint(argument)
        for keyword in call.keywords:
            if keyword.arg is not None:
                actual[keyword.arg] = analyzer.taint(keyword.value)
        return actual

    def summary(self, scope: Scope, function, signature: tuple) -> Summary:
        key = (scope.module.path, getattr(scope.cls, "name", None), function.name, function.lineno, signature)
        if key in self.summaries:
            return self.summaries[key]
        if scope.depth > DEPTH:
            return CUT
        self.summaries[key] = BLANK
        summary = self.analysed(scope, function, dict(signature))
        if summary.cut:
            del self.summaries[key]
        else:
            self.summaries[key] = summary
        return summary

    def analysed(self, scope: Scope, function, signature: dict) -> Summary:
        env = dict(self.module_env(scope.module))
        env.update({name: frozenset({f"{ARG}{name}"}) | signature.get(name, frozenset()) for name in parameters(function)})
        attrs = self.class_attrs(scope.module, scope.cls) if scope.cls is not None else {}
        analyzer = Analyzer(self, scope, env, attrs)
        analyzer.block(function.body)
        return Summary(analyzer.ret, analyzer.plain & TAGS, tuple(analyzer.checks), analyzer.acts, scope.module.test, analyzer.cut)
