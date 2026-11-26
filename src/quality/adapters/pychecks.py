import ast

from quality.adapters.pylabels import (
    ABSENT,
    ARITY,
    CODE,
    CROSS,
    EMPTY,
    FORMS,
    HANDLE,
    LACKS,
    MARKED,
    MUTATORS,
    ORDERED,
    OTHER,
    PATH,
    PLAIN_CONTEXTS,
    PLANTED,
    PRESENT,
    QUIET,
    QUIET_RECEIVERS,
    RAISES,
    RUN,
    SELF,
    SHAPED,
    STRUCT,
    TAGS,
    TEMP,
    call_name,
    comparing,
    contained,
    empty_literal,
    exits,
    failure_name,
    flip,
    is_name,
    texts,
    waived,
)
from quality.adapters.pytaint import Expressions

POSITIVE = "positive"
NEGATIVE = "negative"
NEUTRAL = "neutral"
DIFFERENT = "other"


def classify(check) -> str:
    """
    Args:
        check: Taint of one assertion.

    Returns:
        positive or negative for a presence check on read text, neutral for
        one on paths alone, other for anything else, a check on parsed data
        without a presence tag among it.
    """
    if check & {RUN, TEMP, CROSS, PLANTED, CODE, SHAPED} or (STRUCT in check and not check & TAGS):
        return DIFFERENT
    if texts(check) and PRESENT in check:
        return POSITIVE
    if texts(check) and ABSENT in check:
        return NEGATIVE
    if texts(check) or check & {PATH, HANDLE}:
        return NEUTRAL
    return DIFFERENT


def quiet(func) -> bool:
    return call_name(func) in QUIET or (isinstance(func, ast.Attribute) and ast.unparse(func.value) in QUIET_RECEIVERS)


def producing(condition) -> frozenset:
    """
    Args:
        condition: Taint of an `if` around a finding.

    Returns:
        Its presence tags, SHAPED where it checks parsed data without one,
        as a key or a value, else nothing, also for an order of parsed
        entries, which ranks what holds a text.
    """
    if condition & TAGS:
        return condition & TAGS
    return frozenset({SHAPED}) if STRUCT in condition and ORDERED not in condition else EMPTY


def still_lacking(lacking: bool, condition, tags) -> bool:
    """
    Args:
        lacking: Whether an outer skipped-past condition kept only lines
            lacking a literal.
        condition: Taint of the next condition inward.
        tags: Its presence tags.

    Returns:
        True where this condition keeps only lines lacking a literal, False
        where it keeps only lines holding a text after such an exemption,
        else the outer state.
    """
    if LACKS in condition and tags == {ABSENT}:
        return True
    return False if tags == {PRESENT} else lacking


def skip_condition(kept, waiver: bool) -> tuple:
    """
    Args:
        kept: Taint of what an `if ...: continue` lets pass.
        waiver: Whether its test is a waiver lookup.

    Returns:
        The skipped-past condition, without presence tags where it drops
        lines by punctuation such as a comment mark, or drops waived ones,
        neither of which states the checked text.
    """
    return (kept - TAGS if MARKED in kept or waiver else kept, False)


def skipped_tag(skipped: list) -> frozenset:
    if not skipped:
        return EMPTY
    return frozenset({PRESENT}) if any(PRESENT in tags for tags in skipped) else skipped[-1]


class Analyzer(Expressions):
    """
    Args:
        program: Resolves calls, module constants and class attributes.
        scope: Module, class and call depth of the analysed body.
        env: Local name to taint, seeded with parameters and constants.
        attrs: Attribute of self or cls to taint.
    """

    def __init__(self, program, scope, env: dict, attrs: dict):
        self.program = program
        self.scope = scope
        self.env = env
        self.attrs = attrs
        self.own = {}
        self.local = {}
        self.ret = frozenset()
        self.plain = frozenset()
        self.checks = []
        self.acts = False
        self.cut = False
        self.conds = []
        self.root = None
        self.listed = None

    def record(self, check) -> None:
        self.checks.append(frozenset(check))

    def implicit(self) -> frozenset:
        """
        Returns:
            The labels of every enclosing condition but what ran in it, and
            one presence tag: that of the innermost enclosing `if` with one,
            SHAPED where that `if` checks parsed data instead, else ABSENT
            when a skipped-past `if ...: continue` kept only lines lacking a
            literal, else PRESENT when one kept only lines holding a text,
            else the tag of the innermost skipped-past one.
        """
        labels, direct, skipped, lacking = set(), EMPTY, [], False
        for condition, enclosing in self.conds:
            labels |= condition - TAGS - {CODE, MARKED, SHAPED, ORDERED}
            tags = condition & TAGS
            lacking = still_lacking(lacking, condition, tags)
            made = producing(condition) if enclosing else EMPTY
            if made:
                direct = made
            elif tags:
                skipped.append(tags)
        return frozenset(labels | (direct or (frozenset({ABSENT}) if lacking else skipped_tag(skipped))))

    def guarded(self, taint) -> frozenset:
        """
        Args:
            taint: Taint of a value stored under the current conditions.

        Returns:
            The taint with the presence tag of the innermost condition that
            has one in place of the value's own tags.
        """
        condition = self.implicit()
        return (taint - TAGS if condition & TAGS else taint) | condition

    def assigned(self, value) -> frozenset:
        """
        Args:
            value: What an assignment stores.

        Returns:
            Its guarded taint; a comparison keeps its own tag past
            skipped-past filters alone, which only scope the lines it
            checks.
        """
        found = self.taint(value)
        if not comparing(value) or any(enclosing and producing(test) for test, enclosing in self.conds):
            return self.guarded(found)
        return found | (self.implicit() - TAGS)

    def bind(self, target, taint) -> None:
        if isinstance(target, ast.Name):
            self.env[target.id] = self.env.get(target.id, frozenset()) | taint
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self.bind(element, taint)
        elif isinstance(target, ast.Attribute) and is_name(target.value, SELF):
            self.own[target.attr] = self.own.get(target.attr, frozenset()) | taint
        elif isinstance(target, (ast.Starred, ast.Attribute, ast.Subscript)):
            self.bind(target.value, taint)

    def block(self, statements: list) -> None:
        self.root = statements if self.root is None else self.root
        depth = len(self.conds)
        for statement in statements:
            handler = getattr(self, f"stmt_{type(statement).__name__}", None)
            if handler is not None:
                handler(statement)
            if isinstance(statement, ast.If) and not statement.orelse and exits(statement.body):
                self.conds.append(skip_condition(flip(self.taint(statement.test)), waived(statement.test)))
        del self.conds[depth:]

    def stmt_Assign(self, node):
        found = self.assigned(node.value)
        for target in node.targets:
            self.bind(target, found)

    def stmt_AnnAssign(self, node):
        if node.value is not None:
            self.bind(node.target, self.assigned(node.value))

    def stmt_AugAssign(self, node):
        self.bind(node.target, self.guarded(self.taint(node.value)))

    def stmt_For(self, node):
        source = self.taint(node.iter)
        if HANDLE in source and TEMP not in source:
            self.bind(node.target, (source - {HANDLE}) | self.text_label(node.iter))
        else:
            self.iterate(node.target, node.iter)
        self.block(node.body)
        self.block(node.orelse)

    stmt_AsyncFor = stmt_For

    def stmt_While(self, node):
        self.conds.append((self.taint(node.test), True))
        self.block(node.body)
        self.conds.pop()
        self.block(node.orelse)

    def stmt_If(self, node):
        test = self.taint(node.test)
        for condition, body in ((test, node.body), (flip(test), node.orelse)):
            self.conds.append((condition, True))
            self.block(body)
            self.conds.pop()

    def stmt_With(self, node):
        for item in node.items:
            self.context(item)
        self.block(node.body)

    stmt_AsyncWith = stmt_With

    def context(self, item) -> None:
        expression = item.context_expr
        name = call_name(expression.func) if isinstance(expression, ast.Call) else ""
        if name in RAISES:
            self.record(OTHER)
        elif isinstance(expression, ast.Call) and name not in PLAIN_CONTEXTS:
            self.acts = True
        found = self.taint(expression)
        if item.optional_vars is not None:
            self.bind(item.optional_vars, found)

    def stmt_Try(self, node):
        self.block(node.body)
        for handler in node.handlers:
            self.block(handler.body)
        self.block(node.orelse)
        self.block(node.finalbody)

    stmt_TryStar = stmt_Try

    def stmt_Match(self, node):
        self.taint(node.subject)
        for case in node.cases:
            self.block(case.body)

    def stmt_Assert(self, node):
        self.record(self.taint(node.test))

    def stmt_Raise(self, node):
        if node.exc is not None and failure_name(node.exc) and self.conds:
            self.record(self.failure())

    def stmt_Return(self, node):
        found = self.taint(node.value)
        self.plain |= found
        self.ret |= self.guarded(found)

    def stmt_FunctionDef(self, node):
        inner = Analyzer(self.program, self.scope, dict(self.env), self.attrs)
        inner.block(node.body)
        self.local[node.name] = inner

    stmt_AsyncFunctionDef = stmt_FunctionDef

    def stmt_Expr(self, node):
        value = node.value.value if isinstance(node.value, ast.Await) else node.value
        if isinstance(value, ast.Call):
            self.statement_call(value)
        else:
            self.taint(value)

    def statement_call(self, call) -> None:
        if self.assertion(call):
            return
        func = call.func
        if isinstance(func, ast.Attribute) and func.attr in MUTATORS:
            self.bind(func.value, self.guarded(self.arguments(call)))
        elif quiet(func):
            self.arguments(call)
        elif isinstance(func, ast.Name) and func.id in self.local:
            self.local_call(call)
            self.acts = self.acts or self.local[func.id].acts or not self.local[func.id].checks
        else:
            self.discarded(call)

    def discarded(self, call) -> None:
        target = self.program.resolve(self, call)
        if target is None:
            self.taint(call)
            self.acts = True
        else:
            self.program.invoke(self, call, target, True)

    def failure(self) -> frozenset:
        return flip(self.implicit()) if self.conds else OTHER

    def assertion(self, call) -> bool:
        func = call.func
        if not isinstance(func, ast.Attribute):
            return False
        name = func.attr
        if is_name(func.value, ("pytest",)) and name == "fail":
            self.record(self.failure())
        elif name in RAISES:
            self.record(OTHER)
        elif not name.startswith(("assert", "fail")):
            return False
        else:
            self.record(self.form(name, call) if is_name(func.value, SELF) else OTHER)
        return True

    def form(self, name: str, call) -> frozenset:
        if name == "fail":
            return self.failure()
        form = FORMS.get(name)
        if form is None or len(call.args) < ARITY[form]:
            return self.arguments(call) - TAGS
        return getattr(self, f"form_{form}")(call.args)

    def form_truth(self, args):
        return self.taint(args[0])

    def form_falsity(self, args):
        return flip(self.taint(args[0]))

    def form_member(self, args):
        return self.member(args[0], args[1])

    def form_nonmember(self, args):
        return flip(self.form_member(args))

    def form_regex(self, args):
        return contained(self.taint(args[1]), self.taint(args[0]))

    def form_nonregex(self, args):
        return flip(self.form_regex(args))

    def form_equal(self, args):
        return self.comparison(args[0], ast.Eq(), args[1])

    def form_unequal(self, args):
        return self.comparison(args[0], ast.NotEq(), args[1])

    def form_order(self, args):
        if empty_literal(args[1]):
            return self.taint(args[0])
        return self.order(args[0], args[1], False)
