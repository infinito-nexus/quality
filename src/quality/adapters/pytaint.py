import ast

from quality.adapters.pycalls import Calls
from quality.adapters.pylabels import (
    CROSS,
    EMPTY,
    KEYED,
    NAMED,
    ORDERED,
    OTHER,
    PATH,
    PATH_ATTRS,
    PATHS,
    PLANTED,
    PRESENT,
    PUNCTUATION,
    SELF,
    SEQUENCE_NODES,
    SET_OPERATORS,
    STRUCT,
    TAGS,
    TEMP,
    TEMP_NAME,
    TEMP_ONLY,
    TEXT,
    WAIVER,
    bound,
    contained,
    empty_literal,
    flip,
    is_name,
    key_like,
    scalar_leaf,
    sequences,
    texts,
    trivial,
    waived,
)


def crossed(first, second) -> frozenset:
    return frozenset({CROSS}) if texts(first) and texts(second) and not texts(first) & texts(second) else EMPTY


def worded(items: list) -> bool:
    return any((isinstance(item, ast.Constant) and isinstance(item.value, str) and not trivial(item)) or (isinstance(item, ast.JoinedStr) and worded(item.values)) for item in items)


def mixed(base, literal: bool) -> frozenset:
    """
    Args:
        base: Taint of what an f-string starts with, or a list or dict
            literal unpacks.
        literal: Whether a literal with a word stands beside it: for an
            f-string one ending a line, since a message names a line
            without one, or a constant of the code beside such a line.

    Returns:
        PLANTED where read text as it was read, with no presence tag as a
        list of findings has, gets a literal with a word added, as when a
        test appends a line to a read file before it checks it.
    """
    return frozenset({PLANTED}) if literal and texts(base) and not base & TAGS else EMPTY


class Expressions(Calls):
    def taint(self, node) -> frozenset:
        handler = getattr(self, f"expr_{type(node).__name__}", None)
        return EMPTY if handler is None or node is None else frozenset(handler(node))

    def union(self, nodes) -> frozenset:
        return frozenset().union(*(self.taint(node) for node in nodes))

    def text_label(self, node) -> frozenset:
        return frozenset({f"{TEXT}{self.scope.module.path}:{node.lineno}:{node.col_offset}"})

    def expr_Name(self, node):
        if node.id == "__file__":
            return PATHS
        found = self.env.get(node.id)
        if found is None:
            found = self.program.global_taint(self.scope.module, node.id)
        return found | (TEMP_ONLY if TEMP_NAME.match(node.id) else EMPTY)

    def expr_Attribute(self, node):
        temp = TEMP_ONLY if TEMP_NAME.match(node.attr) else EMPTY
        if is_name(node.value, SELF):
            return self.own.get(node.attr, frozenset()) | self.attrs.get(node.attr, frozenset()) | temp
        if isinstance(node.value, ast.Name) and node.value.id not in self.env:
            member = self.program.member_taint(self.scope.module, node.value.id, node.attr)
            if member is not None:
                return member
        base = self.taint(node.value)
        if node.attr in PATH_ATTRS and base & {PATH, TEMP}:
            return PATHS | (base & TEMP_ONLY)
        return base

    def expr_BinOp(self, node):
        left, right = self.taint(node.left), self.taint(node.right)
        joined = crossed(left, right) if isinstance(node.op, SET_OPERATORS) else EMPTY
        return left | right | joined | self.planted(node, left, right)

    def planted(self, node, left, right) -> frozenset:
        if not isinstance(node.op, ast.Add) or bool(texts(left)) == bool(texts(right)):
            return EMPTY
        other = node.right if texts(left) else node.left
        number = isinstance(other, ast.Constant) and not isinstance(other.value, str)
        return EMPTY if number or trivial(other) else frozenset({PLANTED})

    def expr_Constant(self, node):
        if not isinstance(node.value, str) or not node.value:
            return EMPTY
        if trivial(node):
            return frozenset({PUNCTUATION})
        if WAIVER.search(node.value):
            return EMPTY
        return frozenset({NAMED, KEYED}) if key_like(node) else frozenset({NAMED})

    def expr_BoolOp(self, node):
        exempting = not all(waived(value) for value in node.values)
        return frozenset().union(*(self.taint(value) - (TAGS if exempting and waived(value) else EMPTY) for value in node.values))

    def expr_UnaryOp(self, node):
        inner = self.taint(node.operand)
        return flip(inner) if isinstance(node.op, ast.Not) else inner

    def expr_IfExp(self, node):
        return self.union((node.test, node.body, node.orelse))

    def expr_JoinedStr(self, node):
        first = node.values[0] if node.values else None
        base = self.taint(first.value) if isinstance(first, ast.FormattedValue) else EMPTY
        lines = [item for item in node.values[1:] if isinstance(item, ast.Constant) and "\n" in str(item.value)]
        named = any(lines and isinstance(item, ast.FormattedValue) and self.named(item.value) for item in node.values[1:])
        return (self.union(node.values) - {PUNCTUATION}) | mixed(base, worded(lines) or named)

    def named(self, node) -> bool:
        found = self.taint(node)
        return NAMED in found and not texts(found)

    def expr_FormattedValue(self, node):
        return self.taint(node.value)

    def expr_Subscript(self, node):
        return self.taint(node.value)

    def expr_Starred(self, node):
        return self.taint(node.value)

    def expr_Await(self, node):
        return self.taint(node.value)

    def expr_Tuple(self, node):
        return self.union(node.elts)

    expr_Set = expr_Tuple

    def expr_List(self, node):
        base = self.union([item for item in node.elts if isinstance(item, ast.Starred)])
        return self.union(node.elts) | mixed(base, worded(node.elts))

    def expr_Dict(self, node):
        base = self.union([value for key, value in zip(node.keys, node.values) if key is None])
        return self.union([*node.keys, *node.values]) | mixed(base, worded(node.values))

    def expr_NamedExpr(self, node):
        found = self.taint(node.value)
        self.bind(node.target, found)
        return found

    def expr_Yield(self, node):
        self.ret |= self.taint(node.value)
        return EMPTY

    expr_YieldFrom = expr_Yield

    def expr_Compare(self, node):
        if len(node.ops) != 1:
            return self.order(node.left, node.comparators[-1], False)
        left, operator, right = node.left, node.ops[0], node.comparators[0]
        if isinstance(operator, (ast.In, ast.NotIn)):
            found = self.member(left, right)
            return flip(found) if isinstance(operator, ast.NotIn) else found
        return self.comparison(left, operator, right)

    def member(self, needle, hay) -> frozenset:
        """
        Args:
            needle: What is looked for.
            hay: Where it is looked for.

        Returns:
            The taint of the containment; no presence tag where a key-like
            literal is looked for in parsed data, which checks a key, or
            where the parsed data is a sequence, whose element is compared.
        """
        looked = self.taint(needle)
        found = contained(looked, self.taint(hay))
        keyed = KEYED in looked and not texts(looked)
        return found - TAGS if STRUCT in found and (keyed or self.sequence(hay)) else found

    def sequence(self, node) -> bool:
        if self.listed is None:
            self.listed = sequences(self.root or [])
        return isinstance(node, SEQUENCE_NODES) or ast.unparse(node) in self.listed

    def comparison(self, left, operator, right) -> frozenset:
        if empty_literal(right) or empty_literal(left):
            side, empty = (left, right) if empty_literal(right) else (right, left)
            value = self.taint(side)
            if STRUCT in value and scalar_leaf(side, empty):
                return value - TAGS
            return flip(value) if isinstance(operator, (ast.Eq, ast.Is, ast.LtE, ast.Lt)) else value
        negated = isinstance(operator, (ast.NotEq, ast.IsNot))
        found = self.order(left, right, negated or isinstance(operator, (ast.Eq, ast.Is)))
        return flip(found) if negated else found

    def order(self, left, right, equality: bool) -> frozenset:
        """
        Args:
            left: One side of the comparison.
            right: The other side.
            equality: True for == and !=, which state what the text holds.

        Returns:
            The taint of both sides, CROSS where they come from different
            reads or the other side is data of the code, and a presence tag
            for an equality on read text; none for one on parsed data, which
            checks the structure.
        """
        first, second = self.taint(left), self.taint(right)
        found = first | second | ({STRUCT} if self.stringified(left) or self.stringified(right) else EMPTY)
        if STRUCT in found and not equality:
            return found - TAGS | {ORDERED}
        if STRUCT in found or (not equality and (bound(left, first, second) or bound(right, second, first))):
            return found - TAGS
        if not texts(found):
            return found
        return frozenset(found | crossed(first, second) | self.one_sided(((left, first), (right, second)), equality, found))

    def stringified(self, node) -> bool:
        """
        Args:
            node: One side of a comparison.

        Returns:
            True where it turns parsed data into a string, as
            `str(sso.get('flavor') or '').strip()`, so the comparison checks
            that value, not a text.
        """
        return any(isinstance(item, ast.Call) and is_name(item.func, ("str",)) and item.args and STRUCT in self.taint(item.args[0]) for item in ast.walk(node))

    def one_sided(self, sides, equality: bool, found) -> frozenset:
        """
        Args:
            sides: Each side of a comparison on read text with its taint.
            equality: True for == and !=.
            found: Taint of both sides.

        Returns:
            Nothing where both sides are read text, else OTHER where the
            other side is data of the code, and a presence tag for an
            equality without one.
        """
        (left, first), (right, second) = sides
        if texts(first) and texts(second):
            return EMPTY
        code = OTHER if self.code_data(right if texts(first) else left) else EMPTY
        return code | (frozenset({PRESENT}) if equality and not found & TAGS else EMPTY)

    def code_data(self, node) -> bool:
        return any(
            isinstance(item, ast.Attribute) and isinstance(item.value, ast.Name) and self.program.foreign(self.scope.module, item.value.id)
            for item in ast.walk(node)
        )

    def comprehension(self, node, elements) -> frozenset:
        saved = dict(self.env)
        labels, tags = set(), EMPTY
        for generator in node.generators:
            labels |= self.taint(generator.iter) - TAGS
            self.iterate(generator.target, generator.iter)
            for condition in generator.ifs:
                found = self.taint(condition)
                labels |= found - TAGS
                tags = found & TAGS or tags
        found = self.union(elements)
        self.env = saved
        return frozenset(labels | found | tags)

    def expr_ListComp(self, node):
        return self.comprehension(node, [node.elt])

    expr_SetComp = expr_ListComp
    expr_GeneratorExp = expr_ListComp

    def expr_DictComp(self, node):
        return self.comprehension(node, [node.key, node.value])

    def expr_Call(self, node):
        if isinstance(node.func, ast.Name) and node.func.id in self.local:
            return self.local_call(node)
        target = self.program.resolve(self, node)
        if target is not None:
            return self.program.invoke(self, node, target, False)
        return self.builtin(node)

    def local_call(self, node) -> frozenset:
        inner = self.local[node.func.id]
        self.checks += inner.checks
        return inner.ret | self.arguments(node)
