import ast
import re

EMPTY = frozenset()
PATH = "P"
TEMP = "M"
HANDLE = "H"
RUN = "G"
CROSS = "X"
PLANTED = "W"
CODE = "C"
NAMED = "N"
LACKS = "L"
PUNCTUATION = "Q"
MARKED = "q"
STRUCT = "S"
KEYED = "K"
SHAPED = "Z"
ORDERED = "O"
PRESENT = "+"
ABSENT = "-"
TEXT = "T@"
ARG = "A:"
TAGS = frozenset({PRESENT, ABSENT})
OTHER = frozenset({RUN})
TEMP_ONLY = frozenset({TEMP})
PATHS = frozenset({PATH})
SELF = ("self", "cls")
TEMP_NAME = re.compile(r"^_?(?:tmp|temp)(?![le])|^td$", re.IGNORECASE)
WRITE_MODE = re.compile(r"[wax+]")
WORD = re.compile(r"\w")
ALNUM = re.compile(r"[^\W_]")
WAIVER = re.compile(r"(?i)nocheck|noqa|nosec|pragma|suppress|lint-ignore|allow")
REGEX_ESCAPE = re.compile(r"\\[\\nrtfvsSdDwWbB]")
RUN_NAME = re.compile(
    r"(?i)(?:^|_)(?:load|loads|parse|literal_eval|fromstring|render|exec|eval|run|popen|spawn|system|check_output|check_call"
    r"|invoke|import_module|dump|dumps|main|compose|compose_all|tokenize|lex|lexer)(?:_|$)"
    r"|^(?:Environment|Template|get_template|from_string|getoutput|IPv4Network|IPv6Network|IPv4Address|IPv6Address)$"
)
ARCHIVES = ("tarfile", "zipfile")
RUN_MODULES = ("subprocess", "importlib", "runpy", "ast", "ipaddress", "tokenize", "yaml", "json", "tomllib", "configparser", "xml")
READER_NAME = re.compile(r"(?i)read|content|text|source|lines")
EVALUATOR_NAME = re.compile(r"(?i)(?:^|_)(?:lex|lexer|tokenize|holds|refused|precedes|follows|evaluate|evaluates)(?:_|$)")
PARSE_NAME = re.compile(r"(?i)(?:^|_)(?:load|loads|load_all|safe_load|safe_load_all|full_load|compose|compose_all|literal_eval|fromstring|dump|dumps|safe_dump|dump_all)(?:_|$)")
KEY_LIKE = re.compile(r"^[A-Za-z_][\w-]*$")
PATH_ATTRS = frozenset({"parent", "parents", "name", "stem", "suffix", "suffixes", "parts"})
MUTATORS = frozenset({"append", "add", "extend", "update", "insert", "setdefault", "appendleft", "remove", "discard", "pop", "clear", "sort", "reverse"})
QUIET = frozenset({"print", "skipTest", "skip", "addCleanup", "info", "debug", "warning", "warn", "error", "log"})
QUIET_RECEIVERS = frozenset({"sys.stdout", "sys.stderr", "logging", "logger", "LOGGER", "log", "warnings"})
RAISES = frozenset({"assertRaises", "assertRaisesRegex", "assertWarns", "assertWarnsRegex", "assertLogs", "assertNoLogs", "raises", "warns"})
FAILURES = frozenset({"AssertionError", "Failed", "AssertionFailedError"})
PLAIN_CONTEXTS = frozenset({"open", "subTest", "TemporaryDirectory", "NamedTemporaryFile", "suppress", "nullcontext"})
EQUALS = ("assertEqual", "assertEquals", "assertListEqual", "assertSetEqual", "assertCountEqual", "assertSequenceEqual", "assertMultiLineEqual")
FORMS = {
    **dict.fromkeys(("assertTrue", "assert_", "failUnless", "assertIsNotNone"), "truth"),
    **dict.fromkeys(("assertFalse", "failIf", "assertIsNone"), "falsity"),
    "assertIn": "member",
    "assertNotIn": "nonmember",
    **dict.fromkeys(("assertRegex", "assertRegexpMatches"), "regex"),
    **dict.fromkeys(("assertNotRegex", "assertNotRegexpMatches"), "nonregex"),
    **dict.fromkeys((*EQUALS, "assertDictEqual", "assertTupleEqual", "assertIs"), "equal"),
    **dict.fromkeys(("assertNotEqual", "assertNotEquals", "assertIsNot"), "unequal"),
    **dict.fromkeys(("assertLess", "assertLessEqual", "assertGreater", "assertGreaterEqual"), "order"),
}
ARITY = {form: 1 if form in ("truth", "falsity") else 2 for form in set(FORMS.values())}
SET_OPERATORS = (ast.Sub, ast.BitAnd, ast.BitXor)
EMPTY_CALLS = ("set", "list", "dict", "tuple", "frozenset")
SEQUENCE_CALLS = frozenset({"len", "sorted", "set", "frozenset", "list", "tuple", "enumerate", "reversed", "min", "max"})
SEQUENCE_NODES = (ast.List, ast.ListComp, ast.Set, ast.SetComp, ast.Tuple)
KEEPS_NAMED = ("compile", "escape", "frozenset", "set", "tuple", "list", "join", "format", "lower", "upper", "strip")


def texts(taint) -> frozenset:
    return frozenset(label for label in taint if label.startswith(TEXT))


def parameters(taint) -> frozenset:
    return frozenset(label for label in taint if label.startswith(ARG))


def flip(taint) -> frozenset:
    """
    Args:
        taint: Taint of a check or condition.

    Returns:
        The taint with its presence tags swapped; LACKS added where it held
        only a literal's presence, so the result states that literal absent,
        and dropped where it stated just that.
    """
    swap = {PRESENT: ABSENT, ABSENT: PRESENT}
    swapped = frozenset(swap)
    found = (taint - swapped) | frozenset(swap[label] for label in taint & swapped)
    if NAMED not in taint:
        return found
    if taint & TAGS == {PRESENT}:
        return found | {LACKS}
    return found - {LACKS} if taint & TAGS == {ABSENT} else found


def call_name(func) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def is_name(node, names) -> bool:
    return isinstance(node, ast.Name) and node.id in names


def empty_literal(node) -> bool:
    if isinstance(node, ast.Constant):
        return node.value in (None, 0, "", b"", False)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
        return not (node.keys if isinstance(node, ast.Dict) else node.elts)
    return isinstance(node, ast.Call) and is_name(node.func, EMPTY_CALLS) and not node.args


def exits(body: list) -> bool:
    return bool(body) and isinstance(body[-1], (ast.Continue, ast.Break, ast.Return, ast.Raise))


def contained(needle, hay) -> frozenset:
    """
    Args:
        needle: Taint of what is looked for.
        hay: Taint of where it is looked for.

    Returns:
        The taint of the presence check: the hay's labels and a presence tag
        when the hay is read text and the needle no path but a parsed leaf,
        MARKED when the needle is only punctuation such as a comment mark,
        CROSS when the needle comes from a read too, and what ran or was
        temporary on either side; a hay that is no read text keeps neither
        the needle's text nor its parameters, as a pattern built from read
        names finds nothing read in a planted fixture.
    """
    if not texts(hay) or (PATH in needle and not (texts(needle) and (STRUCT in needle or texts(needle) - texts(hay)))):
        kept = needle - {PLANTED} - (EMPTY if texts(hay) else texts(needle) | parameters(needle))
        return (hay | kept) - TAGS - {PUNCTUATION, MARKED}
    cross = {CROSS} if texts(needle) else set()
    mark = {MARKED} if needle == {PUNCTUATION} else set()
    return frozenset((hay - TAGS - {NAMED, LACKS, PUNCTUATION, MARKED}) | (needle & {RUN, TEMP, CROSS, CODE, NAMED}) | cross | mark | {PRESENT})


def write_mode(call) -> bool:
    modes = [*call.args[1:2], *(keyword.value for keyword in call.keywords if keyword.arg == "mode")]
    return any(isinstance(mode, ast.Constant) and isinstance(mode.value, str) and WRITE_MODE.search(mode.value) for mode in modes)


def key_like(node) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str) and KEY_LIKE.match(node.value) is not None


def trivial(node) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str) and not WORD.search(REGEX_ESCAPE.sub("", node.value))


def planting(old, new) -> bool:
    """
    Args:
        old: What a replace or substitution looks for.
        new: What it puts in its place.

    Returns:
        True unless both are literals without a letter or digit, as when
        lines are joined, quotes or comment marks dropped or dashes made
        underscores before a check.
    """
    return not all(isinstance(side, ast.Constant) and isinstance(side.value, str) and not ALNUM.search(REGEX_ESCAPE.sub("", side.value)) for side in (old, new))


def bound(node, taint, other) -> bool:
    """
    Args:
        node: One side of an ordering comparison.
        taint: Its taint.
        other: Taint of the other side.

    Returns:
        True where that side is a named limit, as a line count cap, against
        a value from a read; False for a literal, which counts how often a
        text occurs.
    """
    return not taint and bool(other) and isinstance(node, (ast.Name, ast.Attribute))


def scalar_leaf(side, empty) -> bool:
    """
    Args:
        side: What a comparison holds against an empty literal.
        empty: That literal.

    Returns:
        True where the literal is a scalar such as 0, "" or None and the
        side no count, so the comparison checks a value of parsed data.
    """
    counted = isinstance(side, ast.Call) and call_name(side.func) == "len"
    return isinstance(empty, ast.Constant) and not counted


def numeric(node) -> bool:
    if isinstance(node, ast.Constant):
        return isinstance(node.value, int) and not isinstance(node.value, bool)
    return isinstance(node, (ast.BinOp, ast.UnaryOp)) or (isinstance(node, ast.Call) and call_name(node.func) == "index")


def listed_against(node) -> list:
    if not all(isinstance(operator, (ast.Eq, ast.NotEq)) for operator in node.ops):
        return []
    sides = [node.left, *node.comparators]
    lists = [side for side in sides if isinstance(side, (ast.List, ast.ListComp))]
    return [side for side in sides if side not in lists] if lists else []


def sequenced(node) -> list:
    """
    Args:
        node: Any node of a function body.

    Returns:
        The expressions it treats as a sequence: what a loop or
        comprehension iterates, what a sequence builtin such as len or
        sorted takes, what a number indexes, what equals a list literal.
    """
    if isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
        return [node.iter]
    if isinstance(node, ast.Call) and is_name(node.func, SEQUENCE_CALLS):
        return node.args[:1]
    if isinstance(node, ast.Subscript):
        return [node.value] if numeric(node.slice) else []
    return listed_against(node) if isinstance(node, ast.Compare) else []


def sequences(statements: list) -> frozenset:
    return frozenset(ast.unparse(item) for statement in statements for node in ast.walk(statement) for item in sequenced(node))


def waived(node) -> bool:
    """
    Args:
        node: Test of an `if ...: continue`.

    Returns:
        True where it calls a waiver lookup such as `is_suppressed_at`,
        negated or not.
    """
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        node = node.operand
    return isinstance(node, ast.Call) and WAIVER.search(call_name(node.func)) is not None


def comparing(node) -> bool:
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        node = node.operand
    return isinstance(node, ast.Compare)


def failure_name(node) -> bool:
    target = node.func if isinstance(node, ast.Call) else node
    return call_name(target) in FAILURES


def under(func, roots) -> bool:
    while isinstance(func, ast.Attribute):
        func = func.value
    return is_name(func, roots)


def os_path(func) -> bool:
    return isinstance(func, ast.Attribute) and ast.unparse(func.value) in ("os.path", "posixpath", "os")
