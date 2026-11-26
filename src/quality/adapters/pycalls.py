import ast

from quality.adapters.pylabels import (
    ARCHIVES,
    EMPTY,
    HANDLE,
    KEEPS_NAMED,
    KEYED,
    NAMED,
    OTHER,
    PARSE_NAME,
    PATH,
    PATHS,
    PLANTED,
    PUNCTUATION,
    RUN_MODULES,
    RUN_NAME,
    STRUCT,
    TAGS,
    TEMP,
    TEMP_ONLY,
    call_name,
    contained,
    is_name,
    os_path,
    planting,
    texts,
    under,
    write_mode,
)


class Calls:
    def arguments(self, node) -> frozenset:
        return self.union([*node.args, *(keyword.value for keyword in node.keywords)])

    def passthrough(self, node) -> frozenset:
        receiver = self.taint(node.func.value) if isinstance(node.func, ast.Attribute) else EMPTY
        found = receiver | self.arguments(node)
        stringified = {STRUCT} if is_name(node.func, ("str",)) else set()
        return (found if call_name(node.func) in KEEPS_NAMED else found - {NAMED, KEYED}) - {PUNCTUATION} - stringified

    def receiver(self, node) -> frozenset:
        if isinstance(node.func, ast.Attribute):
            return self.taint(node.func.value)
        return self.taint(node.args[0]) if node.args else EMPTY

    def builtin(self, node) -> frozenset:
        name = call_name(node.func)
        handler = getattr(self, f"call_{name}", None)
        found = None if handler is None else handler(node)
        if found is not None:
            return found
        if os_path(node.func):
            return PATHS | (self.arguments(node) & TEMP_ONLY)
        parsed = self.parsed(node) if PARSE_NAME.search(name) else None
        if parsed is not None:
            return parsed
        if RUN_NAME.search(name) or under(node.func, RUN_MODULES):
            self.arguments(node)
            self.acts = True
            return OTHER
        return self.passthrough(node)

    def parsed(self, node) -> frozenset | None:
        """
        Returns:
            The read text the call parses with STRUCT added, since a check on
            a string it holds is still one on that text, or None where it
            parses no read text.
        """
        source = self.arguments(node)
        if TEMP in source:
            return None
        if HANDLE in source:
            return self.text_label(node) | {STRUCT}
        return (source - TAGS - {NAMED, PUNCTUATION}) | {STRUCT} if texts(source) else None

    def iterate(self, target, source) -> None:
        """
        Args:
            target: Loop or comprehension target.
            source: Iterated expression; the counter of an enumerate() takes
                no taint, its items take that of the enumerated value.
        """
        counted = isinstance(source, ast.Call) and is_name(source.func, ("enumerate",)) and source.args
        if counted and isinstance(target, ast.Tuple) and len(target.elts) == 2:
            self.bind(target.elts[1], self.taint(source.args[0]))
            return
        self.bind(target, self.taint(source))

    def call_range(self, node):
        self.arguments(node)
        return EMPTY

    def call_replace(self, node):
        if not isinstance(node.func, ast.Attribute) or len(node.args) < 2:
            return None
        found = self.passthrough(node)
        return found | {PLANTED} if texts(found) and planting(node.args[0], node.args[1]) else found

    def call_sub(self, node):
        if not is_name(getattr(node.func, "value", None), ("re", "regex")) or len(node.args) < 3:
            return None
        found = self.passthrough(node)
        return found | {PLANTED} if texts(found) and planting(node.args[0], node.args[1]) else found

    call_subn = call_sub

    def call_read_text(self, node):
        source = self.receiver(node) | self.arguments(node)
        if TEMP in source:
            return TEMP_ONLY
        if isinstance(node.func, ast.Attribute) and not source & {PATH, HANDLE}:
            return source - TAGS
        return self.text_label(node)

    call_read_bytes = call_read_text
    call_getsource = call_read_text
    call_getsourcelines = call_read_text

    def call_read(self, node):
        source = self.receiver(node)
        if TEMP in source:
            return TEMP_ONLY
        return self.text_label(node) if HANDLE in source else None

    call_readlines = call_read
    call_readline = call_read

    def call_open(self, node):
        if write_mode(node):
            self.acts = True
            return EMPTY
        if under(node.func, ARCHIVES):
            return PATHS | (self.arguments(node) & TEMP_ONLY)
        return frozenset({HANDLE}) | ((self.receiver(node) | self.arguments(node)) & TEMP_ONLY)

    def call_Path(self, node):
        return PATHS | ((self.receiver(node) | self.arguments(node)) & TEMP_ONLY)

    call_PurePath = call_Path
    call_PosixPath = call_Path
    call_PurePosixPath = call_Path
    call_glob = call_Path
    call_iglob = call_Path
    call_rglob = call_Path
    call_iterdir = call_Path
    call_walk = call_Path
    call_listdir = call_Path
    call_scandir = call_Path
    call_resolve = call_Path
    call_joinpath = call_Path
    call_with_suffix = call_Path
    call_with_name = call_Path
    call_with_stem = call_Path
    call_relative_to = call_Path
    call_absolute = call_Path
    call_expanduser = call_Path
    call_exists = call_Path
    call_is_file = call_Path
    call_is_dir = call_Path

    def call_isinstance(self, node):
        self.arguments(node)
        return EMPTY

    def call_deepcopy(self, node):
        found = self.arguments(node)
        return found | (frozenset({PLANTED}) if texts(found) else EMPTY)

    def call_mkdtemp(self, node):
        self.arguments(node)
        return frozenset({PATH, TEMP})

    call_mkstemp = call_mkdtemp
    call_mktemp = call_mkdtemp
    call_gettempdir = call_mkdtemp
    call_TemporaryDirectory = call_mkdtemp
    call_NamedTemporaryFile = call_mkdtemp
    call_TemporaryFile = call_mkdtemp

    def call_search(self, node):
        func = node.func
        if not isinstance(func, ast.Attribute) or not node.args:
            return None
        if not is_name(func.value, ("re", "regex")):
            return contained(self.taint(func.value), self.taint(node.args[0]))
        return contained(self.taint(node.args[0]), self.taint(node.args[1])) if len(node.args) > 1 else None

    call_match = call_search
    call_fullmatch = call_search
    call_findall = call_search
    call_finditer = call_search

    def call_startswith(self, node):
        if not isinstance(node.func, ast.Attribute):
            return None
        hay = self.taint(node.func.value)
        if not texts(hay):
            return None
        return contained(self.taint(node.args[0]) if node.args else EMPTY, hay)

    call_endswith = call_startswith
    call_count = call_startswith
    call_index = call_startswith
    call_find = call_startswith
    call_rfind = call_startswith
    call_rindex = call_startswith
