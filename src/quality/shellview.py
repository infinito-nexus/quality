import re
from dataclasses import dataclass, field
from functools import cached_property

from quality import heredoc

CODE = "code"
DOUBLE = "double"
SINGLE = "single"
ANSI = "ansi"
SUBST = "subst"
PAREN = "paren"
TICK = "tick"
ARGUMENT = "argument"
CODE_KINDS = (CODE, SUBST, PAREN, TICK)
QUOTE_KINDS = (DOUBLE, SINGLE, ANSI)
WORD_ENDS = ("blank", "open", "close", "comment", "tick")
SEPARATOR = b" ; "
SPECIAL = re.compile(rb"[\\'\"$`]")
HEX = re.compile(rb"[xuU][0-9A-Fa-f]+")
OCTAL = re.compile(rb"[0-7]{1,3}")
NOT_KEPT = heredoc.NOT_KEPT
HEAD_HINTS = (b"eval", b"trap", b"sh", b"su", b"runuser")
COMMAND_BREAK = re.compile(rb"[;&|()<>`]")
KEYWORDS = (b"{", b"!", b"if", b"elif", b"while", b"until", b"then", b"do", b"else", b"time")
LEADING = re.compile(rb"[A-Za-z_]\w*=.*|\$\{?[A-Za-z_]\w*\}?")
EVALUATORS = (b"eval", b"trap")
BUILTIN_RUNNERS = (b"command", b"builtin")
PRINTERS = (b"echo", b"printf", b"print", b":")
SHELL = re.compile(rb"(?:[^=]*/)?(?:(?:ba|da|z|k|a|mk|ya|tc|c|fi)?sh|su|runuser)")
CODE_FLAG = re.compile(rb"-[A-Za-z]*c[A-Za-z]*")
OPTION = re.compile(rb"[-+][A-Za-z]+|--[A-Za-z-]*")
REDIRECT = re.compile(rb"[0-9]*(?:&>>?|[<>]+&?[0-9-]*)")
GROUP = re.compile(rb"\$?\([^()]*\)|`[^`]*`")
POSITIONAL = b"\x1f"
PIPED = re.compile(rb"(?:[^;&|]|[<>]&|&>)*\|(?!\|)")
CONTINUED = re.compile(rb"(?:[^;&|]|[<>]&|&>)*\\$")
TRAILING = re.compile(rb"[\s;]*(?:" + heredoc.COMMENT + rb")?$")
STARTS = rb"""
    (?P<escape>\\(?:[^\n]|\Z))
    | (?P<ansi>\$')
    | (?P<double>\$?")
    | (?P<single>')
    | (?P<subst>\$\()
    | (?P<tick>`)
    | (?P<open>\()
    | (?P<close>\))
    | (?P<comment>(?<![^\s;&|()<>])\#)
"""
CODE_TOKENS = re.compile(
    rb"(?x) (?P<single_string>'[^']*') | (?P<double_string>\"[^\"\\$`]*\") |"
    + STARTS
    + rb"| (?P<plain>(?:[^\\'\"$`()\#]|\$(?![\'\"(]))+) | (?P<word>[$\#])"
)
WORD_TOKENS = re.compile(rb"(?x)" + STARTS + rb"| (?P<blank>[\s;&|<>]+) | (?P<word>[^\s;&|<>\\'\"$`()\#]+|[$\#])")
QUOTE_TOKENS = {
    DOUBLE: re.compile(
        rb"(?x) (?P<double_escape>\\[\\\"$`]) | (?P<subst>\$\() | (?P<tick>`) | (?P<unquote>\")"
        rb"| (?P<parameter>\$(?:[A-Za-z_]\w*|\{[A-Za-z_]\w*\})) | (?P<data>[^\\\"$`]+|[\\$])"
    ),
    SINGLE: re.compile(rb"(?P<unquote>')|(?P<data>[^']+)"),
    ANSI: re.compile(
        rb"""(?x)
        (?P<unquote>')
        | (?P<ansi_escape>\\(?:x[0-9A-Fa-f]{1,2}|u[0-9A-Fa-f]{1,4}|U[0-9A-Fa-f]{1,8}|[0-7]{1,3}|c[^\n]|[^\n]|\Z))
        | (?P<data>[^'\\]+)
        """
    ),
}
SIMPLE_ESCAPES = {
    b"n": b"\n",
    b"t": b"\t",
    b"r": b"\r",
    b"a": b"\a",
    b"b": b"\b",
    b"e": b"\x1b",
    b"E": b"\x1b",
    b"f": b"\f",
    b"v": b"\v",
    b"\\": b"\\",
    b"'": b"'",
    b'"': b'"',
    b"?": b"?",
}


@dataclass
class Lex:
    line: bytes
    literal: bool
    levels: int
    window: int
    stack: list
    out: bytearray
    pos: int
    floor: int = 0
    closed_at: int = -1
    closed_out: int = 0


def code_view(data: bytes, levels: int, window: int) -> bytes:
    """
    Args:
        data: Content of one shell script.
        levels: How often an interpreter argument nested in another is read as
            code once more.
        window: Bytes of the view before a quote that are searched for the
            interpreter it belongs to.

    Returns:
        What the shell runs as code, line for line, so line numbers stay:
        quotes are removed and the text they hold keeps its word characters
        while blanks, operators and `#` become `_`, so a quoted string stays one
        word; `$(…)` and backticks inside double quotes stay code; the code
        argument of a shell, `su` or `runuser`, the first word after its
        options when one of them holds `c`, is read as code once more, a
        comment in it ending at its closing quote, with
        POSITIONAL after it when words follow, since those are positional
        parameters, unless a printing command (echo, printf, print, `:`)
        stands before the interpreter in the same command, redirections and
        substitutions skipped; so are the arguments of `eval` and `trap` in
        command position. A line after one that ends inside a quote, also
        inside a `$(…)` that quote holds, is read twice, from inside every
        context still open there, up to
        `levels` of them, and from code, see viewed(); only the first reading
        carries on to the next line. A heredoc whose delimiter line follows
        is read as a script of its own, from nothing open and carrying
        nothing out; when the line opening it ends inside a quote or
        substitution, its delimiter may be followed by a closing quote or
        `)`, whose rest of the line is read in the context around the heredoc.
    """
    lines = data.split(b"\n")
    script = Script(lines, levels, window)
    for index in range(len(lines)):
        script.read(index)
    return b"\n".join(script.views)


@dataclass
class Script:
    lines: list
    levels: int
    window: int
    views: list = field(default_factory=list)
    carried: tuple | None = None
    bodies: list = field(default_factory=list)

    @cached_property
    def ends(self) -> dict:
        return heredoc.terminators(self.lines)

    def read(self, index: int) -> None:
        line, head, body = self.lines[index], b"", None
        if self.bodies and self.bodies[-1][0] == index:
            body = self.bodies.pop()
            head, line, self.carried = line[: body[1]], line[body[1] :], body[2]
        heredocs, stack = self.shown(index, head, line, body is not None)
        found = body[3] if body else []
        if heredocs and not found:
            limit = self.bodies[-1][0] if self.bodies else len(self.lines)
            enclosed = any(kind not in (CODE, PAREN) for kind in stack)
            found = heredoc.ends_of(self.ends, index, heredocs, limit, enclosed)
        if found:
            self.bodies.append((*found[0], self.carried, found[1:]))
            self.carried = None

    def shown(self, index: int, head: bytes, line: bytes, ended: bool) -> tuple:
        if (ended and not line) or (self.carried is None and not SPECIAL.search(line) and b"<<" not in line):
            self.views.append(head + line)
            return [], []
        starts = [[CODE]] if self.carried is None else [list(self.carried), [CODE]]
        lexes = [lexed(Lex(line, False, self.levels, self.window, stack, bytearray(), 0, floor_of(stack)), False) for stack in starts]
        if piped_out(lexes[0], self.carried, b"".join(self.lines[index + 1 : index + 2])):
            self.views[-1] = continued(self.views[-1])
        self.views.append(head + viewed(lexes, self.carried, self.levels, self.window))
        self.carried = carried_on(lexes[0].stack, self.levels)
        return heredoc.opened(bytes(lexes[0].out)), lexes[0].stack


def piped_out(inner: Lex, carried: tuple | None, following: bytes) -> bool:
    """
    Args:
        inner: The reading of a line from inside its carried context.
        carried: That context, see carried_on().
        following: The next line.

    Returns:
        Whether the line closes a code argument at its start and pipes the
        interpreter's output on, as `" | sh`, or as `" \\` before a line
        that does, as `app 2>&1 | sh`, so the view of the line before, the argument's
        last, is followed by a copy of itself, see continued(), that
        continues into this one, as one logical line.
    """
    if carried is None or ARGUMENT not in carried or inner.closed_at < 0 or inner.line[: inner.closed_at].strip():
        return False
    tail = bytes(inner.out[inner.closed_out :])
    if PIPED.match(tail):
        return True
    return CONTINUED.match(tail) is not None and PIPED.match(following) is not None


def continued(view: bytes) -> bytes:
    """
    Args:
        view: The view of a code argument's last line.

    Returns:
        That view without a trailing comment or `;`, then a copy of it that
        continues into the next line, so a fetch it ends with reaches the
        pipe there while a match of its own still ends where it did.
    """
    code = TRAILING.sub(b"", view, count=1)
    return code + SEPARATOR + code + b" \\"


def floor_of(stack: list) -> int:
    marks = (ARGUMENT,) if ARGUMENT in stack else QUOTE_KINDS
    return next((place for place, kind in enumerate(stack) if kind in marks), 0)


def viewed(lexes: list, carried: tuple | None, levels: int, window: int) -> bytes:
    """
    Args:
        lexes: The readings of one line: without a carried context only the
            one from code, else first the one from inside it, then the one
            from code.
        carried: The context the line starts in, see carried_on().
        levels: As for code_view().
        window: As for code_view().

    Returns:
        The view of the line. Where the inside reading closes the carried
        context, the reading from code stops at that quote, so it never reads
        the rest of the line with its quotes flipped. Inside a code argument
        only the reading from code counts, and on the line its quote closes
        that reading up to the quote, a comment in it ending there, is
        followed by the inside reading of the rest, as on one line.
    """
    if carried is None:
        return bytes(lexes[0].out)
    inner, code = lexes
    if inner.closed_at >= 0:
        code = lexed(Lex(inner.line[: inner.closed_at], False, levels, window, [CODE], bytearray(), 0), False)
    if ARGUMENT not in carried:
        return SEPARATOR.join([bytes(inner.out), bytes(code.out)])
    if inner.closed_at < 0:
        return bytes(code.out)
    rest = inner.line[inner.closed_at + 1 :].lstrip()
    end = POSITIONAL if rest and not COMMAND_BREAK.match(rest) else b""
    return heredoc.COMMENT_TEXT.sub(b"", bytes(code.out)) + end + bytes(inner.out[inner.closed_out :])


def carried_on(stack: list, levels: int) -> tuple | None:
    return (CODE, *stack[1:][-max(levels, 1) :]) if any(kind in QUOTE_KINDS for kind in stack) else None


def line_view(line: bytes, levels: int, window: int) -> bytes:
    return bytes(lexed(Lex(line.replace(b"\n", b";"), False, levels, window, [CODE], bytearray(), 0), False).out)


def lexed(lex: Lex, word: bool) -> Lex:
    """
    Args:
        lex: Where to start, with the open contexts.
        word: Stop at the end of the word that starts at lex.pos.

    Returns:
        The same lex, advanced to the end of the line or word.
    """
    if not word and lex.stack == [CODE] and not SPECIAL.search(lex.line, lex.pos):
        lex.out += lex.line[lex.pos :]
        lex.pos = len(lex.line)
        return lex
    code_tokens = WORD_TOKENS if word else CODE_TOKENS
    while lex.pos < len(lex.line):
        kind = lex.stack[-1]
        match = (code_tokens if kind in CODE_KINDS else QUOTE_TOKENS[kind]).match(lex.line, lex.pos)
        if word and len(lex.stack) == 1 and match.lastgroup in WORD_ENDS:
            break
        HANDLERS[match.lastgroup](lex, match)
    return lex


def argument_end(lex: Lex) -> bytes | None:
    """
    Args:
        lex: A lex standing at a quote in code.

    Returns:
        None when the word starting at the quote, within the window of the
        view, is no code. Otherwise what follows its view: nothing after an
        argument of `eval` or `trap` in command position, whose other words
        are code too, and POSITIONAL, the unit separator 0x1F, after the code
        argument of a shell, `su` or `runuser`, see code_argument(): the rule
        reads it as the end of the code for an interpreter at its end while
        the pipe the interpreter writes into stays, and unlike `)` it closes
        no group simple_command() strips.
    """
    tail = bytes(lex.out[-lex.window :])
    hinted = any(word in tail for word in HEAD_HINTS)
    if not hinted or lex.literal or lex.levels <= 0:
        return None
    command = COMMAND_BREAK.split(simple_command(tail))[-1]
    words = command.split()
    if words and not command[-1:].isspace():
        words.pop()
    if evaluated(words):
        return b""
    return POSITIONAL if code_argument(words) else None


def simple_command(tail: bytes) -> bytes:
    tail = REDIRECT.sub(b" ", tail)
    count = 1
    while count:
        tail, count = GROUP.subn(b"_", tail)
    return tail


def evaluated(words: list) -> bool:
    for word in words:
        if word not in KEYWORDS and word not in BUILTIN_RUNNERS and not LEADING.fullmatch(word):
            return word in EVALUATORS
    return False


def code_argument(words: list) -> bool:
    """
    Args:
        words: The words of one command before a quote.

    Returns:
        Whether the quote starts the code argument of a shell, `su` or
        `runuser`: the words right before it are options, one holding `c`,
        and the nearest such interpreter before those options is no argument
        of a printing command, as in `echo bash -c`, wherever it stands, so
        `docker run --entrypoint sh img -c` and `find . -exec sh -c` count.
    """
    start = len(words)
    while start and OPTION.fullmatch(words[start - 1]):
        start -= 1
    if not any(CODE_FLAG.fullmatch(word) for word in words[start:]):
        return False
    for place in range(start - 1, -1, -1):
        if SHELL.fullmatch(words[place]):
            return not any(word.rsplit(b"/", 1)[-1] in PRINTERS for word in words[:place])
    return False


def unwrapped(lex: Lex, match, end: bytes) -> None:
    argument = lexed(Lex(lex.line, True, lex.levels, lex.window, [CODE], bytearray(), match.start()), True)
    lex.out += heredoc.COMMENT_TEXT.sub(b"", line_view(bytes(argument.out), lex.levels - 1, lex.window))
    lex.pos = argument.pos
    still_open = argument.stack[1:]
    if still_open and still_open[0] in QUOTE_KINDS:
        lex.stack += [ARGUMENT, *still_open]
    rest = lex.line[lex.pos :].lstrip()
    if rest and not COMMAND_BREAK.match(rest):
        lex.out += end


def data(lex: Lex, text: bytes) -> None:
    lex.out += text if lex.literal else NOT_KEPT.sub(b"_", text)


def quote(lex: Lex, match) -> None:
    end = argument_end(lex)
    if end is not None:
        unwrapped(lex, match, end)
        return
    lex.pos = match.end()
    lex.stack.append(match.lastgroup)


def whole_quote(lex: Lex, match) -> None:
    end = argument_end(lex)
    if end is not None:
        unwrapped(lex, match, end)
        return
    lex.pos = match.end()
    data(lex, match.group()[1:-1])


def code_escape(lex: Lex, match) -> None:
    lex.pos = match.end()
    escaped = match.group()[1:]
    if not escaped:
        lex.out += b"\\"
    elif lex.literal or not NOT_KEPT.match(escaped):
        lex.out += escaped
    else:
        lex.out += b"_"


def subst(lex: Lex, match) -> None:
    verbatim(lex, match)
    lex.stack.append(SUBST)


def tick(lex: Lex, match) -> None:
    verbatim(lex, match)
    if lex.stack[-1] == TICK:
        lex.stack.pop()
    else:
        lex.stack.append(TICK)


def opened(lex: Lex, match) -> None:
    verbatim(lex, match)
    lex.stack.append(PAREN)


def closed(lex: Lex, match) -> None:
    verbatim(lex, match)
    if lex.stack[-1] in (PAREN, SUBST):
        lex.stack.pop()


def comment(lex: Lex, match) -> None:
    lex.out += match.group()
    lex.pos = len(lex.line)


def verbatim(lex: Lex, match) -> None:
    lex.pos = match.end()
    lex.out += match.group()


def unquote(lex: Lex, match) -> None:
    lex.pos = match.end()
    lex.stack.pop()
    if lex.stack[-1] == ARGUMENT:
        lex.stack.pop()
    if lex.closed_at < 0 and len(lex.stack) <= lex.floor:
        lex.closed_at = match.start()
        lex.closed_out = len(lex.out)


def quoted(lex: Lex, match) -> None:
    lex.pos = match.end()
    data(lex, match.group())


def double_escape(lex: Lex, match) -> None:
    lex.pos = match.end()
    data(lex, match.group()[1:])


def ansi_escape(lex: Lex, match) -> None:
    lex.pos = match.end()
    data(lex, decoded(match.group()))


def decoded(escape: bytes) -> bytes:
    """
    Args:
        escape: One backslash escape inside `$'…'`.

    Returns:
        The bytes bash makes of it; an unknown one stays as written.
    """
    body = escape[1:]
    if HEX.fullmatch(body):
        number = int(body[1:], 16)
        return bytes([number]) if body[:1] == b"x" else chr(min(number, 0x10FFFF)).encode("utf-8", "replace")
    if OCTAL.fullmatch(body):
        return bytes([int(body, 8) & 0xFF])
    if body[:1] == b"c" and len(body) > 1:
        return bytes([body[1] & 0x1F])
    return SIMPLE_ESCAPES.get(body, escape)  # nocheck: clean.default-value -- bash keeps an unknown escape as written


HANDLERS = {
    "single_string": whole_quote,
    "double_string": whole_quote,
    "escape": code_escape,
    "ansi": quote,
    "double": quote,
    "single": quote,
    "subst": subst,
    "tick": tick,
    "open": opened,
    "close": closed,
    "comment": comment,
    "plain": verbatim,
    "blank": verbatim,
    "word": verbatim,
    "parameter": verbatim,
    "double_escape": double_escape,
    "unquote": unquote,
    "data": quoted,
    "ansi_escape": ansi_escape,
}
