import re

OPENER = re.compile(rb"<\?(?:php(?=\s|\Z)|=)?", re.IGNORECASE)
CODE = re.compile(rb"\?>|//|#|/\*|['\"`]|<<<")
BRACED = re.compile(rb"[{}]|//|#|/\*|['\"`]|<<<")
QUOTED = {
    b"'": re.compile(rb"[\\']"),
    b'"': re.compile(rb'[\\"]|\{\$|\$\{'),
    b"`": re.compile(rb"[\\`]|\{\$|\$\{"),
}
HEREDOC = re.compile(rb"<<<[ \t]*([\"']?)([A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*)\1\r?\n")
HEREDOC_BODY = {True: re.compile(rb"\n|\\|\{\$|\$\{"), False: re.compile(rb"\n")}
NAME_CHAR = re.compile(rb"[A-Za-z0-9_\x80-\xff]")
INDENT = re.compile(rb"[ \t]*")
COMMENT_END = re.compile(rb"\r|\n|\?>")
MARKUP = re.compile(rb"[^\r\n]")
LINE_BREAKS = (b"\n", b"\r")
CLOSE = b"?>"
ECHO = b"echo"


def unhosted(data: bytes) -> bytes:
    """
    Args:
        data: A PHP file.

    Returns:
        The file at its length and with its line breaks, the markup outside
        PHP's tags blanked: an opener becomes spaces or `echo`, and a closing
        tag the `;` it implies. Strings, heredocs and comments are lexed as
        PHP lexes them.
    """
    result = bytearray(data)
    position = 0
    while position < len(data):
        opener = OPENER.search(data, position)
        stop = len(data) if opener is None else opener.start()
        result[position:stop] = MARKUP.sub(b" ", data[position:stop])
        if opener is None:
            break
        begin = opened(result, data, opener)
        close = code_end(result, data, begin)
        if close < len(data):
            result[close : close + len(CLOSE)] = implied(result, begin, close)
        position = close + len(CLOSE)
    return bytes(result)


def opened(result: bytearray, data: bytes, opener) -> int:
    """
    Args:
        result: The copy being blanked, markup before the opener blanked.
        data: The PHP file.
        opener: Match of the opener.

    Returns:
        Offset where its code begins. A `<?=` becomes the `echo` it means
        where echo_at finds room; else it is blanked too.
    """
    start, end = opener.span()
    result[start:end] = b" " * (end - start)
    at = echo_at(result, data, start, end) if opener.group() == b"<?=" else None
    if at is not None:
        result[at : at + len(ECHO)] = ECHO
    return end


def echo_at(result: bytearray, data: bytes, start: int, end: int):
    """
    Args:
        result: The copy being blanked.
        data: The PHP file.
        start: Offset of a `<?=`.
        end: Offset after it.

    Returns:
        Where `echo` fits over the tag and the blank before or after it
        without running into a name, or None.
    """
    if result[start - 1 : start] == b" " and not NAME_CHAR.match(data, end):
        return end - len(ECHO)
    if data[end : end + 1] in (b" ", b"\t") and not NAME_CHAR.match(data, end + 1):
        return start
    return None


def implied(result: bytearray, begin: int, close: int) -> bytes:
    if result[begin:close].rstrip()[-1:] in (b"", b":", b"{"):
        return b"  "
    return b"; "


def code_end(result: bytearray, data: bytes, position: int) -> int:
    """
    Args:
        result: The copy being blanked.
        data: The PHP file.
        position: Offset where code begins.

    Returns:
        Offset of the `?>` that ends the code, or the end of the file. A line
        comment that a `?>` ends is blanked.
    """
    token = CODE.search(data, position)
    while token is not None:
        position = token.start()
        if data.startswith(CLOSE, position):
            return position
        if line_comment(data, position):
            end = comment_end(data, position)
            if data.startswith(CLOSE, end):
                result[position:end] = b" " * (end - position)
            position = end
        else:
            position = skipped(data, position)
        token = CODE.search(data, position)
    return len(data)


def line_comment(data: bytes, position: int) -> bool:
    return data.startswith(b"//", position) or (data.startswith(b"#", position) and not data.startswith(b"#[", position))


def comment_end(data: bytes, position: int) -> int:
    end = COMMENT_END.search(data, position)
    return len(data) if end is None else end.start()


def skipped(data: bytes, position: int) -> int:
    """
    Args:
        data: The PHP file.
        position: Offset of a token in code.

    Returns:
        Offset after a string, heredoc, nowdoc or block comment that starts
        there, else after the one byte.
    """
    byte = data[position : position + 1]
    if byte in QUOTED:
        return quoted_end(data, position + 1, byte)
    if data.startswith(b"/*", position):
        end = data.find(b"*/", position + 2)
        return len(data) if end < 0 else end + 2
    heredoc = HEREDOC.match(data, position)
    if heredoc is not None:
        return heredoc_end(data, heredoc)
    return position + 1


def quoted_end(data: bytes, position: int, quote: bytes) -> int:
    token = QUOTED[quote].search(data, position)
    while token is not None:
        position = token.start()
        if token.group() == quote:
            return position + 1
        if token.group() == b"\\":
            position += 2
        else:
            position = braced_end(data, position + (token.group() == b"${"))
        token = QUOTED[quote].search(data, position)
    return len(data)


def braced_end(data: bytes, position: int) -> int:
    """
    Args:
        data: The PHP file.
        position: Offset of the `{` that opens code inside a string.

    Returns:
        Offset after its matching `}`; strings and comments inside are lexed
        as code, and a `?>` there does not end it.
    """
    depth = 0
    token = BRACED.search(data, position)
    while token is not None:
        position = token.start()
        if token.group() == b"{":
            depth += 1
        if token.group() == b"}":
            depth -= 1
            if depth == 0:
                return position + 1
        if line_comment(data, position):
            position = max(comment_end(data, position), position + 1)
        else:
            position = skipped(data, position)
        token = BRACED.search(data, position)
    return len(data)


def heredoc_end(data: bytes, heredoc) -> int:
    """
    Args:
        data: The PHP file.
        heredoc: Match of the `<<<` line, its quote and name.

    Returns:
        Offset after the closing name, which stands at the start of a line
        after optional blanks and is not followed by a name character.
    """
    name = heredoc.group(2)
    body = HEREDOC_BODY[heredoc.group(1) != b"'"]
    position = heredoc.end()
    while position < len(data):
        begin = INDENT.match(data, position).end()
        after = begin + len(name)
        if data.startswith(name, begin) and not NAME_CHAR.match(data, after):
            return after
        position = heredoc_line_end(data, position, body)
    return len(data)


def heredoc_line_end(data: bytes, position: int, body) -> int:
    token = body.search(data, position)
    while token is not None:
        position = token.start()
        if token.group() == b"\n":
            return position + 1
        if token.group() == b"\\":
            position += 1 + (data[position + 1 : position + 2] not in LINE_BREAKS)
        else:
            position = braced_end(data, position + (token.group() == b"${"))
        token = body.search(data, position)
    return len(data)
