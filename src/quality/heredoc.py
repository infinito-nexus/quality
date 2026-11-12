import bisect
import re

COMMENT = rb"(?<![^\s;&|()<>])#.*"
COMMENT_TEXT = re.compile(COMMENT)
NOT_KEPT = re.compile(rb"[^A-Za-z0-9_./:@%+,=~-]")
HEREDOC = re.compile(rb"(?<!<)<<(?!<)(-?)[\t ]*([^\s;&|<>()`\x1f]+)")
CLOSING = re.compile(rb"[)'\"`]")


def opened(code: bytes) -> list:
    """
    Args:
        code: The code view of one line, quoted text already neutralized.

    Returns:
        The `-` flag and delimiter of every heredoc the line opens, in order,
        a `<<` in a comment not counted; a quoted delimiter comes as quoted
        text is viewed, as `END_OF_HELP` for `<<'END OF HELP'`.
    """
    return HEREDOC.findall(COMMENT_TEXT.sub(b"", code))


def terminators(lines: list) -> dict:
    """
    Args:
        lines: The lines of one script.

    Returns:
        For each delimiter a line may hold, as written and with the
        characters quoted text neutralizes made `_`, whether the line starts
        with tabs and whether the delimiter ends it instead of standing
        before a closing quote, backtick or `)`, the lines it stands on, in
        order, each with the length of the line up to the delimiter's end;
        an empty line or one starting with a blank ends no heredoc, since
        only a quoted delimiter could start with one.
    """
    found = {}
    for place, line in enumerate(lines):
        text = line.lstrip(b"\t")
        if text[:1] in (b"", b" "):
            continue
        tabs = len(line) - len(text)
        text = text.removesuffix(b"\r")
        closing = CLOSING.search(text)
        for delimiter, exact in [(text, True), *([(text[: closing.start()], False)] if closing else [])]:
            for key in {delimiter, NOT_KEPT.sub(b"_", delimiter)}:
                found.setdefault((key, tabs > 0, exact), []).append((place, tabs + len(delimiter)))
    return found


def ends_of(ends: dict, index: int, heredocs: list, limit: int, enclosed: bool) -> list:
    """
    Args:
        ends: Lines that can end a heredoc body, see terminators().
        index: The line holding the heredocs.
        heredocs: Their `-` flag and delimiter, in order, see opened().
        limit: The first line no body may reach, the end of the body around.
        enclosed: Whether that line ends inside a quote or substitution, so
            a delimiter may end a body before what closes them, as `EOF)`.

    Returns:
        Line and delimiter length of the end of each heredoc, in order, one
        whose delimiter line does not follow skipped as no heredoc, as the
        `<<` of `$(( 1 << n ))`, so no body runs on to the end of the file.
    """
    found, start = [], index + 1
    for dash, delimiter in heredocs:
        kinds = {(delimiter, tabbed, exact) for tabbed in (False, bool(dash)) for exact in (True, not enclosed)}
        if hits := [hit for kind in kinds if (hit := first(ends.get(kind, []), start, limit))]:
            found.append(min(hits))
            start = found[-1][0] + 1
    return found


def first(candidates: list, start: int, limit: int) -> tuple | None:
    place = bisect.bisect_left(candidates, (start,))
    return candidates[place] if place < len(candidates) and candidates[place][0] < limit else None
