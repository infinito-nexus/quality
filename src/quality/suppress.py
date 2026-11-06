import io
import re
import tokenize
from dataclasses import dataclass

NOCHECK = re.compile(r"nocheck:\s*(?P<rule>[A-Za-z0-9_.\-]+)\s+--\s+\S")
QUOTES = "\"'`"


@dataclass(frozen=True)
class NocheckLine:
    path: str
    line: int
    rule: str


def python_comments(data: bytes) -> dict:
    """
    Args:
        data: File content.

    Returns:
        Line number to the text of each real comment. A file that stops
        tokenizing yields the comments before that point.
    """
    found = {}
    try:
        for token in tokenize.tokenize(io.BytesIO(data).readline):
            if token.type == tokenize.COMMENT:
                found[token.start[0]] = token.string
    except (tokenize.TokenError, SyntaxError, ValueError):
        return found
    return found


def line_comment(text: str, marker: str) -> str | None:
    """
    Args:
        text: One source line.
        marker: The kind's line comment marker.

    Returns:
        The comment including its marker, skipping quoted text, or None.
    """
    quote = None
    index = 0
    while index < len(text):
        char = text[index]
        if quote is not None:
            if char == "\\":
                index += 1
            elif char == quote:
                quote = None
        elif char in QUOTES:
            quote = char
        elif starts_comment(text, index, marker):
            return text[index:]
        index += 1
    return None


def starts_comment(text: str, index: int, marker: str) -> bool:
    if not text.startswith(marker, index):
        return False
    # Exception: `$#` and `${#x}` are shell syntax, so `#` needs leading blank.
    return marker != "#" or index == 0 or text[index - 1].isspace()


def marker_comments(lines: list, marker: str) -> dict:
    found = {}
    for number, text in enumerate(lines, start=1):
        comment = line_comment(text, marker)
        if comment is not None:
            found[number] = comment
    return found


def nocheck_rule(comment: str) -> str | None:
    """
    Args:
        comment: Text of a real comment.

    Returns:
        The rule or group a nocheck directive names, or None when the
        directive is absent or has no reason.
    """
    match = NOCHECK.search(comment)
    return match["rule"] if match else None


def rule_matches(rule_id: str, name: str) -> bool:
    return rule_id == name or rule_id.startswith(f"{name}.")


def split_nocheck(hits: list, snapshot) -> tuple:
    """
    Args:
        hits: Findings on the head side.
        snapshot: Snapshot the findings came from.

    Returns:
        The remaining findings and the applied NocheckLine records. Hard rules
        are never suppressed inline, and a finding without a line cannot be.
    """
    kept = []
    applied = {}
    for hit in hits:
        name = None if hit.rule.hard or hit.line is None else suppressor(hit, snapshot)
        if name is None:
            kept.append(hit)
        else:
            applied[(hit.path, hit.line, name)] = NocheckLine(hit.path, hit.line, name)
    return kept, list(applied.values())


def suppressor(hit, snapshot) -> str | None:
    comment = snapshot.comment(hit.path, hit.line)
    name = nocheck_rule(comment) if comment is not None else None
    return name if name is not None and rule_matches(hit.rule.id, name) else None
