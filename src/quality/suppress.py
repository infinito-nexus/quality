import io
import re
import tokenize
from dataclasses import dataclass
from typing import NoReturn

import yaml

from quality import QualityError

NOCHECK = re.compile(r"nocheck:\s*(?P<rule>[A-Za-z0-9_.\-]+)\s+--\s+\S")
QUOTES = "\"'`"
BOM = "\N{ZERO WIDTH NO-BREAK SPACE}"
COMMENTS_FILE = "comments.yml"
DECLARATION_FILE = ".quality/comments.yml"
DIRECTIVES = "directives"
PRAGMAS_ALLOWED = "pragmas_allowed"
GROUP_KEYS = frozenset({"tool", "spellings", "languages", "marker", "tight", "position"})
NOTHING = "[^\\s\\S]"


def refuse(key: str, problem: str) -> NoReturn:
    raise QualityError(f"{DECLARATION_FILE}: {key} {problem}")


def compiled(pattern: object, key: str) -> str:
    if not isinstance(pattern, str):
        refuse(key, "must hold regex strings")
    try:
        re.compile(pattern)
    except re.error as error:
        refuse(key, f"holds a regex that does not compile: {error}")
    return pattern


def regex_list(value: object, key: str) -> list:
    if not isinstance(value, list) or not value:
        refuse(key, "must be a non-empty list of regexes")
    return [compiled(pattern, key) for pattern in value]


def declared_group(group: object, position: int, languages: set | None) -> dict:
    key = f"{DIRECTIVES}[{position}]"
    if not isinstance(group, dict):
        refuse(key, "must be a mapping")
    unknown = sorted(set(group) - GROUP_KEYS)
    if unknown:
        refuse(key, f"has unknown keys {unknown}")
    named = group.get("languages", [])
    if not isinstance(named, list) or (languages is not None and not set(named) <= languages):
        refuse(f"{key} languages", f"must be a list of {sorted(languages or [])}")
    return {**group, "spellings": regex_list(group.get("spellings"), f"{key} spellings")}


def top_level(data: bytes) -> dict:
    try:
        raw = yaml.safe_load(data)
    except yaml.YAMLError:
        refuse("content", "is not valid YAML")
    if not isinstance(raw, dict):
        refuse("top level", "must be a mapping")
    unknown = sorted(set(raw) - {DIRECTIVES, PRAGMAS_ALLOWED})
    if unknown:
        refuse("top level", f"has unknown keys {unknown}")
    return raw


def declaration(data: bytes | None, languages: set | None) -> dict:
    """
    Args:
        data: Content of the repository's .quality/comments.yml, or None
            when it has none.
        languages: ast-grep languages a directive group may name, or None
            for a caller that reads only the allowed pragmas.

    Returns:
        The declared directive groups and allowed pragma regexes under
        `directives` and `pragmas_allowed`, both empty without a file.

    Raises:
        QualityError: The file is not YAML, has an unknown key, a group
            without spellings or with an unknown language, or a regex that
            does not compile.
    """
    if data is None:
        return {DIRECTIVES: [], PRAGMAS_ALLOWED: []}
    raw = top_level(data)
    groups = raw.get(DIRECTIVES, [])
    if not isinstance(groups, list):
        refuse(DIRECTIVES, "must be a list of groups")
    allowed = regex_list(raw[PRAGMAS_ALLOWED], PRAGMAS_ALLOWED) if PRAGMAS_ALLOWED in raw else []
    return {
        DIRECTIVES: [declared_group(group, position, languages) for position, group in enumerate(groups)],
        PRAGMAS_ALLOWED: allowed,
    }


def with_declaration(comments: dict, declared: dict) -> dict:
    """
    Args:
        comments: Content of the catalogue's comments.yml.
        declared: A repository's declaration, as `declaration` returns it.

    Returns:
        comments.yml with the declared directive groups after the
        catalogue's and the declared allowed pragmas.
    """
    return {
        **comments,
        DIRECTIVES: [*spellings(comments, DIRECTIVES), *declared[DIRECTIVES]],
        PRAGMAS_ALLOWED: declared[PRAGMAS_ALLOWED],
    }


def spellings(raw: dict, key: str):
    if not isinstance(raw, dict) or key not in raw:
        raise QualityError(f"rule data: {COMMENTS_FILE} is missing key {key!r}")
    return raw[key]


def alternatives(groups: dict) -> str:
    return "|".join(spelling for found in groups.values() for spelling in found)


def comment_patterns(raw: dict) -> dict:
    """
    Args:
        raw: Content of comments.yml: the comment marker, each tool's pragma
            spellings, the parameter-doc sections and doc tags.

    Returns:
        Placeholder to pattern for every language alike. Every pattern
        compiles for Rust's regex crate and for Python; `@docstring` alone
        needs Python's lookahead and backreferences.
    """
    marker = spellings(raw, "marker")
    sections = "|".join(spellings(raw, "sections"))
    tag = f"@(?:{'|'.join(spellings(raw, 'doc_tags'))})"
    suppressing = alternatives(spellings(raw, "pragmas"))
    entries = "(?:(?P=i)[ \\t]+\\S[^\\n]*\\n|[ \\t]*\\n)*"
    return {
        "@pragma": f"(?i)(?:(?:^|\\s){marker}\\s*(?:{suppressing})|{alternatives(spellings(raw, 'pragmas_anywhere'))})",
        "@doc-block": (
            f"^(?:/\\*\\*[ \\t]*{tag}[^\\n]*?\\*/|/\\*\\*[ \\t]*(?:{tag}[^\\n]*\\n"
            f"|\\n(?:[ \\t]*\\*[ \\t]*\\n)*[ \\t]*\\*[ \\t]+{tag}[^\\n]*\\n)"
            f"(?:[ \\t]*\\*[^\\n]*\\n)*[ \\t]*\\*/)$"
        ),
        "@block-sections": (
            f"^/\\*+[ \\t]*\\n(?:[ \\t]*\\*[ \\t]*\\n)*(?:[ \\t]*\\*[ \\t]?(?:{sections}):[ \\t]*\\n"
            f"(?:[ \\t]*\\*(?:[ \\t]{{2,}}\\S[^\\n]*|[ \\t]*)\\n)*)+[ \\t]*\\*/$"
        ),
        "@docstring": (
            f"[rRuU]{{0,2}}(?P<q>\"\"\"|''')(?:\\s*Exception:[\\s\\S]*"
            f"|(?=[\\s\\S]*\\n(?P<i>[ \\t]*)(?P=q)\\Z)(?:[ \\t]*\\n(?:[ \\t]*\\n)*(?P=i))?"
            f"(?:{sections}):[ \\t]*\\n{entries}(?:(?P=i)(?:{sections}):[ \\t]*\\n{entries})*(?P=i)(?P=q))"
        ),
    }


def nocheck_names(rule_ids: list) -> list:
    """
    Args:
        rule_ids: Every rule id of the catalogue.

    Returns:
        The names a nocheck may carry: each id and each of its dotted groups.
    """
    names = set()
    for rule_id in rule_ids:
        parts = rule_id.split(".")
        names.update(".".join(parts[:index]) for index in range(1, len(parts) + 1))
    return sorted(names)


def directive_form(marker: str, group: dict) -> str:
    own = group["marker"] if "marker" in group else marker
    gap = "" if group.get("tight") else "\\s*"
    return f"{own}{gap}(?:{'|'.join(group['spellings'])})\\s*(?:\\*/|-->)?\\s*"


def allowed_pattern(raw: dict) -> str:
    return "|".join(raw.get(PRAGMAS_ALLOWED, [])) or NOTHING


def language_patterns(raw: dict, names: list, language: str) -> dict:
    """
    Args:
        raw: Content of comments.yml.
        names: Rule ids and groups a nocheck may name.
        language: ast-grep language the patterns are for.

    Returns:
        `@directive`, the directives a tool of this language reads, a nocheck
        naming a catalogue rule among them; `@positional`, the directives a
        tool reads only at a place in the file, as pattern and position;
        `@starter`, the first line of an exception or parameter doc;
        `@prose-starter`, the starters whose next lines may be prose;
        `@entry`, an indented line, the only kind a section line such as
        `Returns:` carries; and `@pragma-allowed`, the pragmas a repository
        declared allowed, matching nothing without a declaration.
    """
    marker = spellings(raw, "marker")
    sections = "|".join(spellings(raw, "sections"))
    groups = [
        group
        for group in spellings(raw, "directives")
        if "languages" not in group or language in group["languages"]
    ]
    nocheck = f"{marker}\\s*nocheck:\\s*(?:{'|'.join(re.escape(name) for name in names)})\\s+--\\s+\\S.*"
    free = [directive_form(marker, group) for group in groups if "position" not in group]
    headings = spellings(raw, "headings")
    heading = [f"{headings[language]}\\s*#\\s+(?:{sections})\\s*"] if language in headings else []
    prose = [
        f"{marker}\\s*(?:Exception:[\\s\\S]*"
        f"|Param:\\s+\\S+(?:\\s+\\([^)\\n]*\\))?\\s+-\\s+\\S[\\s\\S]*"
        f"|Param\\s+[^\\s:]+:\\s+\\S[\\s\\S]*)",
        *heading,
    ]
    section = f"{marker}\\s*(?:{sections}):\\s*"
    return {
        "@directive": f"^(?:{'|'.join([nocheck, *free])})$",
        "@positional": [
            {"pattern": f"^{directive_form(marker, group)}$", "position": group["position"]}
            for group in groups
            if "position" in group
        ],
        "@starter": f"^(?:{'|'.join([section, *prose])})$",
        "@prose-starter": f"^(?:{'|'.join(prose)})$",
        "@entry": f"^{marker}(?:(?:\\t|[ \\t]{{2,}})\\S[\\s\\S]*|[ \\t]*)$",
        "@pragma-allowed": allowed_pattern(raw),
    }


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
    return marker != "#" or text[:index] in ("", BOM) or text[index - 1].isspace()


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


def idle(name: str | None, ran: set, able: set) -> bool:
    """
    Args:
        name: Rule or group a nocheck that waived nothing names, or None
            for a comment without a nocheck.
        ran: Ids of the rules this run applied to the file.
        able: Ids of every rule with a tool that applies to the file in some
            run, pending rules and every tier included.

    Returns:
        True when every rule of that name that can fire on the file ran,
        which holds trivially when none can; a nocheck naming a rule, or a
        group holding a rule, that is pending or of a tier this run skips is
        never judged.
    """
    if name is None:
        return False
    return all(rule_id in ran for rule_id in able if rule_matches(rule_id, name))


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
