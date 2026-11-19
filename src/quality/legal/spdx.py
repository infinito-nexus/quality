import re

import yaml

from quality import QualityError
from quality.ruledata import require

TOKEN = re.compile(r"\(|\)|[^\s()]+")
OPERATORS = {"AND", "OR", "WITH"}
PARENTHESES = {"(", ")"}
CONFIG_LISTS = ("allow", "deny", "vendored")
CONFIG_FLAGS = ("reuse",)


def license_ids(expression: str) -> set:
    """
    Args:
        expression: SPDX licence expression.

    Returns:
        Every licence and exception id it names.
    """
    return {token for token in TOKEN.findall(expression) if token.upper() not in OPERATORS and token not in PARENTHESES}


def expression_of(value) -> str | None:
    """
    Args:
        value: A licence field as a manifest or lockfile holds it.

    Returns:
        One SPDX expression: a list is a choice among its licences, as
        composer records it. None for anything but a non-empty string or a
        non-empty list of strings.
    """
    if isinstance(value, list) and value and all(isinstance(item, str) for item in value):
        return " OR ".join(f"({item})" for item in value)
    return value if isinstance(value, str) and value else None


def agrees(expression: str, ids: list) -> bool:
    return bool(license_ids(expression) & set(ids))


def allowed(expression: str, allow: set) -> bool | None:
    """
    Args:
        expression: SPDX licence expression, such as `MIT OR (GPL-3.0-only AND ISC)`.
        allow: Licence ids that may be distributed with the project.

    Returns:
        True when one choice the expression offers needs only allowed
        licences (an exception after WITH counts as its licence), False when
        none does, None when the expression does not parse.
    """
    try:
        verdict, rest = disjunction(TOKEN.findall(expression), allow)
    except (IndexError, ValueError):
        return None
    return None if rest else verdict


def disjunction(tokens: list, allow: set) -> tuple:
    verdict, tokens = conjunction(tokens, allow)
    while tokens and tokens[0].upper() == "OR":
        right, tokens = conjunction(tokens[1:], allow)
        verdict = verdict or right
    return verdict, tokens


def conjunction(tokens: list, allow: set) -> tuple:
    verdict, tokens = operand(tokens, allow)
    while tokens and tokens[0].upper() == "AND":
        right, tokens = operand(tokens[1:], allow)
        verdict = verdict and right
    return verdict, tokens


def operand(tokens: list, allow: set) -> tuple:
    first, rest = tokens[0], tokens[1:]
    if first == "(":
        verdict, rest = disjunction(rest, allow)
        if rest[0] != ")":
            raise ValueError("unbalanced")
        return verdict, rest[1:]
    if first in PARENTHESES or first.upper() in OPERATORS:
        raise ValueError("no licence id")
    if rest and rest[0].upper() == "WITH":
        rest = rest[2:]
    return first in allow, rest


def nearest_license(snapshot, path: str, names: list) -> str | None:
    """
    Args:
        snapshot: Snapshot holding the files.
        path: File relative to the snapshot root.
        names: File names a licence file goes by, such as LICENSE.

    Returns:
        The licence file in the path's folder or in the nearest folder
        above it, the root included, or None.
    """
    parts = path.split("/")[:-1]
    for depth in range(len(parts), -1, -1):
        folder = "/".join(parts[:depth])
        for name in names:
            candidate = f"{folder}/{name}" if folder else name
            if candidate in snapshot.files:
                return candidate
    return None


def family_of(snapshot, license_path: str, licenses: dict) -> str | None:
    """
    Args:
        snapshot: Snapshot holding the licence file.
        license_path: The licence file.
        licenses: Licence name to its `text` pattern and its SPDX `ids`.

    Returns:
        The first licence whose text pattern the file holds, or None.
    """
    data = snapshot.text(license_path)
    text = "" if data is None else data.decode("utf-8", "replace")
    for family, entry in licenses.items():
        if re.search(require(entry, "text", f"licence {family}"), text):
            return family
    return None


def project_license(snapshot, path: str, project: dict) -> tuple:
    """
    Args:
        snapshot: Snapshot holding the files.
        path: File whose project is asked for.
        project: The `project` settings: licence file `files` and `licenses`.

    Returns:
        (licence file or None, licence name or None) of the nearest licence file.
    """
    found = nearest_license(snapshot, path, require(project, "files", "project settings"))
    if found is None:
        return None, None
    return found, family_of(snapshot, found, require(project, "licenses", "project settings"))


def config(snapshot, name: str) -> dict:
    """
    Args:
        snapshot: Snapshot of one side.
        name: Path of the repository's legal settings, `.quality/legal.yml`.

    Returns:
        Its mapping: `allow` and `deny` (licence ids that widen and narrow the
        project's default allowlist), `vendored` (folders that need a licence
        file) and `reuse` (true opts into REUSE); empty without the file.

    Raises:
        QualityError: The file is a link or over the size limit, is no valid
            YAML, or sets another key or type.
    """
    if name in snapshot.irregular or name in snapshot.unchecked:
        raise QualityError(f"{name} must be a regular file under the size limit")
    if name not in snapshot.files:
        return {}
    try:
        document = yaml.safe_load(snapshot.data(name))
    except yaml.YAMLError:
        raise QualityError(f"{name} is not valid YAML") from None
    document = {} if document is None else document
    if not isinstance(document, dict) or not all(valid_setting(key, value) for key, value in document.items()):
        raise QualityError(f"{name} may only set {', '.join(CONFIG_LISTS)} (lists of strings) and reuse (true or false)")
    return document


def valid_setting(key, value) -> bool:
    if key in CONFIG_FLAGS:
        return type(value) is bool
    return key in CONFIG_LISTS and isinstance(value, list) and all(type(item) is str for item in value)
