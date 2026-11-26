from quality import QualityError
from quality.agent import ledger


def rows() -> set:
    """
    Returns:
        ledger.rows(): the shared accepted-findings ledger and its kept copy,
        the two listings security.py reads.

    Raises:
        QualityError: A ledger is unreadable or holds a malformed row.
    """
    try:
        return ledger.rows()
    except ValueError as error:
        raise QualityError(str(error)) from None
    except OSError as error:
        raise QualityError(f"accepted-findings ledger unreadable: {error}") from None


def wanted(reviewed: set) -> set:
    return {(rule, path) for rule, path, _sha1, _context in reviewed}


def kept(findings: list, texts: dict, reviewed: set) -> list:
    """
    Args:
        findings: Review findings of the lenses the ledger binds.
        texts: Path to the text of that file at the target.
        reviewed: The ledger's rows.

    Returns:
        A flag per finding, True when ledger.accepted() finds no row for it.
    """
    keys = [
        (item["rule"], item["path"], *ledger.fingerprint(texts[item["path"]], item["line"]))
        if item["path"] in texts
        else None
        for item in findings
    ]
    return [not flag for flag in ledger.accepted(keys, reviewed)]
