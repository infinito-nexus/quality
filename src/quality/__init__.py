__version__ = "0.1.0"


class QualityError(Exception):
    pass


def printable(text: str) -> str:
    """
    Args:
        text: Output that may hold a file name or an ignore reason from the target.

    Returns:
        The text with every non-printable character escaped.
    """
    return "".join(
        char if char.isprintable() else char.encode("unicode_escape").decode("ascii")
        for char in text
    )
