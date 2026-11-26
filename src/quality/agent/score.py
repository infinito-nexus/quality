import argparse

DASH = "-"
NEW = "new"
UNKNOWN = "?"


def percent(text: str) -> float:
    """
    Args:
        text: a command-line value meant as a percentage.

    Returns:
        The value as a float within 0..100; argparse.ArgumentTypeError otherwise.
    """
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a number") from None
    if not 0 <= value <= 100:
        raise argparse.ArgumentTypeError(f"{text!r} is outside 0..100")
    return value
