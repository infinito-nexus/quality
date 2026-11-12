import argparse
import os
import sys

from quality import QualityError, __version__, printable


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="quality", allow_abbrev=False)
    parser.add_argument("--version", action="version", version=f"quality {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check", allow_abbrev=False)
    mode = check.add_mutually_exclusive_group(required=True)
    mode.add_argument("--staged", action="store_true")
    mode.add_argument("--base", metavar="REF")
    mode.add_argument("--all", action="store_true", dest="whole")
    check.add_argument("--json", action="store_true", dest="as_json")
    check.add_argument("--verbose", action="store_true")
    check.add_argument("--rules", metavar="DIR")
    check.add_argument("--db", metavar="DIR")
    database = commands.add_parser("db", allow_abbrev=False)
    actions = database.add_subparsers(dest="action", required=True)
    update = actions.add_parser("update", allow_abbrev=False)
    update.add_argument("--db", metavar="DIR")
    update.add_argument("--rules", metavar="DIR")
    return parser


def selected_mode(args: argparse.Namespace) -> str:
    if args.staged:
        return "staged"
    return "all" if args.whole else "base"


def execute(args: argparse.Namespace) -> int:
    # Exception: these imports stay inside main's try block, because a broken
    # PyYAML raising at import time would exit 1, which reads as findings.
    from quality.modes import Options, check, update_database
    from quality.report import exit_code, render_json, render_text

    if args.command == "db":
        print(printable(update_database(args.db, args.rules).note()))
        return 0
    mode = selected_mode(args)
    options = Options(mode, args.base, args.rules, args.db, args.verbose, os.getcwd())
    outcome = check(options)
    print(render_json(outcome) if args.as_json else render_text(outcome))
    return exit_code(outcome)


def main(argv: list | None = None) -> int:
    """
    Args:
        argv: Arguments without the program name, or None for sys.argv.

    Returns:
        0 without findings, 1 with findings, 2 on usage, configuration or tool errors.
    """
    args = build_parser().parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", errors="backslashreplace")
    try:
        return execute(args)
    except QualityError as error:
        print(f"quality: error: {printable(str(error))}", file=sys.stderr)
    except Exception as error:
        print(f"quality: internal error: {type(error).__name__}", file=sys.stderr)
    return 2
