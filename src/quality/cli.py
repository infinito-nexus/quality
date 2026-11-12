import argparse
import os
import sys

from quality import QualityError, __version__, printable


def thread_count(text: str) -> int:
    """
    Args:
        text: The --threads value.

    Returns:
        The number of threads each tool may run, from 1 to the host's cores.

    Raises:
        argparse.ArgumentTypeError: The value is not a whole number in that
            range; a larger cap would cap nothing, and Go ignores a
            GOMAXPROCS it cannot parse, so those tools would run uncapped.
    """
    cores = os.cpu_count()
    if not (text.isascii() and text.isdigit()) or int(text) < 1 or (cores is not None and int(text) > cores):
        raise argparse.ArgumentTypeError(f"must be a whole number from 1 to the host's {cores} cores")
    return int(text)


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
    check.add_argument("--threads", metavar="N", type=thread_count)
    database = commands.add_parser("db", allow_abbrev=False)
    actions = database.add_subparsers(dest="action", required=True)
    update = actions.add_parser("update", allow_abbrev=False)
    update.add_argument("--db", metavar="DIR")
    update.add_argument("--rules", metavar="DIR")
    coverage = commands.add_parser("coverage", allow_abbrev=False)
    coverage.add_argument("--json", action="store_true", dest="as_json")
    coverage.add_argument("--rules", metavar="DIR")
    return parser


def selected_mode(args: argparse.Namespace) -> str:
    if args.staged:
        return "staged"
    return "all" if args.whole else "base"


def execute(args: argparse.Namespace) -> int:
    if args.command == "coverage":
        return execute_coverage(args)
    from quality.modes import Options, check, update_database
    from quality.report import exit_code, render_json, render_text

    if args.command == "db":
        print(printable(update_database(args.db, args.rules).note()))
        return 0
    mode = selected_mode(args)
    options = Options(mode, args.base, args.rules, args.db, args.verbose, os.getcwd(), args.threads)
    outcome = check(options)
    print(render_json(outcome) if args.as_json else render_text(outcome))
    return exit_code(outcome)


def execute_coverage(args: argparse.Namespace) -> int:
    import json
    import shutil
    import tempfile
    from pathlib import Path

    from quality.modes import ALL_TIERS, COVERAGE, Options, open_session

    scratch = Path(tempfile.mkdtemp(prefix="quality-")).resolve()
    try:
        session = open_session(Options(COVERAGE, None, args.rules, None, False, os.getcwd(), None), scratch)
        snapshot = session.snapshot(session.repo.index_entries(), "head")
        counted = snapshot.census()
        files = {path: snapshot.kinds_of(path) for path in snapshot.paths()}
        active, pending = session.data.kind_rules(files, ALL_TIERS)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    document = coverage_document(counted, active, pending)
    print(json.dumps(document, indent=2, sort_keys=True) if args.as_json else coverage_text(document))
    return 0


def coverage_document(counted: dict, active: dict, pending: dict) -> dict:
    """
    Args:
        counted: File count per kind present in the index.
        active: Kind to the active rules that run on a file by it.
        pending: Kind to the pending rules that would.

    Returns:
        Per present kind its file count and rules, and the kinds without an
        active rule as gaps.
    """
    kinds = {
        kind: {"files": counted[kind], "rules": active.get(kind, []), "pending": pending.get(kind, [])}
        for kind in sorted(counted)
    }
    return {"kinds": kinds, "gaps": [kind for kind, row in kinds.items() if not row["rules"]]}


def coverage_text(document: dict) -> str:
    lines = []
    for kind, row in document["kinds"].items():
        rules = ", ".join(row["rules"]) if row["rules"] else "no rules"
        pending = f" (pending: {', '.join(row['pending'])})" if row["pending"] else ""
        lines.append(f"{kind} ({row['files']} files): {rules}{pending}")
    gaps = document["gaps"]
    lines.append(f"quality: {len(gaps)} kind(s) without rules: {', '.join(gaps)}")
    return "\n".join(printable(line) for line in lines)


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
