import argparse
from dataclasses import dataclass
from pathlib import PurePosixPath

STAGED = "staged"
BASE = "base"
RANGE = "range"
ALL = "all"
RANGE_SEPARATOR = ".."


@dataclass(frozen=True)
class Request:
    """
    Args:
        repo: The --repo directory.
        mode: STAGED, BASE, RANGE or ALL.
        ref: The --base ref or the start of --range; None otherwise.
        end: The end of --range; None otherwise.
        paths: The --path files, relative to the repository root; empty
            for every file.
        db: The --db directory, or None.
        measure: True with --measure.
        command: The command the performance lens measures, given after
            `--`; empty without --measure.
    """

    repo: str
    mode: str
    ref: str | None
    end: str | None
    paths: tuple
    db: str | None
    measure: bool
    command: tuple

    def covers(self, path: str) -> bool:
        """
        Args:
            path: Repository path of a finding.

        Returns:
            True when no --path is given or the path is one of them.
        """
        return not self.paths or path in self.paths


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="review.py",
        allow_abbrev=False,
        description="Run every measurable check Quality owns on one change and print one JSON.",
    )
    parser.add_argument("--repo", required=True, metavar="ROOT")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--base", metavar="REF")
    mode.add_argument("--staged", action="store_true")
    mode.add_argument("--range", metavar="A..B", dest="span")
    mode.add_argument("--all", action="store_true", dest="whole")
    parser.add_argument("--path", action="append", metavar="FILE", dest="paths")
    parser.add_argument("--db", metavar="DIR")
    parser.add_argument("--measure", action="store_true")
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument("command", nargs="*", metavar="-- COMMAND")
    return parser


def mode_of(args: argparse.Namespace) -> str:
    if args.staged:
        return STAGED
    if args.base is not None:
        return BASE
    return RANGE if args.span is not None else ALL


def split_range(parser: argparse.ArgumentParser, text: str) -> tuple:
    """
    Args:
        parser: Parser that reports a malformed value.
        text: The --range value.

    Returns:
        Start and end ref of `<a>..<b>`; a usage error exits 2 for anything
        else, `<a>...<b>` included.
    """
    start, separator, end = text.partition(RANGE_SEPARATOR)
    if not separator or not start or not end or end.startswith("."):
        parser.error(f"--range wants <a>..<b>, got {text!r}")
    return start, end


def repository_path(parser: argparse.ArgumentParser, text: str) -> str:
    """
    Args:
        parser: Parser that reports a malformed value.
        text: One --path value.

    Returns:
        The path in the form findings name it; a usage error exits 2 for an
        absolute path, one leaving the repository or the root itself.
    """
    path = PurePosixPath(text)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        parser.error(f"--path wants a file relative to the repository root, got {text!r}")
    return path.as_posix()


def parse(argv: list) -> Request:
    """
    Args:
        argv: Arguments without the program name.

    Returns:
        The request. Usage errors exit 2: no mode or two, an unknown option,
        a missing --json, --measure without a command after `--` or a
        command without --measure.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.as_json:
        parser.error("--json is required: review.py prints JSON only")
    if args.measure and not args.command:
        parser.error("--measure needs the command to measure after --")
    if args.command and not args.measure:
        parser.error("a command after -- needs --measure")
    ref, end = (args.base, None) if args.span is None else split_range(parser, args.span)
    paths = tuple(dict.fromkeys(repository_path(parser, text) for text in args.paths or ()))
    return Request(args.repo, mode_of(args), ref, end, paths, args.db, args.measure, tuple(args.command))
