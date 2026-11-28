#!/usr/bin/env kvb-quality-python
from __future__ import annotations

import argparse
import datetime
import fcntl
import json
import re
from pathlib import Path

from staging import fail, git

from quality.agent import ledger as shared

SHA1 = re.compile(r"[0-9a-f]{40}")


def fingerprint(tree: Path, path: str, line: int | None) -> tuple[str | None, str | None]:
    """Returns:
        shared.fingerprint() of the file at tree/path, (None, None) for an
        unreadable file.
    """
    try:
        text = (tree / path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None, None
    return shared.fingerprint(text, line)


def accepted() -> set[shared.Key]:
    """Returns:
        shared.rows(); exit 2 for an unreadable ledger or a row without rule,
        path and sha1.
    """
    try:
        return shared.rows()
    except (ValueError, OSError) as error:
        fail(f"accepted-findings ledger: {error}")


def separated(every: list[dict], reviewed: set[shared.Key]) -> tuple[list[dict], list[dict]]:
    """Returns:
        the findings that count and the ones shared.accepted() lets pass.
    """
    flags = shared.accepted([(f["rule"], f["path"], f["sha1"], f["context"]) for f in every], reviewed)
    return [f for f, flag in zip(every, flags, strict=True) if not flag], [
        f for f, flag in zip(every, flags, strict=True) if flag
    ]


def reviewed_context(parser: argparse.ArgumentParser, root: Path, args: argparse.Namespace) -> str | None:
    """Returns:
        the context sha1 of --line, None without it; a parser error when
        --sha1 is not that line's, or, without --line, when the line's text
        recurs in the file or --sha1 names neither a line nor the whole file.
    """
    if args.line is not None:
        sha1, context = fingerprint(root, args.path, args.line)
        if sha1 != args.sha1:
            parser.error(f"--sha1 is not the sha1 of line {args.line} of {args.path}")
        return context
    try:
        text = (root / args.path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        text = ""
    twins = sum(shared.digest(row.strip()) == args.sha1 for row in text.splitlines())
    if twins > 1:
        parser.error(f"the line occurs {twins} times in {args.path}; name the reviewed one with --line")
    if twins == 0 and shared.digest(text) != args.sha1:
        parser.error(f"--sha1 names no line of {args.path} and is not the sha1 of the whole file")
    return None


def rows_of(args: argparse.Namespace, root: str, context: str | None) -> list[dict]:
    """Returns:
        one ledger row per --rule.
    """
    date = datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds")
    bound = {"context": context} if context else {}
    return [
        {
            "id": shared.digest("\t".join([rule, args.path, args.sha1, *bound.values()])), "rule": rule,
            "path": args.path, "sha1": args.sha1, **bound,
            "reason": args.reason, "repo": root, "date": date,
        }
        for rule in args.rule
    ]


def record(listing: Path, rows: list[dict]) -> None:
    listing.parent.mkdir(parents=True, exist_ok=True)
    with listing.open("a", encoding="utf-8") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        handle.write("".join(json.dumps(row) + "\n" for row in rows))


def accept(argv: list[str], listing: Path) -> int:
    """Args:
        argv: the arguments after `accept`.
        listing: the accepted-findings ledger the rows are appended to.

    Returns:
        0 once the rows are recorded; exit 2 for a usage error.
    """
    parser = argparse.ArgumentParser(prog="security.py accept", description="Record a reviewed false positive.")
    for flag in ("--repo", "--path", "--sha1", "--reason"):
        parser.add_argument(flag, required=True)
    parser.add_argument("--rule", action="append", required=True)
    parser.add_argument("--line", type=int)
    args = parser.parse_args(argv)
    if not SHA1.fullmatch(args.sha1):
        parser.error("--sha1 must be 40 lowercase hex digits")
    if not args.reason.strip() or "\n" in args.reason:
        parser.error("--reason must be one non-empty line")
    root = git(Path(args.repo), "rev-parse", "--show-toplevel").strip()
    context = reviewed_context(parser, Path(root), args)
    record(listing, rows_of(args, root, context))
    print(f"accepted {', '.join(args.rule)} {args.path} ({args.sha1[:12]}) in {listing}")
    return 0
