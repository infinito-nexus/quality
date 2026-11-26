#!/usr/bin/env kvb-quality-python
"""
Args:
    --repo: git repository whose working tree holds the change.
    --base: git ref the change starts from.
    --json: print the figures as JSON instead of the line.
    --timeout: whole seconds, 1 to CEILING, each medusa scanner may spend on
        one file, handed to medusa as KNOB in place of any the caller set;
        default TIMEOUT.
    --deadline: whole seconds, 1 to CEILING, the whole medusa run may take;
        past it its process group is killed and the run is incomplete;
        default DEADLINE. A STOPS signal the caller does not ignore kills
        that group too, then this process by the same signal.
    accept --repo <root> --rule <rule_id> [--rule ...] --path <repo path> --sha1 <40 hex> [--line <n>] --reason <one line>:
        record reviewed false positives of one line instead, a row per rule;
        --json of a scan prints rule, path, line and sha1 of every finding.
        --line binds the row to that line's neighbourhood and is required
        when the line's text occurs more than once in the file.

Environment:
    AGENTS_COUNCIL_ROOT, XDG_STATE_HOME, HOME: the council root and the
        host-only root, as quality.agent.state resolves them; the council
        root holds the accepted-findings ledger and the scan cache.
    PATH: git, and medusa unless Quality's pinned tool set names one.

Inputs:
    Tool: medusa from Quality's pinned tool set, the pins.json beside the
        quality package, when it names an executable file, else from PATH;
        stderr names the one that ran and where it came from.
    Scan: the regular files `git diff <ref>` names plus untracked ones,
        symlinks left out, copied to a temporary tree and scanned once with
        `medusa scan <tree> --format json -o <dir> --no-cache --workers <w>`,
        w host_workers() also for fewer files, HOME pointing into the
        temporary directory because medusa creates ~/.medusa on start and
        KNOB set to --timeout (a medusa that ignores KNOB keeps its own cap),
        read from `<dir>/medusa-scan-*.json`: a `findings` list whose entries
        carry `severity` (critical, high, medium, low or info), `rule_id`,
        `file` and `line`. medusa skips the SKIPPED suffixes (.mjs, .cjs, any
        case), so such a file is copied under its name with ALIAS (.js)
        appended, again while a path or folder of the change holds that name,
        or under the sha1 of its path with ALIAS when that file name would
        pass NAME_MAX bytes; its findings are fingerprinted from that copy and
        reported and accepted at its repository path. Rules, coverage and not
        covered judge the tree path medusa scans and name the repository path.
    Rules: medusa's own RULES, read without running medusa from the medusa
        package that the interpreter of medusa's shebang (an `env` program
        looked up on PATH) imports with medusa's environment: from
        core/parallel.py the extensions of FILE_SCANNERS, the exact names,
        the name prefixes and suffix, the top-level folders whose markdown it
        takes up and MAX_SCAN_FILE_SIZE; from scanners/base.py
        MAX_RULE_SCAN_LINES; from config.py the default exclude_paths and
        exclude_files. Without all of them no file can be proven covered and
        a diff with files gets no score.
    Path exclusions: medusa drops a path whose part equals or matches a path
        pattern, or that holds a path pattern anywhere inside (env drops
        utils/env/ and environ.py alike), so a copied file they drop moves to
        NEUTRAL/<sha1 of its repository path>/<its name>, or to
        NEUTRAL/<that sha1><its suffix> when its name alone holds a pattern,
        and is reported and accepted at its repository path.
    Not covered: a copied file of a type medusa never scans, one a file
        pattern drops, or one no NEUTRAL path makes medusa take up, is named
        as such and left out of the score and its proof; a diff of such files
        only gets no score.
    Coverage, checked before medusa runs: no scanned file over medusa's
        MAX_SCAN_FILE_SIZE bytes (skipped) or MAX_RULE_SCAN_LINES lines, with
        CR, CRLF and LF as breaks as its scanners read text (regex scan cut).
        Such a file is never covered, on any run, so the scan stops there.
        After the run its report must prove it: its `scan_summary` counts
        every scanned file in `files_scanned` and, as medusa counts each
        file's LF bytes plus one and a skipped file as 0, their sum in
        `lines_scanned`. The run is complete only when medusa also exits 0
        and its output names no FAULT (a scanner error or a timeout: a
        scanner over its per-file timeout, as on a long file or under a fully
        loaded CPU, adds nothing to the report; a directory left unread, both
        printed by medusa's main process) and no SKIP. A SKIP line is a
        second signal only: medusa runs with `python -E`, so its pool workers
        print it into a buffer that dies with them. A TIMED FAULT names
        RERUN, unless core/parallel.py assigns PER_SCANNER_TIMEOUT a plain
        number: medusa then ignores KNOB, and the problem names CAPPED with
        that number when the run lasted at least as long, else ERRED.
    Accepted: one JSON row per reviewed false positive (id, rule, path, sha1
        of the stripped source line, or of the whole file for a finding
        without a line, context: the sha1 of the stripped lines up to REACH
        above and below it when accept got --line, reason, repo, date),
        appended by accept to the ledger <council root>/security-accepted.jsonl
        that quality.agent.state names; a scan reads it and its kept copy
        below the host-only root, <state home>/agents-council. A finding with
        that rule, path, text and context is accepted and leaves the score; a
        row without context accepts it only while no other finding of the
        scan shares its rule, path and text, so one acceptance never hides an
        identical line elsewhere. An edit of the line, its neighbourhood or
        the file brings it back. A row without rule, path and sha1 is a usage
        error.

Outputs:
    `🛡️ security <n> % critical <c> (medusa: <k> findings, <a> accepted in <m> files: <severity> <path>:<line>, ...; not covered: <path>, ...)`,
        c the critical findings, the --critical of score.py, `, <a>
        accepted` only when a is above 0, m the files scanned, the first
        SHOWN locations by severity and `+<rest> more`, the first SHOWN files
        not covered and `+<rest> more` only when there are any. n = SAFE - 50
        * critical - 25 * high - 10 * medium - 2 * low, at least 0. Matched
        values are never printed. --json adds the counts per severity, every
        location with its rule and sha1, the accepted ones and every file not
        covered.
    Cache: the findings of a complete scan, keyed by the sha256 of every
        script of this skill, the resolved medusa binary with its mtime and
        size, PATH, the files not covered, every MEDUSA_* variable handed to
        medusa and the tree path, repository path, mode and content sha256 of
        every copied file, in <council root>/security-cache/<key>.json for
        CACHE_SECONDS. A later scan with the same key reads them instead of
        running medusa; any edit of a scanned file, of medusa or of a script
        misses. The folder is used only when it is a directory of the current
        user that neither group nor others may write, an entry only when it
        is a regular file of the current user.

Exit codes:
    0 security 100, 1 a critical finding, 2 usage error, 3 under 100 without a
    critical finding, 4 medusa missing, its report or RULES unreadable, its
    run incomplete (RERUN, CAPPED, ERRED or past --deadline), a scanned file it never
    covers or a diff of files not covered only: review the diff by hand.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple

from launch import CEILING, DEADLINE, TIMEOUT, Budget, Incomplete, Stopped, medusa
from ledger import accept, accepted, separated
from shelf import shelf
from staging import fail, git
from sweep import scan
from verdict import Result, Uncovered, Unreadable, document, exit_code, summary_line

import quality
from quality.agent import state

DESCRIPTION = "Scan the files a change touches with MEDUSA and fold the findings into one security percentage."
HAND = (
    "review trust boundaries, secrets and injection in the diff by hand, "
    "then pass --security '~<n>' to kvb-quality-score"
)
UNSCORED = 4
PINS = "pins.json"


class Places(NamedTuple):
    """
    Attributes:
        council: the council root of quality.agent.state.
        listing: its accepted-findings ledger.
        pins: the pin manifest of Quality's pinned tool set.
    """

    council: Path
    listing: Path
    pins: Path


def places() -> Places:
    """Returns:
        the state and tool paths of Quality's package.
    """
    council = state.root()
    return Places(council, council / state.ACCEPTED, Path(quality.__file__).with_name(PINS))


def seconds(text: str) -> int:
    if not text.isdecimal() or not 1 <= int(text) <= CEILING:
        raise argparse.ArgumentTypeError(f"want whole seconds from 1 to {CEILING}, got {text!r}")
    return int(text)


def options() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--timeout", type=seconds, default=TIMEOUT)  # nocheck: clean.default-value -- --timeout is optional by contract, TIMEOUT its documented value
    parser.add_argument("--deadline", type=seconds, default=DEADLINE)  # nocheck: clean.default-value -- --deadline is optional by contract, DEADLINE its documented value
    return parser.parse_args()


def repository(repo: str, base: str) -> Path:
    """Returns:
        the top level of the git work tree at repo; exit 2 when repo is no
        directory or base names no commit.
    """
    folder = Path(repo)
    if not folder.is_dir():
        fail(f"{folder} is not a directory")
    root = Path(git(folder, "rev-parse", "--show-toplevel").strip())
    probe = subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", f"{base}^{{commit}}"], cwd=root, capture_output=True, check=False
    )
    if probe.returncode != 0:
        fail(f"unknown ref {base!r}")
    return root


def problem(reason: str, as_json: bool) -> int:
    print(json.dumps({"security": None, "problem": reason}) if as_json else f"🛡️ security – ({reason}: {HAND})")
    return UNSCORED


def main() -> int:
    args = options()
    root = repository(args.repo, args.base)
    found = places()
    reviewed = accepted()
    tool = medusa(found.pins)
    if tool is None:
        return problem("medusa missing", args.json)
    print(f"security: medusa {tool[0]} from {tool[1]}", file=sys.stderr)
    try:
        scanned, every, missed = scan(tool[0], root, args.base, shelf(found.council), Budget(args.timeout, args.deadline))
    except Unreadable as error:
        return problem(f"medusa report unreadable: {error}", args.json)
    except Incomplete as error:
        return problem(f"medusa run incomplete, nothing cached, {error}", args.json)
    except Uncovered as error:
        return problem(f"medusa never covers this diff, nothing cached: {error}", args.json)
    result = Result(scanned, *separated(every, reviewed), missed)
    print(json.dumps(document(result)) if args.json else summary_line(result))
    return exit_code(result.found)


if __name__ == "__main__":
    try:
        sys.exit(accept(sys.argv[2:], places().listing) if sys.argv[1:2] == ["accept"] else main())
    except Stopped as stopped:
        signal.signal(stopped.args[0], signal.SIG_DFL)
        os.kill(os.getpid(), stopped.args[0])
