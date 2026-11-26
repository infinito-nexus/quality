import hashlib
import shutil
import tempfile
from dataclasses import replace
from pathlib import Path

from quality import QualityError, __version__
from quality.modes import FAST, Options, check, check_base, open_session, tier_of
from quality.report import architecture_of, legal_of, public_finding
from quality.ruledata import RuleData

from . import ledger
from .document import Result, failed, skipped
from .options import ALL, BASE, RANGE, STAGED, Request
from .target import Change, PinnedRepo, blob_text, finding_blobs

QUALITY = "quality"
DEEP = "quality-deep"
LEGAL = "legal"
ARCHITECTURE = "architecture"
LENSES = (QUALITY, LEGAL, ARCHITECTURE)
LEDGER_LENSES = (LEGAL, ARCHITECTURE)
CHECK_MODES = {STAGED: "staged", ALL: "all", BASE: "base", RANGE: "base"}
DATABASE_NOTE = "vulnerability database:"
UNCHECKED_MARK = "~"
DIGEST_LENGTH = 16
STAGED_DEEP = "quality check --staged runs the fast tier only"
NO_DATABASE = "the deep tier needs a vulnerability database: pass --db <dir>"


def rules_digest(directory: Path) -> str:
    """
    Args:
        directory: The rule data quality check reads.

    Returns:
        The leading DIGEST_LENGTH hex digits of one sha256 over the path and
        content of every rule file, the rule-set version.
    """
    digest = hashlib.sha256()
    for path in sorted(directory.rglob("*.yml")):
        digest.update(path.relative_to(directory).as_posix().encode() + b"\0" + path.read_bytes() + b"\0")
    return digest.hexdigest()[:DIGEST_LENGTH]


def deep_reason(request: Request) -> str | None:
    if request.mode == STAGED:
        return STAGED_DEEP
    return NO_DATABASE if request.db is None else None


def options_of(request: Request, change: Change, data: RuleData, deep: bool) -> Options:
    """
    Args:
        request: The parsed command line.
        change: The reviewed change.
        data: The packaged rule data.
        deep: True to run the deep tier too.

    Returns:
        The options of `quality check`: --base and --range check from the
        merge base, and without the deep tier a diff or --all run selects the
        fast tier's rules, so it needs no database.
    """
    fast = None if deep or request.mode == STAGED else [rule.id for rule in data.rules if tier_of(rule) == FAST]
    return Options(CHECK_MODES[request.mode], change.base, None, request.db, False, change.repo.root, None, fast)


def outcome_of(options: Options, pin: str | None):
    """
    Args:
        options: The options of `quality check`.
        pin: The end of a --range, or None.

    Returns:
        The outcome of `quality check`, for a --range that of `--base` with
        HEAD pinned to the range end.
    """
    if pin is None:
        return check(options)
    scratch = Path(tempfile.mkdtemp(prefix="quality-review-")).resolve()
    try:
        session = open_session(options, scratch)
        moved = replace(session, repo=PinnedRepo(session.repo, pin))
        outcome = check_base(moved, options)
        return replace(outcome, notes=[*outcome.notes, *moved.notes])
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def lens_of(rule) -> str:
    if rule.legal:
        return LEGAL
    return ARCHITECTURE if rule.architecture else QUALITY


def message_of(item: dict) -> str:
    value = "" if item["value"] is None else f" (value {item['value']})"
    principle = "" if item["lens"] is None else f" (principle {item['lens']})"
    return f"{item['summary']}{value}{principle}"


def finding_of(hit, blobs: dict) -> dict:
    """
    Args:
        hit: Internal finding of quality check.
        blobs: (path, commit) to blob hash.

    Returns:
        The review finding; its message is the rule's summary, never the
        tool's text, which may quote a secret.
    """
    item = public_finding(hit)
    return {
        "lens": lens_of(hit.rule),
        "rule": item["rule"],
        "severity": item["severity"],
        "path": item["path"],
        "line": item["line"],
        "message": message_of(item),
        "commit": item["commit"],
        "tier": tier_of(hit.rule),
        "blob": blobs.get((hit.path, hit.commit)),
    }


def accepted_out(change: Change, pairs: list) -> list:
    """
    Args:
        change: The reviewed change.
        pairs: (hit, review finding) of every finding.

    Returns:
        The pairs without the legal and architecture findings a row of the
        shared accepted-findings ledger accepts.
    """
    reviewed = ledger.rows()
    bound = [index for index, (_hit, item) in enumerate(pairs) if item["lens"] in LEDGER_LENSES]
    items = [pairs[index][1] for index in bound]
    flags = ledger.kept(items, ledger_texts(change, items, reviewed), reviewed)
    dropped = {index for index, flag in zip(bound, flags, strict=True) if not flag}
    return [pair for index, pair in enumerate(pairs) if index not in dropped]


def ledger_texts(change: Change, items: list, reviewed: set) -> dict:
    """
    Args:
        change: The reviewed change.
        items: Review findings the ledger binds.
        reviewed: The ledger's rows.

    Returns:
        Path to its text at the target, read only for a finding whose rule
        and path a row names.
    """
    named = ledger.wanted(reviewed)
    oids = {item["path"]: item["blob"] for item in items if (item["rule"], item["path"]) in named and item["blob"]}
    return {path: blob_text(change.repo, oid) for path, oid in oids.items()}


def scores_of(outcome, hits: list) -> dict:
    """
    Args:
        outcome: The outcome of `quality check`.
        hits: Its findings left after --path and the ledger.

    Returns:
        The legal and architecture values of those findings, `~<n>` for a
        legal value with unchecked licences; both None for --all, which has
        no base to ratchet against.
    """
    if outcome.legal is None:
        return {LEGAL: None, ARCHITECTURE: None}
    legal = legal_of(hits, []).score
    return {
        LEGAL: f"{UNCHECKED_MARK}{legal}" if outcome.legal.unchecked else legal,
        ARCHITECTURE: architecture_of(hits),
    }


def version_of(digest: str, outcome, deep: bool) -> str:
    version = f"quality {__version__} rules sha256:{digest}"
    notes = [note for note in outcome.notes if note.startswith(DATABASE_NOTE)] if deep else []
    return "; ".join([version, *notes])


def quality_results(request: Request, change: Change, data: RuleData, rules: Path) -> list:
    """
    Args:
        request: The parsed command line.
        change: The reviewed change.
        data: The packaged rule data.
        rules: Its directory.

    Returns:
        The results of the lenses quality check fills: quality, its deep
        tier, legal and architecture. A failing check is a tool error of
        each; rules it left pending are one of the quality lens.
    """
    reason = deep_reason(request)
    deep = reason is None
    tier = [] if deep else [skipped(DEEP, reason)]
    try:
        outcome = outcome_of(options_of(request, change, data, deep), change.pin)
        pairs = reviewed_pairs(request, change, outcome)
    except QualityError as error:
        return [failed(lens, f"quality check: {error}") for lens in LENSES + ((DEEP,) if deep else ())] + tier
    version = version_of(rules_digest(rules), outcome, deep)
    return lens_results(outcome, pairs, version) + ([Result(DEEP, version, [], {}, None, None)] if deep else tier)


def reviewed_pairs(request: Request, change: Change, outcome) -> list:
    """
    Args:
        request: The parsed command line.
        change: The reviewed change.
        outcome: The outcome of `quality check`.

    Returns:
        (hit, review finding) of every finding inside --path that no row of
        the accepted-findings ledger accepts.
    """
    hits = [hit for hit in outcome.findings if request.covers(hit.path)]
    blobs = finding_blobs(change, hits)
    return accepted_out(change, [(hit, finding_of(hit, blobs)) for hit in hits])


def lens_results(outcome, pairs: list, version: str) -> list:
    """
    Args:
        outcome: The outcome of `quality check`.
        pairs: Its (hit, review finding) pairs left after --path and the ledger.
        version: Version of quality and its rule set.

    Returns:
        The results of the quality, legal and architecture lenses; rules the
        check left pending are a tool error of the quality lens.
    """
    pending = f"pending rules: {', '.join(outcome.incomplete)}" if outcome.incomplete else None
    scores = scores_of(outcome, [hit for hit, _item in pairs])
    grouped = {lens: [item for _hit, item in pairs if item["lens"] == lens] for lens in LENSES}
    return [
        Result(QUALITY, version, grouped[QUALITY], {}, None, pending),
        Result(LEGAL, version, grouped[LEGAL], {LEGAL: scores[LEGAL]}, None, None),
        Result(ARCHITECTURE, version, grouped[ARCHITECTURE], {ARCHITECTURE: scores[ARCHITECTURE]}, None, None),
    ]
