import shutil
from dataclasses import dataclass, replace

from quality.ignorefile import split_ignored
from quality.report import unchecked_of


@dataclass(frozen=True, eq=False)
class History:
    found: list
    ignored: list
    unchecked: list
    at_head: set


def history_rule(rule) -> bool:
    return rule.history


def finding_key(hit) -> tuple:
    return (hit.rule.id, hit.path, hit.line)


def history_hits(session, base: str, entries: list, head_blobs: set) -> History:
    """
    Args:
        session: The running check.
        base: Merge base.
        entries: Base side ignore entries.
        head_blobs: Path and object ID of every HEAD entry.

    Returns:
        Findings of the rules marked history over every blob the range adds,
        each carrying its commit SHA. A blob the merge base already holds at
        that path is legacy and skipped, and a merge adds only the blobs it
        resolved itself, never one it took over from either side. The keys of
        findings on blobs still at HEAD are returned in at_head.
    """
    if not session.data.has_history_rules():
        return History([], [], [], set())
    seen = {(entry.path, entry.oid) for entry in session.repo.tree_entries(base)}
    found = []
    unchecked = []
    at_head = set()
    for commit in session.repo.commits(base):
        fresh = [e for e in session.repo.commit_entries(commit) if (e.path, e.oid) not in seen]
        seen.update((entry.path, entry.oid) for entry in fresh)
        scanned = scan_commit(session, commit, fresh, head_blobs)
        found += scanned.found
        unchecked += scanned.unchecked
        at_head |= scanned.at_head
    kept, ignored = split_ignored(found, [], entries)
    return History(kept, ignored, unchecked, at_head)


def scan_commit(session, commit: str, fresh: list, head_blobs: set) -> History:
    snapshot = session.snapshot(fresh, f"history-{commit}")
    hits = session.collect(snapshot, snapshot.paths(), history_rule, False)
    hits += session.oversized(snapshot, snapshot.unchecked) + session.binary_code(snapshot)
    blobs = {entry.path: entry.oid for entry in fresh}
    at_head = {finding_key(hit) for hit in hits if (hit.path, blobs[hit.path]) in head_blobs}
    unchecked = unchecked_of(snapshot, None)
    shutil.rmtree(snapshot.root)
    return History([replace(hit, commit=commit) for hit in hits], [], unchecked, at_head)
