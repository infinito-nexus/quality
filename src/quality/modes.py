import os
import shutil
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path

from quality import QualityError
from quality.adapters import Collector, Runtime, refuse_inside
from quality.gate import baseline_of, code_hit, merge_baselines, new_hits
from quality.ignorefile import audit_lines, describe, split_ignored
from quality.ignorefile import parse as parse_ignore
from quality.repo import Repo, hardened_env
from quality.report import Outcome
from quality.ruledata import RuleData, load, locate
from quality.snapshot import Snapshot, materialize
from quality.suppress import split_nocheck

FAST_TIER = ("fast",)
ALL_TIERS = ("fast", "deep")
HEAD_ONLY_NOTE = "HEAD only: history not scanned"
SIZE_GUARD = "size-guard"


@dataclass(frozen=True)
class Options:
    mode: str
    ref: str | None
    rules: str | None
    verbose: bool
    cwd: str


@dataclass(frozen=True, eq=False)
class Session:
    data: RuleData
    repo: Repo
    collector: Collector
    scratch: Path

    def snapshot(self, entries: list, label: str) -> Snapshot:
        return materialize(
            self.repo,
            entries,
            self.scratch / label,
            self.data.limit("blob_max_bytes"),
            self.data.kinds,
        )

    def oversized(self, snapshot: Snapshot, paths: list) -> list:
        """
        Args:
            snapshot: Snapshot the paths were left unread in.
            paths: Unchecked paths of this run.

        Returns:
            One finding per path named like code, since a padded file would
            otherwise pass every rule unread.
        """
        rule = self.data.runner_rule(SIZE_GUARD)
        return [
            code_hit(rule, path, None, "", snapshot)
            for path in paths
            if self.data.kinds.code_name(path)
        ]

    def pending_notes(self, tiers: tuple) -> list:
        return [
            f"not checked: {rule.id} needs {', '.join(rule.pending_tools())}"
            for rule in self.data.pending_rules(tiers)
        ]


@dataclass(frozen=True, eq=False)
class Plan:
    head: Snapshot
    changes: list
    parents: list
    diff: Callable
    soft_entries: list
    hard_entries: list


def every_rule(_rule) -> bool:
    return True


def soft_rule(rule) -> bool:
    return not rule.hard


def history_rule(rule) -> bool:
    return rule.history


def validated_path(environ: dict) -> str:
    """
    Args:
        environ: The caller's environment.

    Returns:
        PATH with absolute entries only, so it never resolves a tool relative to the target.

    Raises:
        QualityError: PATH is not set.
    """
    raw = environ.get("PATH")
    if raw is None:
        raise QualityError("environment is missing key 'PATH'")
    return os.pathsep.join(entry for entry in raw.split(os.pathsep) if os.path.isabs(entry))


def tool_environment(path_value: str, home: Path) -> dict:
    return {
        "PATH": path_value,
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home),
        "LC_ALL": "C.UTF-8",
        "PYTHONSAFEPATH": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "RUFF_NO_CACHE": "true",
    }


def enclosing_roots(cwd: str) -> list:
    """
    Args:
        cwd: Directory the check runs in.

    Returns:
        That directory and the nearest ancestor holding `.git`, found without
        git, because git itself must be vetted before it runs.
    """
    start = Path(cwd).resolve()
    marked = [path for path in (start, *start.parents) if (path / ".git").exists()]
    return [start, *marked[:1]]


def open_session(options: Options, scratch: Path) -> Session:
    data = load(locate(options.rules))
    path_value = validated_path(os.environ)
    git = shutil.which("git", path=path_value)
    if git is None:
        raise QualityError("missing tool: git")
    refuse_inside(git, "git", enclosing_roots(options.cwd))
    env = hardened_env(path_value, os.environ)
    repo = Repo.open(options.cwd, env, data.limit("git_timeout"), git)
    refuse_inside(git, "git", [Path(repo.root).resolve()])
    home = scratch / "home"
    home.mkdir()
    empty_file = scratch / "empty.yaml"
    empty_file.touch()
    runtime = Runtime(
        path_value,
        tool_environment(path_value, home),
        empty_file,
        Path(repo.root).resolve(),
        options.verbose,
    )
    return Session(data, repo, Collector(data, runtime), scratch)


def parent_baseline(session: Session, plan: Plan, parent: str, index: int):
    snapshot = session.snapshot(session.repo.tree_entries(parent), f"base-{index}")
    renames_back = {
        change.path: change.old_path for change in plan.diff(parent) if change.status == "renamed"
    }
    wanted = {
        renames_back.get(change.path, change.path)
        for change in plan.changes
        if change.status != "deleted"
    }
    wanted |= {change.old_path for change in plan.changes if change.old_path}
    paths = sorted(path for path in wanted if path in snapshot.files)
    hits = session.collector.collect(snapshot, paths, soft_rule)
    return baseline_of(hits, {old: new for new, old in renames_back.items()})


def judged(session: Session, plan: Plan, notes: list) -> Outcome:
    """
    Args:
        session: The running check.
        plan: Head snapshot, its changes and the parents to compare with.
        notes: Lines the report carries along.

    Returns:
        Hard findings absolute, all other findings through the differential gate.
    """
    changed = {change.path for change in plan.changes}
    unchecked = [path for path in plan.head.unchecked if path in changed]
    hits = session.collector.collect(plan.head, touched_paths(plan), every_rule)
    hits += session.oversized(plan.head, unchecked)
    kept, ignored = split_ignored(hits, plan.soft_entries, plan.hard_entries)
    kept, nocheck = split_nocheck(kept, plan.head)
    findings = [hit for hit in kept if hit.rule.hard]
    soft = [hit for hit in kept if not hit.rule.hard]
    if soft:
        findings += new_hits(soft, plan_baseline(session, plan))
    return Outcome(findings, ignored, nocheck, unchecked, notes, [])


def touched_paths(plan: Plan) -> list:
    return sorted(
        change.path
        for change in plan.changes
        if change.status != "deleted" and change.path in plan.head.files
    )


def plan_baseline(session: Session, plan: Plan):
    return merge_baselines(
        [parent_baseline(session, plan, parent, index) for index, parent in enumerate(plan.parents)]
    )


def check_all(session: Session, _options: Options) -> Outcome:
    head = session.snapshot(session.repo.index_entries(), "head")
    if not head.files and not head.unchecked:
        raise QualityError("--all found zero files in the index")
    hits = session.collector.collect(head, head.paths(), every_rule)
    hits += session.oversized(head, head.unchecked)
    entries = parse_ignore(head.ignore_data(), session.data)
    kept, ignored = split_ignored(hits, entries, entries)
    stale = [entry for entry in entries if entry not in ignored]
    if stale:
        raise QualityError(f"stale .qualityignore.yml entry: {describe(stale[0])}")
    findings, nocheck = split_nocheck(kept, head)
    notes = session.pending_notes(ALL_TIERS)
    if session.repo.is_shallow():
        notes.append(HEAD_ONLY_NOTE)
    pending = [rule.id for rule in session.data.pending_rules(ALL_TIERS)]
    return Outcome(findings, ignored, nocheck, head.unchecked, notes, pending)


def check_staged(session: Session, _options: Options) -> Outcome:
    repo = session.repo
    first_parent = repo.head() or repo.empty_tree()
    changes = repo.staged_changes(first_parent)
    notes = session.pending_notes(FAST_TIER)
    if not changes:
        return Outcome([], [], [], [], notes, [])
    head = session.snapshot(repo.index_entries(), "head")
    merge_head = repo.merge_head()
    parents = [first_parent, merge_head] if merge_head else [first_parent]
    entries = parse_ignore(head.ignore_data(), session.data)
    plan = Plan(head, changes, parents, repo.staged_changes, entries, entries)
    return judged(session, plan, notes)


def base_side_entries(session: Session, base: str) -> list:
    # Exception: a broken file on the base side must not block the pull request
    # fixing it, and an empty list keeps every hard rule enforced.
    try:
        blob = session.repo.ignore_blob(base, session.data.limit("blob_max_bytes"))
        return parse_ignore(blob, session.data)
    except QualityError:
        return []


def history_hits(session: Session, base: str, entries: list) -> tuple:
    """
    Args:
        session: The running check.
        base: Merge base.
        entries: Base side ignore entries.

    Returns:
        Findings of the rules marked history over every commit of the range,
        each carrying its commit SHA, then applied entries and unchecked paths.
    """
    if not session.data.has_history_rules():
        return [], [], []
    seen = set()
    found = []
    unchecked = []
    for commit in session.repo.commits(base):
        fresh = [e for e in session.repo.commit_entries(commit) if (e.path, e.oid) not in seen]
        seen.update((entry.path, entry.oid) for entry in fresh)
        snapshot = session.snapshot(fresh, f"history-{commit}")
        hits = session.collector.collect(snapshot, snapshot.paths(), history_rule)
        hits += session.oversized(snapshot, snapshot.unchecked)
        found += [replace(hit, commit=commit) for hit in hits]
        unchecked += snapshot.unchecked
        shutil.rmtree(snapshot.root)
    kept, ignored = split_ignored(found, [], entries)
    return kept, ignored, unchecked


def check_base(session: Session, options: Options) -> Outcome:
    repo = session.repo
    base = repo.merge_base(options.ref)
    changes = repo.range_changes(base, "HEAD")
    head = session.snapshot(repo.tree_entries("HEAD"), "head")
    head_entries = parse_ignore(head.ignore_data(), session.data)
    base_entries = base_side_entries(session, base)
    notes = audit_lines(base_entries, head_entries) + session.pending_notes(ALL_TIERS)

    def diff(parent: str) -> list:
        return repo.range_changes(parent, "HEAD")

    plan = Plan(head, changes, [base], diff, head_entries, base_entries)
    outcome = judged(session, plan, notes)
    found, ignored, unchecked = history_hits(session, base, base_entries)
    return replace(
        outcome,
        findings=outcome.findings + found,
        ignored=outcome.ignored + [item for item in ignored if item not in outcome.ignored],
        unchecked=sorted({*outcome.unchecked, *unchecked}),
    )


HANDLERS = {"all": check_all, "base": check_base, "staged": check_staged}


def check(options: Options) -> Outcome:
    """
    Args:
        options: Mode and settings from the command line.

    Returns:
        The finished outcome.

    Raises:
        QualityError: Usage, configuration, missing tool or fail-closed abort.
    """
    scratch = Path(tempfile.mkdtemp(prefix="quality-")).resolve()
    try:
        session = open_session(options, scratch)
        session.repo.assert_no_conflict()
        return HANDLERS[options.mode](session, options)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
