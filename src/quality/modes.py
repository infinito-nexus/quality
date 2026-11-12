import os
import shutil
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path

from quality import QualityError, db
from quality.adapters import Collector, Runtime, reads_by_name, refuse_inside
from quality.adapters.builtin import (
    changed_folders,
    folder_items,
    prefix_groups,
    tree_children,
)
from quality.gate import baseline_of, code_hit, merge_baselines, new_hits
from quality.history import finding_key, history_hits
from quality.ignorefile import audit_lines, refuse_stale, split_ignored, stale_names
from quality.ignorefile import parse as parse_ignore
from quality.repo import Repo, hardened_env
from quality.report import Outcome, unchecked_of
from quality.ruledata import (
    BINARY_GUARD,
    FOLDER_ITEMS,
    PREFIX_GROUPS,
    SIZE_GUARD,
    RuleData,
    load,
    locate,
)
from quality.snapshot import (
    BINARY,
    Snapshot,
    control_notes,
    materialize,
    refuse_control_names,
)
from quality.suppress import split_nocheck

FAST = "fast"
FAST_TIER = (FAST,)
ALL_TIERS = (FAST, "deep")
MODE_TIERS = {"staged": FAST_TIER, "base": ALL_TIERS, "all": ALL_TIERS}
HEAD_ONLY_NOTE = "HEAD only: history not scanned"


@dataclass(frozen=True)
class Options:
    mode: str
    ref: str | None
    rules: str | None
    db: str | None
    verbose: bool
    cwd: str


def tier_of(rule) -> str:
    return rule.tier or FAST


@dataclass(frozen=True, eq=False)
class Session:
    data: RuleData
    repo: Repo
    collector: Collector
    scratch: Path
    tiers: tuple
    bundle: db.Bundle | None
    notes: list

    def collect(self, snapshot: Snapshot, paths: list, predicate, base_side: bool) -> list:
        """
        Args:
            snapshot: Snapshot holding the files.
            paths: Files to check.
            predicate: Selects the rules of this run among those of the mode's tiers.
            base_side: True for a parent of the differential gate: a failing tool
                leaves that side without its findings, and skipped files are not named.

        Returns:
            All findings, unfiltered. Files a tool skipped on the checked side and
            tools that failed on the base side are added to the notes.
        """
        hits, skipped, failures = self.collector.collect(
            snapshot,
            paths,
            lambda rule: tier_of(rule) in self.tiers and predicate(rule),
            base_side,
        )
        if base_side:
            lines = [f"base side failed, so every finding of that tool counts as new: {failure}" for failure in failures]
        else:
            lines = [f"unchecked: {item.path}: {item.reason}" for item in skipped]
        self.notes.extend(line for line in dict.fromkeys(lines) if line not in self.notes)
        return hits

    def database_notes(self) -> list:
        return [] if self.bundle is None else [self.bundle.note()]

    def changed_only_rules(self) -> set:
        return {rule.id for rule in self.data.rules if rule.changed_only and tier_of(rule) in self.tiers}

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
            One finding per path named like code or like a lockfile a rule of the
            running tiers reads, since a padded file would otherwise pass every
            rule unread.
        """
        return self.unread_code(SIZE_GUARD, snapshot, paths)

    def binary_code(self, snapshot: Snapshot) -> list:
        """
        Args:
            snapshot: Snapshot the secret scanner ran on.

        Returns:
            One finding per path named like code whose content the secret
            scanner skipped as binary, since a magic prefix would otherwise
            let a file pass it unread.
        """
        paths = sorted(path for path, reason in snapshot.unread.items() if reason == BINARY)
        return self.unread_code(BINARY_GUARD, snapshot, paths)

    def unread_code(self, enforcer: str, snapshot: Snapshot, paths: list) -> list:
        rule = self.data.runner_rule(enforcer)
        return [
            code_hit(rule, path, None, "", snapshot)
            for path in paths
            if self.data.kinds.code_name(path) or self.read_by_name(path)
        ]

    def read_by_name(self, path: str) -> bool:
        return any(
            tier_of(binding.rule) in self.tiers and reads_by_name(binding, path)
            for bindings in self.data.bindings().values()
            for binding in bindings
        )

    def structure(self, snapshot: Snapshot, folders: list | None) -> list:
        """
        Args:
            snapshot: Snapshot of a whole tree or index.
            folders: Folders to measure, or None for every folder.

        Returns:
            Folder size and prefix group findings of those folders.
        """
        children = tree_children(snapshot)
        chosen = sorted(children) if folders is None else folders
        return folder_items(self.data.runner_rule(FOLDER_ITEMS), children, chosen) + prefix_groups(
            self.data.runner_rule(PREFIX_GROUPS), children, chosen
        )

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


def tool_environment(path_value: str, home: Path, bundle: db.Bundle | None) -> dict:
    """
    Args:
        path_value: Validated PATH.
        home: Scratch directory every tool gets as HOME and cache.
        bundle: Vulnerability database of the deep tier, or None.

    Returns:
        The only environment tools see: Semgrep without metrics and version
        check, osv-scanner on the bundle, no proxy, so no tool reaches the network.
    """
    env = {
        "PATH": path_value,
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home),
        "XDG_CACHE_HOME": str(home),
        "LC_ALL": "C.UTF-8",
        "PYTHONSAFEPATH": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "RUFF_NO_CACHE": "true",
        "SEMGREP_ENABLE_VERSION_CHECK": "0",
        "SEMGREP_SEND_METRICS": "off",
        "EIO_BACKEND": "posix",
    }
    if bundle is not None:
        env["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"] = str(bundle.osv_cache())
    return env


def needs_database(data: RuleData, tiers: tuple) -> bool:
    return any(
        data.tools.get(tool, {}).get("database")
        and any(tier_of(binding.rule) in tiers for binding in bindings)
        for tool, bindings in data.bindings().items()
    )


def open_database(options: Options, data: RuleData, tiers: tuple) -> db.Bundle | None:
    if not needs_database(data, tiers):
        return None
    return db.open_bundle(
        db.location(options.db, os.environ),
        data.limit("db_max_age_days"),
        datetime.now(timezone.utc),
    )


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
    rules_dir = locate(options.rules)
    data = load(rules_dir)
    path_value = validated_path(os.environ)
    git = shutil.which("git", path=path_value)
    if git is None:
        raise QualityError("missing tool: git")
    refuse_inside(git, "git", enclosing_roots(options.cwd))
    env = hardened_env(path_value, os.environ)
    repo = Repo.open(options.cwd, env, data.limit("git_timeout"), git)
    refuse_inside(git, "git", [Path(repo.root).resolve()])
    tiers = MODE_TIERS[options.mode]
    bundle = open_database(options, data, tiers)
    home = scratch / "home"
    home.mkdir()
    empty_file = scratch / "empty.yaml"
    empty_file.touch()
    empty_json = scratch / "empty.json"
    empty_json.write_text("{}\n", encoding="utf-8")
    resources = {
        "rules_dir": rules_dir.resolve(),
        "database": bundle,
        "work_dir": scratch,
        "empty_json": empty_json,
    }
    runtime = Runtime(
        path_value,
        tool_environment(path_value, home, bundle),
        empty_file,
        Path(repo.root).resolve(),
        options.verbose,
        resources,
    )
    return Session(data, repo, Collector(data, runtime), scratch, tiers, bundle, [])


def update_database(option: str | None, rules: str | None) -> db.Bundle:
    """
    Args:
        option: The --db value, or None for the default location.
        rules: The --rules value, or None for the packaged rule data.

    Returns:
        The fetched bundle; the only network access quality makes.
    """
    data = load(locate(rules))
    return db.update(db.location(option, os.environ), data, validated_path(os.environ), os.environ)


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
    hits = without_changed_only(session.collect(snapshot, paths, soft_rule, True))
    hits += session.structure(snapshot, plan_folders(plan))
    return baseline_of(hits, {old: new for new, old in renames_back.items()})


def without_changed_only(hits: list) -> list:
    return [hit for hit in hits if not hit.rule.changed_only]


def plan_folders(plan: Plan) -> list:
    return changed_folders([path for change in plan.changes for path in (change.path, change.old_path) if path])


def ungated(hit) -> bool:
    return hit.rule.hard or hit.absolute


def judged(session: Session, plan: Plan, notes: list) -> Outcome:
    """
    Args:
        session: The running check.
        plan: Head snapshot, its changes and the parents to compare with.
        notes: Lines the report carries along.

    Returns:
        Hard and unread-file findings absolute, all other findings through the
        differential gate.
    """
    changed = {change.path for change in plan.changes}
    notes = notes + control_notes(plan.head, plan.changes)
    oversize = [path for path in plan.head.unchecked if path in changed]
    hits = session.collect(plan.head, touched_paths(plan), every_rule, False)
    hits += session.oversized(plan.head, oversize) + session.binary_code(plan.head)
    hits += session.structure(plan.head, plan_folders(plan))
    refuse_stale(stale_names(plan.soft_entries, hits, set(touched_paths(plan)), session.changed_only_rules()))
    kept, ignored = split_ignored(hits, plan.soft_entries, plan.hard_entries)
    kept, nocheck = split_nocheck(kept, plan.head)
    findings = [hit for hit in kept if ungated(hit)]
    soft = [hit for hit in kept if not ungated(hit)]
    if soft:
        findings += new_hits(soft, plan_baseline(session, plan))
    return Outcome(findings, ignored, nocheck, unchecked_of(plan.head, changed), notes, [])


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
    refuse_control_names(head.unread)
    hits = session.collect(head, head.paths(), every_rule, False)
    hits += session.oversized(head, head.unchecked) + session.binary_code(head)
    hits += session.structure(head, None)
    entries = parse_ignore(head.ignore_data(), session.data)
    kept, ignored = split_ignored(hits, entries, entries)
    refuse_stale([entry for entry in entries if entry not in ignored])
    findings, nocheck = split_nocheck(without_changed_only(kept), head)
    notes = session.database_notes() + session.pending_notes(ALL_TIERS) + unparsed_notes(kept)
    if session.repo.is_shallow():
        notes.append(HEAD_ONLY_NOTE)
    pending = [rule.id for rule in session.data.pending_rules(ALL_TIERS)]
    return Outcome(findings, ignored, nocheck, unchecked_of(head, None), notes, pending)


def unparsed_notes(kept: list) -> list:
    return [f"parse incomplete: {path}" for path in sorted({hit.path for hit in kept if hit.rule.changed_only})]


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


def check_base(session: Session, options: Options) -> Outcome:
    repo = session.repo
    base = repo.merge_base(options.ref)
    refuse_control_names(path for commit in repo.commits(base) for path in repo.touched_paths(commit))
    changes = repo.range_changes(base, "HEAD")
    head_tree = repo.tree_entries("HEAD")
    head = session.snapshot(head_tree, "head")
    head_entries = parse_ignore(head.ignore_data(), session.data)
    base_entries = base_side_entries(session, base)
    notes = (
        session.database_notes()
        + audit_lines(base_entries, head_entries)
        + session.pending_notes(ALL_TIERS)
    )

    def diff(parent: str) -> list:
        return repo.range_changes(parent, "HEAD")

    plan = Plan(head, changes, [base], diff, head_entries, base_entries)
    outcome = judged(session, plan, notes)
    head_blobs = {(entry.path, entry.oid) for entry in head_tree}
    history = history_hits(session, base, base_entries, head_blobs)
    findings = [hit for hit in outcome.findings if finding_key(hit) not in history.at_head]
    return replace(
        outcome,
        findings=findings + history.found,
        ignored=outcome.ignored + [item for item in history.ignored if item not in outcome.ignored],
        unchecked=sorted({*outcome.unchecked, *history.unchecked}),
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
        outcome = HANDLERS[options.mode](session, options)
        return replace(outcome, notes=[*outcome.notes, *session.notes])
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
