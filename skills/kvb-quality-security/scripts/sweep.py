#!/usr/bin/env kvb-quality-python
from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import NamedTuple

from launch import KNOB, Budget, Incomplete, advice, host_workers, medusa_run
from rulebook import Rules, capped, package, rules, taken
from shelf import keyed, recalled, remember
from staging import changed, copy, oversized, relocated, sized
from verdict import Uncovered, Unreadable, cut, findings, shown, uncovered

DECORATION = " \t!⚠️"


class Job(NamedTuple):
    """
    Attributes:
        medusa: the medusa executable.
        work: the temporary directory holding tree, reports and home.
        env: medusa's environment.
        names: the tree path of every copied file to its repository path.
        sizes: sized() of every file medusa takes up, by repository path.
    """

    medusa: str
    work: Path
    env: dict
    names: dict
    sizes: dict


def prepared(names: dict[str, str], tree: Path, known: Rules | None) -> tuple[dict[str, str], dict, list[str]]:
    """Returns:
        names after relocated(), sized() of every file medusa takes up by its
        repository path and the repository paths of the rest; Uncovered
        without known rules, when medusa takes up none of the files, or for a
        file over medusa's limits, which no run ever covers.
    """
    if known is None:
        raise Uncovered("medusa's own types, exclusions and limits are unreadable from its source")
    names = relocated(names, tree, known)
    sizes = {names[scratch]: size for scratch, size in sized(tree).items() if taken(scratch, known)}
    missed = sorted(set(names.values()) - sizes.keys())
    if not sizes:
        raise Uncovered(f"medusa scans none of its files, not covered: {shown(missed)}")
    over = oversized(sizes, known)
    if over:
        raise Uncovered(over)
    return names, sizes, missed


def ran(job: Job, deadline: int, folder: Path) -> list[dict]:
    """Returns:
        the findings of one medusa run over the job's tree; Unreadable,
        Uncovered or Incomplete when its report proves less than a complete
        run over every file.
    """
    tree, reports = job.work / "tree", job.work / "reports"
    code, out, lasted = medusa_run(
        [job.medusa, "scan", str(tree), "--format", "json", "-o", str(reports), "--no-cache",
         "--workers", str(host_workers())],
        job.work, job.env, deadline,
    )
    try:
        found, summary = findings(reports, tree, job.names)
    except Unreadable as error:
        raise Unreadable(f"{error} (medusa exit {code})") from None
    said = [line.replace(f"{tree}/", "").strip(DECORATION) for line in out.splitlines()]
    never = uncovered(said, summary, job.sizes)
    if never:
        raise Uncovered(never)
    short = cut(code, said, summary, job.sizes)
    if short:
        raise Incomplete(f"{advice(short, capped(folder), lasted)}: {short}")
    return found


def scan(medusa: str, root: Path, base: str, cache: Path | None, budget: Budget) -> tuple[int, list[dict], list[str]]:
    """Returns:
        the count of scanned files, their findings and the repository paths
        of the copied files medusa never takes up; the findings of a complete
        run are cached in cache.
    """
    with tempfile.TemporaryDirectory(prefix="kvb-security-") as scratch:
        work = Path(scratch)
        tree, home = work / "tree", work / "home"
        tree.mkdir()
        home.mkdir()
        names = copy(root, changed(root, base), tree)
        if not names:
            return 0, [], []
        env = {**os.environ, "HOME": str(home), KNOB: str(budget.timeout)}
        folder = package(medusa, work, env)
        names, sizes, missed = prepared(names, tree, rules(folder))
        key = keyed(medusa, tree, names, missed, env)
        hit = recalled(cache, key) if cache else None
        if hit is not None:
            return len(sizes), hit, missed
        found = ran(Job(medusa, work, env, names, sizes), budget.deadline, folder)
        if cache:
            remember(cache, key, found)
        return len(sizes), found, missed
