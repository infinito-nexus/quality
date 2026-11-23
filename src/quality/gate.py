import re
from collections import Counter
from dataclasses import dataclass

from quality.ruledata import Rule

PATH_TOKEN = re.compile(r"[^\s`'\"]*/[^\s`'\"]*")
DIGITS = re.compile(r"\d+")
PATH_PLACEHOLDER = "<path>"
PEP_503_SEPARATORS = re.compile(r"[-_.]+")


@dataclass(frozen=True, repr=False, eq=False)
class Hit:
    rule: Rule
    path: str
    line: int | None
    message: str
    source: str
    value: int | None
    entity: str
    commit: str | None
    absolute: bool
    ids: frozenset
    group: tuple


def code_hit(rule: Rule, path: str, row: int | None, message: str, snapshot) -> Hit:
    """
    Args:
        rule: Catalogue rule.
        path: Path relative to the snapshot root.
        row: Line number, ignored for file-level rules.
        message: Tool message; it stays in memory and is never printed.
        snapshot: Snapshot holding the source line of the fingerprint.

    Returns:
        The finding.
    """
    line = None if rule.file_level or row is None else row
    source = "" if line is None else snapshot.source_key(path, line)
    return Hit(rule, path, line, message, source, None, "", None, False, frozenset(), ())


def package_name(ecosystem: str, name: str) -> str:
    """
    Args:
        ecosystem: Ecosystem as osv-scanner names it, or the purl type trivy
            reports, in any case.
        name: Package name as the lockfile spells it.

    Returns:
        The name its registry resolves: PEP 503 for PyPI, lowercase for
        Composer, unchanged where case tells packages apart, as on npm and Go.
    """
    kind = ecosystem.lower()
    if kind == "pypi":
        return PEP_503_SEPARATORS.sub("-", name).lower()
    if kind in ("composer", "packagist"):
        return name.lower()
    return name


def package_hit(rule: Rule, path: str, row: int | None, name: str, ids: set) -> Hit:
    """
    Args:
        rule: Catalogue rule.
        path: Lockfile path relative to the snapshot root.
        row: Line declaring the package, or None.
        name: Package name as package_name() normalised it.
        ids: Vulnerability ids the tool reported for that package.

    Returns:
        A finding the gate judges by its ids: new when the package holds an id
        its lockfile on the base side did not.
    """
    line = None if rule.file_level or row is None else row
    return Hit(rule, path, line, name, "", None, name, None, False, frozenset(ids), ())


def unread_hit(rule: Rule, path: str) -> Hit:
    """
    Args:
        rule: Catalogue rule whose tool could not read the file.
        path: Path relative to the snapshot root.

    Returns:
        A finding the differential gate does not filter.
    """
    return Hit(rule, path, None, "", "", None, "", None, True, frozenset(), ())


def metric_hit(rule: Rule, path: str, row: int | None, value: int, entity: str) -> Hit:
    return Hit(rule, path, row, "", "", value, entity, None, False, frozenset(), ())


def normalise_message(message: str) -> str:
    return DIGITS.sub("0", PATH_TOKEN.sub(PATH_PLACEHOLDER, message))


def fingerprint(hit: Hit) -> tuple:
    return (hit.rule.id, hit.source)


def per_file_key(hit: Hit, path: str) -> tuple:
    return (path, hit.rule.id, normalise_message(hit.message))


def metric_key(hit: Hit, path: str) -> tuple:
    return (hit.rule.id, path, hit.entity)


def package_key(hit: Hit, path: str) -> tuple:
    return (path, hit.rule.id, hit.entity)


@dataclass(frozen=True, repr=False)
class Baseline:
    fingerprints: Counter
    per_class: Counter
    per_file: Counter
    metrics: dict
    packages: dict


def baseline_of(hits: list, renames: dict) -> Baseline:
    """
    Args:
        hits: Findings of that side, unsuppressed.
        renames: Map of base path to head path.

    Returns:
        The multisets, metric values and vulnerability ids per package the
        head side is compared with.
    """
    fingerprints = Counter()
    per_class = Counter()
    per_file = Counter()
    metrics = {}
    packages = {}
    for hit in hits:
        path = renames.get(hit.path, hit.path)  # nocheck: clean.default-value -- a path that was not renamed keeps its name
        if hit.ids:
            packages.setdefault(package_key(hit, path), set()).update(hit.ids)
        elif hit.rule.metric is not None:
            metrics.setdefault(metric_key(hit, path), []).append(hit.value)
        else:
            fingerprints[fingerprint(hit)] += 1
            per_class[class_key(hit, path)] += 1
            per_file[per_file_key(hit, path)] += 1
    for values in metrics.values():
        values.sort(reverse=True)
    return Baseline(fingerprints, per_class, per_file, metrics, packages)


def merge_baselines(baselines: list) -> Baseline:
    """
    Args:
        baselines: One baseline per parent.

    Returns:
        The per-key maximum.
    """
    fingerprints = Counter()
    per_class = Counter()
    per_file = Counter()
    metrics = {}
    packages = {}
    for baseline in baselines:
        fingerprints |= baseline.fingerprints
        per_class |= baseline.per_class
        per_file |= baseline.per_file
        for key, values in baseline.metrics.items():
            metrics[key] = pointwise_maximum(metrics.get(key, []), values)
        for key, ids in baseline.packages.items():
            packages.setdefault(key, set()).update(ids)
    return Baseline(fingerprints, per_class, per_file, metrics, packages)


def pointwise_maximum(left: list, right: list) -> list:
    longer, shorter = (left, right) if len(left) >= len(right) else (right, left)
    return [
        max(value, shorter[index]) if index < len(shorter) else value
        for index, value in enumerate(longer)
    ]


def new_fingerprint_hits(hits: list, baseline: Baseline, added: dict) -> list:
    ordered = sorted(hits, key=lambda hit: (hit.path, hit.line or 0), reverse=True)  # nocheck: clean.default-value -- a finding without a line sorts as line 0
    preferred = sorted(ordered, key=lambda hit: hit.line not in added.get(hit.path, ()))
    classes = Counter(gate_class(hit) for hit in preferred) - baseline.per_class
    favoured = Counter(gate_class(hit) for hit in preferred if hit.line in added.get(hit.path, ())) & classes
    picked = {id(hit) for hit in chosen(preferred, matched_counts((favoured, classes), *rises(hits, baseline)))}
    return [hit for hit in ordered if id(hit) in picked]


def rises(hits: list, baseline: Baseline) -> tuple:
    fingerprint_rise = Counter(fingerprint(hit) for hit in hits)
    fingerprint_rise.subtract(baseline.fingerprints)
    file_rise = Counter(per_file_key(hit, hit.path) for hit in hits)
    file_rise.subtract(baseline.per_file)
    return +fingerprint_rise, +file_rise


def chosen(preferred: list, left: Counter) -> list:
    picked = []
    for hit in preferred:
        if left[gate_class(hit)] > 0:
            left[gate_class(hit)] -= 1
            picked.append(hit)
    return picked


def gate_class(hit: Hit) -> tuple:
    return class_key(hit, hit.path)


def class_key(hit: Hit, path: str) -> tuple:
    return fingerprint(hit), per_file_key(hit, path)


def matched_counts(sizes: tuple, spare_print: Counter, spare_file: Counter) -> Counter:
    """
    Args:
        sizes: Per class, the rise of its count in its file, limited to its
            hits on added lines, then unlimited, both in the order to fill
            the classes.
        spare_print: Rise of each fingerprint; used up in place.
        spare_file: Rise of each per-file key; used up in place.

    Returns:
        Per class how many of its hits are new: at most its rise, and as
        many in total as the fingerprint and per-file rises allow
        together. The classes are first filled in order with
        their hits on added lines, then with the rest, and a class filled
        then gives a hit up only where the total needs it.
    """
    favoured, classes = sizes
    matching = Matching(classes, spare_print, spare_file)
    matching.fill(favoured)
    matching.fill(classes)
    while matching.round():
        continue
    return matching.flow


class Matching:
    def __init__(self, classes: Counter, spare_print: Counter, spare_file: Counter):
        self.classes = classes
        self.spare_print = spare_print
        self.spare_file = spare_file
        self.flow = Counter()
        self.by_print = {}
        self.by_file = {}
        for key in classes:
            self.by_print.setdefault(key[0], []).append(key)
            self.by_file.setdefault(key[1], []).append(key)

    def fill(self, sizes: Counter) -> None:
        for key in self.classes:
            take = min(sizes[key] - self.flow[key], self.spare_print[key[0]], self.spare_file[key[1]])
            self.flow[key] += take
            self.spare_print[key[0]] -= take
            self.spare_file[key[1]] -= take

    def round(self) -> int:
        """
        Returns:
            How many chains one pass over every fingerprint with rise left
            found and applied; nodes the pass visits stay visited for it, so
            a pass costs one walk over the classes and a pass finding none
            proves the total maximal.
        """
        seen = set()
        found = 0
        for start in self.by_print:
            if self.spare_print[start] > 0 and ("print", start) not in seen and (path := self.search(start, seen)):
                self.augment(path)
                found += 1
        return found

    def search(self, start, seen: set) -> list:
        """
        Args:
            start: A fingerprint with rise left.
            seen: Nodes this pass visited; extended in place.

        Returns:
            A chain of classes from it to a per-file key with rise left,
            alternating one class that can take another hit and one that
            gives one up, or an empty list.
        """
        seen.add(("print", start))
        stack = [(start, [])]
        while stack:
            node, path = stack.pop()
            for forward in self.by_print[node]:
                if self.flow[forward] < self.classes[forward] and ("file", forward[1]) not in seen:
                    seen.add(("file", forward[1]))
                    if self.spare_file[forward[1]] > 0:
                        return [*path, forward]
                    stack.extend(self.steps(forward, path, seen))
        return []

    def steps(self, forward: tuple, path: list, seen: set) -> list:
        steps = []
        for backward in self.by_file[forward[1]]:
            if self.flow[backward] > 0 and ("print", backward[0]) not in seen:
                seen.add(("print", backward[0]))
                steps.append((backward[0], [*path, forward, backward]))
        return steps

    def augment(self, path: list) -> None:
        self.spare_print[path[0][0]] -= 1
        self.spare_file[path[-1][1]] -= 1
        for index, key in enumerate(path):
            self.flow[key] += -1 if index % 2 else 1


def new_metric_hits(hits: list, baseline: Baseline) -> list:
    positions = Counter()
    new = []
    for hit in sorted(hits, key=lambda item: item.value, reverse=True):
        key = metric_key(hit, hit.path)
        known = baseline.metrics.get(key, [])
        index = positions[key]
        positions[key] += 1
        if index >= len(known) or hit.value > known[index]:
            new.append(hit)
    return new


def new_hits(hits: list, baseline: Baseline, added: dict) -> list:
    """
    Args:
        hits: Non-hard findings on the head side.
        baseline: Merged baseline of every parent.
        added: Per head-side path the line numbers the change adds.

    Returns:
        Fingerprint findings whose fingerprint count, per-file count and
        count of the same fingerprint and message in their file all rose,
        as many as the rises allow together, findings on added lines
        taken first wherever the total allows the choice, metric findings
        that grew or are new, and package findings with a
        vulnerability id the same lockfile and package lacked on the base side.
    """
    packages = [hit for hit in hits if hit.ids]
    plain = [hit for hit in hits if not hit.ids and hit.rule.metric is None]
    metric = [hit for hit in hits if not hit.ids and hit.rule.metric is not None]
    return (
        new_package_hits(packages, baseline)
        + new_fingerprint_hits(plain, baseline, added)
        + new_metric_hits(metric, baseline)
    )


def new_package_hits(hits: list, baseline: Baseline) -> list:
    return [hit for hit in hits if hit.ids - baseline.packages.get(package_key(hit, hit.path), set())]
