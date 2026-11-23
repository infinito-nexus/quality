import json
import re
import tomllib
from dataclasses import replace
from pathlib import PurePosixPath

from quality.gate import code_hit, package_hit, unread_hit
from quality.legal.dependencies import format_of, read_dependencies
from quality.legal.index import license_of
from quality.legal.spdx import (
    agrees,
    allowed,
    config,
    expression_of,
    license_ids,
    project_license,
)
from quality.ruledata import gitignore_spec, require
from quality.snapshot import textual

UNCHECKED = "unchecked:"
NO_PROJECT = f"{UNCHECKED}project"
NO_DATA = f"{UNCHECKED}data"
NO_EXPRESSION = f"{UNCHECKED}expression"
NO_READER = f"{UNCHECKED}format"
NO_ORIGIN = f"{UNCHECKED}origin"
REASONS = {
    NO_PROJECT: "legal.dependency-license knows no allowlist for the project licence, so the dependency is not checked",
    NO_DATA: "legal.dependency-license has no licence data for this dependency in the bundle",
    NO_EXPRESSION: "legal.dependency-license cannot parse the licence of this dependency",
    NO_READER: "legal.dependency-license reads no dependencies from this file",
    NO_ORIGIN: "legal.foreign-origin knows no allowlist for the project licence or cannot parse the licence it found",
}
FIELD = re.compile(r'^\s*"?license"?\s*[:=]')
TOML_SUFFIX = ".toml"
DEPENDENCY_LICENSE = "dependency-license"


def settings_of(item) -> tuple:
    return item.binding.rule, item.binding.settings, f"enforcer of {item.binding.rule.id}"


def license_declared(item, snapshot, _resources) -> list:
    """
    Args:
        item: Bound rule with its files; settings name the `project` licence
            files and texts, the `manifests` with the key path of their licence
            field, the SPDX `header` pattern and the `header_bytes` it is
            searched in.
        snapshot: Snapshot holding the files.
        _resources: Unused.

    Returns:
        A file-level finding per manifest without a licence file at or above
        it, and one per manifest field or SPDX header naming another licence
        than that file.
    """
    rule, settings, where = settings_of(item)
    project, manifests = require(settings, "project", where), require(settings, "manifests", where)
    hits = []
    for path in item.files:
        found, family = project_license(snapshot, path, project)
        keys = manifests.get(PurePosixPath(path).name)
        if found is None and keys is not None:
            hits.append(code_hit(rule, path, None, "no licence file", snapshot))
        if family is not None:
            ids = require(project["licenses"][family], "ids", f"licence {family}")
            hits += manifest_hits(rule, snapshot, path, keys, ids) + header_hits(rule, snapshot, path, settings, ids)
    return hits


def manifest_hits(rule, snapshot, path: str, keys: list | None, ids: list) -> list:
    declared = None if keys is None else manifest_license(snapshot, path, keys)
    if declared is None or agrees(declared, ids):
        return []
    row = next((row for row, line in enumerate(snapshot.lines(path), 1) if FIELD.match(line)), None)
    return [code_hit(rule, path, row, "", snapshot)]


def manifest_license(snapshot, path: str, keys: list) -> str | None:
    """
    Args:
        snapshot: Snapshot holding the manifest.
        path: The manifest, TOML or JSON by its suffix.
        keys: Key path of its licence field.

    Returns:
        The licence it declares as an SPDX expression, or None without one
        or when it does not parse.
    """
    try:
        text = snapshot.data(path).decode("utf-8")
        value = tomllib.loads(text) if path.endswith(TOML_SUFFIX) else json.loads(text)
    except ValueError:
        return None
    for key in keys:
        value = value.get(key) if isinstance(value, dict) else None
    return expression_of(value.get("text") if isinstance(value, dict) else value)


def header_hits(rule, snapshot, path: str, settings: dict, ids: list) -> list:
    where = f"enforcer of {rule.id}"
    with snapshot.file(path).open("rb") as stream:
        data = textual(stream.read(require(settings, "header_bytes", where)))
    text = "" if data is None else data.decode("utf-8", "replace")
    found = re.search(require(settings, "header", where), text)
    if found is None or agrees(found.group(1), ids):
        return []
    return [code_hit(rule, path, text.count("\n", 0, found.start()) + 1, "", snapshot)]


def vendored_license(item, snapshot, _resources) -> list:
    """
    Args:
        item: Bound rule with its files; settings name the `config` file and
            the `project` licence file names.
        snapshot: Snapshot holding the files.
        _resources: Unused.

    Returns:
        One finding per vendored folder of the config that holds no licence
        file, among those holding a file of this run, or every one when the
        config itself is a file of this run.
    """
    rule, settings, where = settings_of(item)
    name = require(settings, "config", where)
    names = require(require(settings, "project", where), "files", where)
    touched = set(item.files)
    hits = []
    for folder in sorted({entry.strip("/") for entry in config(snapshot, name).get("vendored", [])}):
        changed = name in touched or any(path.startswith(f"{folder}/") for path in touched)
        if changed and not any(f"{folder}/{license_name}" in snapshot.files for license_name in names):
            hits.append(code_hit(rule, folder, None, "", snapshot))
    return hits


def dependency_license(item, snapshot, resources) -> list:
    """
    Args:
        item: Bound rule with its files; settings name the `config` file, the
            `project` licences, the `allow` list per project licence, the
            dependency files it `reads`, their readers per file pattern under
            `formats` and the `exempt` paths of build- and test-only files.
            The patterns stay apart from `files`, so a lockfile over the size
            limit stays an unchecked path of the run instead of a hard
            security.oversized-code finding of the fast tier.
        snapshot: Snapshot holding the files.
        resources: The run's values; `licenses` reads the bundle's licence index.

    Returns:
        A finding per runtime dependency whose licence the allowlist does not
        cover, judged by that licence, and an unchecked finding per dependency
        without licence data or allowlist and per file no reader parses.
    """
    rule, settings, where = settings_of(item)
    repository = config(snapshot, require(settings, "config", where))
    reads = gitignore_spec(require(settings, "reads", where))
    exempt = gitignore_spec(require(settings, "exempt", where))
    hits = []
    for path in item.files:
        if reads.match_file(path) and not exempt.match_file(path):
            allow = allowlist(snapshot, path, settings, repository)
            hits += dependency_hits(rule, snapshot, path, (settings, allow), resources)
    return hits


def allowlist(snapshot, path: str, settings: dict, repository: dict) -> set | None:
    """
    Args:
        snapshot: Snapshot holding the files.
        path: Dependency file.
        settings: The enforcer settings with `project`, the licence `groups`
            and per project licence the groups it `allow`s.
        repository: The repository's config(), whose `allow` and `deny` widen
            and narrow the default.

    Returns:
        The licence ids its project may distribute, or None when the nearest
        licence file is missing or names a licence without a default list.
    """
    where = f"allowlist of {path}"
    family = project_license(snapshot, path, require(settings, "project", where))[1]
    names = require(settings, "allow", where).get(family)
    if names is None:
        return None
    groups = require(settings, "groups", where)
    default = {licence for name in names for licence in require(groups, name, where)}
    return (default | set(repository.get("allow", []))) - set(repository.get("deny", []))


def dependency_hits(rule, snapshot, path: str, judged: tuple, resources: dict) -> list:
    settings, allow = judged
    reader = format_of(path, require(settings, "formats", f"enforcer of {rule.id}"))
    found = None if reader is None else read_dependencies(reader, snapshot, path)
    if found is None:
        return [replace(unread_hit(rule, path), ids=frozenset({NO_READER}))]
    hits = []
    for dependency in found:
        verdict = NO_PROJECT if allow is None else license_verdict(dependency, allow, resources)
        if verdict is not None:
            hits.append(package_hit(rule, path, dependency.row, dependency.name, {verdict}))
    return hits


def license_verdict(dependency, allow: set, resources: dict) -> str | None:
    """
    Args:
        dependency: One runtime dependency.
        allow: Licence ids the project may distribute.
        resources: The run's values with the `licenses` index reader.

    Returns:
        None for an allowed licence, the licence id of a refused one, or the
        unchecked marker of the reason it could not be judged.
    """
    expression = dependency.license or license_of(
        resources["licenses"](), dependency.ecosystem, dependency.name, dependency.version
    )
    if expression is None:
        return NO_DATA
    verdict = allowed(expression, allow)
    if verdict is None:
        return NO_EXPRESSION
    return None if verdict else f"license:{expression}"


def reuse(item, snapshot, _resources) -> list:
    """
    Args:
        item: Bound rule with its files; settings name the `config` file, the
            SPDX `header` and `copyright` tags, the `sidecar` suffix, the
            `licenses_dir` and the `skip` patterns REUSE needs no data for.
        snapshot: Snapshot holding the files.
        _resources: Unused.

    Returns:
        A file-level finding per file without REUSE data, only when the
        repository's config sets `reuse: true`.
    """
    rule, settings, where = settings_of(item)
    if config(snapshot, require(settings, "config", where)).get("reuse") is not True:
        return []
    skip = gitignore_spec(require(settings, "skip", where))
    return [
        code_hit(rule, path, None, "", snapshot)
        for path in item.files
        if not skip.match_file(path) and not reuse_ready(snapshot, path, settings)
    ]


def reuse_ready(snapshot, path: str, settings: dict) -> bool:
    sidecar = f"{path}{settings['sidecar']}"
    data = snapshot.text(sidecar if sidecar in snapshot.files else path)
    text = "" if data is None else data.decode("utf-8", "replace")
    found = re.search(settings["header"], text)
    if found is None or settings["copyright"] not in text:
        return False
    return all(f"{settings['licenses_dir']}/{name}.txt" in snapshot.files for name in license_ids(found.group(1)))


def split_unchecked(hits: list) -> tuple:
    """
    Args:
        hits: Findings of a run, after the differential gate.

    Returns:
        The findings without the unchecked ones, and those.
    """
    return [hit for hit in hits if not unchecked(hit)], [hit for hit in hits if unchecked(hit)]


def unchecked(hit) -> bool:
    return any(marker.startswith(UNCHECKED) for marker in hit.ids)


def unchecked_notes(hits: list) -> list:
    """
    Args:
        hits: The unchecked findings of split_unchecked().

    Returns:
        One note per finding, naming its file and line, never the package,
        ordered by file and line.
    """
    notes = []
    for hit in sorted(hits, key=lambda hit: (hit.path, -1 if hit.line is None else hit.line)):
        where = hit.path if hit.line is None else f"{hit.path}:{hit.line}"
        notes += [f"unchecked: {where}: {REASONS[marker]}" for marker in sorted(hit.ids)]
    return list(dict.fromkeys(notes))


BUILTINS = {
    "license-declared": license_declared,
    "vendored-license": vendored_license,
    DEPENDENCY_LICENSE: dependency_license,
    "reuse": reuse,
}
