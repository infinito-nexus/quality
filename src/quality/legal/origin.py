from dataclasses import dataclass

from quality import QualityError
from quality.gate import code_hit, package_hit
from quality.legal.checks import NO_ORIGIN, allowlist
from quality.legal.spdx import allowed, config, nearest_license
from quality.ruledata import gitignore_spec, require

LICENCE = "licence"
HOLDER = "holder"
REPORTS = (LICENCE, HOLDER)


@dataclass(frozen=True)
class Scan:
    """
    Args:
        licences: Licence detections of one file as (SPDX expression, first line).
        holders: Its copyright holders as (holder, line).
    """

    licences: list
    holders: list


def where_of(binding) -> str:
    return f"enforcer of {binding.rule.id}"


def licence_files(command, snapshot) -> list:
    """
    Args:
        command: The chunk scancode scans.
        snapshot: Snapshot holding its files.

    Returns:
        The nearest licence file of each file of the chunk, whose copyright
        holders are the project's own.
    """
    binding = command.bound[0].binding
    names = require(require(binding.settings, "project", where_of(binding)), "files", where_of(binding))
    return sorted({nearest_license(snapshot, path, names) for path in command.files} - {None})


def origin_hits(command, snapshot, scanned: dict) -> list:
    """
    Args:
        command: The chunk scancode scanned, whose files are judged, never
            other files of the bindings; each binding's settings name
            what it `reports` (licence or holder), the `config` file, the
            `project` licences, the licence `groups` and the groups each
            project licence may `allow`, the `neutral` ids that name no
            licence and the `skip` patterns of the project's own licence texts.
        snapshot: Snapshot holding the files.
        scanned: Path to its Scan; a judged file it lacks raises KeyError.

    Returns:
        For a licence binding, a finding per licence detection the allowlist
        of the file's project licence does not cover, and an unchecked one
        per detection without allowlist or with an expression that does not
        parse. For a holder binding, a finding per copyright holder the
        nearest licence file does not name, in a file whose every detection
        is allowed.
    """
    chunk = set(command.files)
    hits = []
    for item in command.bound:
        binding = item.binding
        settings = binding.settings
        if require(settings, "reports", where_of(binding)) not in REPORTS:
            raise QualityError(f"rule data: {where_of(binding)} reports neither {LICENCE} nor {HOLDER}")
        skip = gitignore_spec(require(settings, "skip", where_of(binding)))
        repository = config(snapshot, require(settings, "config", where_of(binding)))
        for path in item.files:
            if path in chunk and not skip.match_file(path):
                hits += file_hits(binding, snapshot, path, (scanned, repository))
    return hits


def file_hits(binding, snapshot, path: str, context: tuple) -> list:
    scanned, repository = context
    settings = binding.settings
    allow = allowlist(snapshot, path, settings, repository)
    neutral = set(require(settings, "neutral", where_of(binding)))
    judged = [(expression, line, verdict(expression, allow, neutral)) for expression, line in scanned[path].licences]
    if settings["reports"] == LICENCE:
        return [licence_hit(binding.rule, snapshot, path, entry) for entry in judged if entry[2] is not True]
    if any(entry[2] is not True for entry in judged):
        return []
    own = own_holders(snapshot, path, settings, scanned)
    return [
        code_hit(binding.rule, path, line, f"holder:{holder}", snapshot)
        for holder, line in scanned[path].holders
        if holder.casefold() not in own
    ]


def verdict(expression: str, allow: set | None, neutral: set) -> bool | None:
    """
    Args:
        expression: SPDX expression of one licence detection.
        allow: Licence ids the project may distribute, or None without an
            allowlist for its licence.
        neutral: Ids scancode reports for a reference or disclaimer that
            names no licence.

    Returns:
        True when allowed, False when refused, None when it cannot be judged.
    """
    if allow is None:
        return None
    return allowed(expression, allow | neutral)


def licence_hit(rule, snapshot, path: str, entry: tuple):
    expression, line, judged = entry
    if judged is None:
        return package_hit(rule, path, line, expression, {NO_ORIGIN})
    return code_hit(rule, path, line, f"license:{expression}", snapshot)


def own_holders(snapshot, path: str, settings: dict, scanned: dict) -> set:
    """
    Args:
        snapshot: Snapshot holding the files.
        path: A scanned file.
        settings: Enforcer settings naming the `project` licence files.
        scanned: Path to its Scan, the licence files included.

    Returns:
        The casefolded copyright holders of the file's nearest licence file.
    """
    found = nearest_license(snapshot, path, require(settings["project"], "files", "project settings"))
    return {holder.casefold() for holder, _line in scanned[found].holders} if found in scanned else set()
