import json
import os
import re
from pathlib import Path

from quality.adapters.base import Command, known_path
from quality.architecture import contract
from quality.gate import code_hit

CONFIG = "quality-depcruise.json"
JAVASCRIPT_KIND = "javascript"
LAYER = "layer"
CYCLE = "cycle"
RULE_IDS = {LAYER: "architecture.layer", CYCLE: "architecture.cycle"}
REGEX_SPECIAL = re.compile(r"([.^$*+?()\[\]{}|\\])")


def commands(bound: list, _settings: dict, _empty_file) -> list:
    """
    Args:
        bound: The architecture rules with .quality/architecture.yml.
        _settings: Unused tool entry.
        _empty_file: Unused.

    Returns:
        One command for every bound rule; operands() stages its input and
        arguments.
    """
    return [Command([], [contract.PATH], bound)]


def path_pattern(paths: tuple) -> str:
    alternatives = "|".join(REGEX_SPECIAL.sub(r"\\\1", path) for path in paths)
    return f"^(?:{alternatives})(?:/|$)"


def configuration(section: contract.Section) -> dict:
    """
    Args:
        section: The javascript section of the contract.

    Returns:
        A dependency-cruiser configuration: every circular dependency under
        the source, and every import a rule forbids, as warnings, so the
        exit code stays 0 and only a failure changes it.
    """
    forbidden = [{"name": CYCLE, "severity": "warn", "from": {}, "to": {"circular": True}}]
    forbidden += [
        {"name": LAYER, "severity": "warn", "from": {"path": path_pattern(importers)}, "to": {"path": path_pattern(imported)}}
        for importers, imported in section.rules
    ]
    return {"forbidden": forbidden, "options": {"doNotFollow": {"path": "node_modules"}}}


def stage(snapshot, section: contract.Section, work: Path) -> None:
    (work / section.source).mkdir(parents=True, exist_ok=True)
    for path in snapshot.paths():
        inside = contract.staged_path(path, section.source) is not None
        if inside and path not in snapshot.links and JAVASCRIPT_KIND in snapshot.kinds_of(path):
            staged = work / path
            staged.parent.mkdir(parents=True, exist_ok=True)
            os.link(snapshot.root / path, staged)


def prepared(section: contract.Section, snapshot, work: Path) -> list:
    """
    Args:
        section: The javascript section of the contract.
        snapshot: Snapshot holding the files.
        work: Working directory dependency-cruiser runs in.

    Returns:
        The arguments of a cruise over the JavaScript files of the source,
        staged under their own paths, with the configuration written here
        instead of one from the target.
    """
    stage(snapshot, section, work)
    (work / CONFIG).write_text(json.dumps(configuration(section)), encoding="utf-8")
    return ["--config", CONFIG, "--output-type", "json", section.source]


operands = contract.operands_for(contract.JAVASCRIPT, prepared)


def member(entry) -> str:
    return entry["name"] if isinstance(entry, dict) else entry


def violation_hit(violation: dict, rules: dict, snapshot):
    """
    Args:
        violation: One entry of the report's summary.
        rules: Bound rule per rule name of the configuration.
        snapshot: Snapshot the files came from.

    Returns:
        A key that is the same for every report of one forbidden import or
        of one cycle, whichever of its modules it starts at, and the finding:
        at the importing file for an import, at the first module by name for
        a cycle.
    """
    name = violation["rule"]["name"]
    if name == LAYER:
        importer, imported = violation["from"], violation["to"]
        key = (LAYER, importer, imported)
        return key, code_hit(rules[name], known_path(importer, snapshot), None, f"{importer} -> {imported}", snapshot)
    members = sorted({violation["from"], *map(member, violation["cycle"])})
    key = (CYCLE, *members)
    return key, code_hit(rules[CYCLE], known_path(members[0], snapshot), None, " -> ".join(members), snapshot)


def parse(stdout: bytes, command: Command, snapshot) -> list:
    """
    Args:
        stdout: dependency-cruiser's JSON report.
        command: The command that produced it.
        snapshot: Snapshot the files came from.

    Returns:
        One finding per forbidden import and one per import cycle, of the
        rules this run binds.
    """
    if contract.JAVASCRIPT not in contract.read(snapshot):
        return []
    bound = {item.binding.rule.id: item.binding.rule for item in command.bound}
    rules = {name: bound[rule_id] for name, rule_id in RULE_IDS.items() if rule_id in bound}
    found = {}
    for violation in json.loads(stdout)["summary"]["violations"]:
        if RULE_IDS[violation["rule"]["name"]] in bound:
            key, hit = violation_hit(violation, rules, snapshot)
            found.setdefault(key, hit)
    return list(found.values())
