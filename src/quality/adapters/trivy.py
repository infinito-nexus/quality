import json

from quality import QualityError
from quality.adapters.base import Command, all_files, checked_rules
from quality.gate import package_hit, package_name
from quality.ruledata import require


def commands(bound: list, settings: dict, _empty_file) -> list:
    """
    Args:
        bound: The rule with its lockfiles.
        settings: The tool's entry in tools.yml with the paths of this run.
        _empty_file: Unused.

    Returns:
        One command per lockfile, with --debug. It reads the bundle's
        database in place, keeps its cache in memory and never fetches.
    """
    bundle = require(settings, "database", "runtime")
    if bundle is None:
        raise QualityError("trivy needs the vulnerability database: run `quality db update`")
    prefix = [
        "filesystem",
        "--cache-dir",
        str(bundle.trivy_cache()),
        "--cache-backend",
        "memory",
        "--skip-db-update",
        "--skip-java-db-update",
        "--skip-check-update",
        "--skip-vex-repo-update",
        "--offline-scan",
        "--disable-telemetry",
        "--skip-version-check",
        "--no-progress",
        "--debug",
        "--scanners",
        "vuln",
        "--list-all-pkgs",
        "--format",
        "json",
        "--config",
        "",
        "--ignorefile",
        "",
        "--secret-config",
        "",
        "--",
    ]
    return [Command(prefix, [path], bound) for path in all_files(bound)]


def package_lines(result: dict) -> dict:
    return {
        package["Identifier"]["UID"]: package["Locations"][0]["StartLine"]
        for package in result.get("Packages") or []
        if package.get("Locations")
    }


def parse(stdout: bytes, command: Command, _snapshot) -> list:
    """
    Args:
        stdout: trivy's JSON report on one lockfile.
        command: The command naming that lockfile.
        _snapshot: Unused.

    Returns:
        One finding per vulnerable package, on the line declaring it when trivy
        knows it, carrying its name as its registry resolves it, named by the
        package's purl type, and its vulnerability ids. None when only
        security.partial-scan is bound.
    """
    document = json.loads(stdout)
    rules = checked_rules(command)
    if not rules:
        return []
    rule = rules[0]
    path = command.files[0]
    hits = []
    for result in document.get("Results") or []:
        lines = package_lines(result)
        vulnerable = {}
        for vulnerability in result.get("Vulnerabilities") or []:
            identifier = vulnerability["PkgIdentifier"]
            ecosystem = identifier.get("PURL", "").removeprefix("pkg:").split("/", 1)[0]
            package = (identifier["UID"], package_name(ecosystem, vulnerability["PkgName"]))
            vulnerable.setdefault(package, set()).add(vulnerability["VulnerabilityID"])
        hits += [
            package_hit(rule, path, lines.get(uid), name, ids)
            for (uid, name), ids in sorted(vulnerable.items())
        ]
    return hits


def unparsed(result, command: Command, settings: dict, _snapshot) -> list:
    """
    Args:
        result: The finished run of one command.
        command: The command naming one lockfile.
        settings: The tool's entry in tools.yml, whose `parse_errors` are the
            log lines of a lockfile trivy could not parse.
        _snapshot: Unused.

    Returns:
        The lockfile when the log holds such a line.
    """
    markers = settings.get("parse_errors", [])
    return list(command.files) if any(marker.encode() in result.stderr for marker in markers) else []
