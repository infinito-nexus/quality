import json
import re

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
UNKNOWN = "UNKNOWN"
CVE = re.compile(r"CVE-[0-9]{4}-[0-9]+")
CVSS_FLOORS = ((9.0, "CRITICAL"), (7.0, "HIGH"), (4.0, "MEDIUM"), (0.1, "LOW"))
VERSION_PARTS = re.compile(r"([0-9]+)")
TRIVY_FIX_SEPARATOR = ","


def natural(version: str) -> list:
    return [(int(part), "") if part.isdigit() else (-1, part) for part in VERSION_PARTS.split(version)]


def highest(versions: list) -> str:
    """
    Args:
        versions: Fixed-in versions, empty for none.

    Returns:
        The highest by natural order, or "" when every one is empty.
    """
    present = [version for version in versions if version]
    return max(present, key=natural) if present else ""


def rank(severity: str) -> int:
    return SEVERITIES.index(severity) if severity in SEVERITIES else len(SEVERITIES)


def graver(known: str, reported: str) -> str:
    return reported if rank(reported) < rank(known) else known


def canonical(identifier: str, aliases: list) -> str:
    """
    Args:
        identifier: The engine's vulnerability id, such as DEBIAN-CVE-2024-1 or GHSA-x.
        aliases: Further ids the engine names for it.

    Returns:
        The first CVE id among them, so both engines' ids of one CVE join;
        the identifier itself when none is a CVE.
    """
    for name in [identifier, *aliases]:
        found = CVE.search(name)
        if found:
            return found.group(0)
    return identifier


def cvss_severity(score: str) -> str:
    try:
        value = float(score)
    except (TypeError, ValueError):
        return UNKNOWN
    return next((severity for floor, severity in CVSS_FLOORS if value >= floor), UNKNOWN)


def trivy_rows(stdout: bytes) -> list:
    """
    Args:
        stdout: `trivy image --format json` output.

    Returns:
        One (package, installed, id, severity, fixed) per reported vulnerability.
    """
    rows = []
    for result in json.loads(stdout).get("Results") or []:
        for item in result.get("Vulnerabilities") or []:
            fixed = highest([part.strip() for part in (item.get("FixedVersion") or "").split(TRIVY_FIX_SEPARATOR)])
            severity = item.get("Severity") if item.get("Severity") in SEVERITIES else UNKNOWN
            identifier = canonical(item["VulnerabilityID"], [])
            rows.append((item["PkgName"], item.get("InstalledVersion") or "", identifier, severity, fixed))
    return rows


def osv_fixed(vulnerability: dict, package: dict) -> str:
    """
    Args:
        vulnerability: One OSV record.
        package: The scanned package with its name and ecosystem.

    Returns:
        The highest `fixed` event of the record's ranges for exactly that
        package and ecosystem, such as Debian:12, or "".
    """
    wanted = (package.get("name"), package.get("ecosystem"))
    matching = [affected for affected in vulnerability.get("affected") or [] if affected_key(affected) == wanted]
    return highest([fixed for affected in matching for fixed in fixed_events(affected)])


def affected_key(affected: dict) -> tuple:
    named = affected.get("package") or {}
    return named.get("name"), named.get("ecosystem")


def fixed_events(affected: dict) -> list:
    return [event.get("fixed") or "" for span in affected.get("ranges") or [] for event in span.get("events") or []]


def package_rows(found: dict) -> list:
    """
    Args:
        found: One package entry of osv-scanner's JSON with its groups and
            vulnerabilities.

    Returns:
        One (package, installed, id, severity, fixed) per vulnerability, its
        severity from its group's highest CVSS score.
    """
    package = found["package"]
    scores = {name: group.get("max_severity") for group in found.get("groups") or [] for name in group["ids"]}
    rows = []
    for vulnerability in found.get("vulnerabilities") or []:
        aliases = [*(vulnerability.get("aliases") or []), *(vulnerability.get("upstream") or [])]
        identifier = canonical(vulnerability["id"], aliases)
        severity = cvss_severity(scores.get(vulnerability["id"]))
        rows.append((package["name"], package.get("version") or "", identifier, severity, osv_fixed(vulnerability, package)))
    return rows


def osv_rows(stdout: bytes) -> list:
    """
    Args:
        stdout: `osv-scanner scan image --format json` output.

    Returns:
        One (package, installed, id, severity, fixed) per reported vulnerability.
    """
    results = json.loads(stdout).get("results") or []
    return [row for result in results for found in result.get("packages") or [] for row in package_rows(found)]
