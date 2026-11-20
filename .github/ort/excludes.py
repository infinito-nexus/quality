import json
import sys

RULE = "legal.dependency-license"
REASON = "OTHER"
COMMENT = "Build- or test-only and never distributed: exempt in rules/legal.yml."
UNSUPPORTED = ("[", "\\")


class ExcludeError(Exception):
    pass


def ant_patterns(exempt: str) -> list:
    """
    Args:
        exempt: One gitignore pattern of the exempt list.

    Returns:
        The Ant patterns ORT matches the same paths with: a pattern without a
        slash inside matches at any depth, a trailing slash only directories.
    """
    if exempt.startswith("!") or any(sign in exempt for sign in UNSUPPORTED):
        raise ExcludeError(f"exempt pattern {exempt!r} has no Ant equivalent")
    body = exempt.rstrip("/")
    pattern = body.lstrip("/") if "/" in body else f"**/{body}"
    return [f"{pattern}/**"] if exempt.endswith("/") else [pattern, f"{pattern}/**"]


def ort_config(rules: list) -> str:
    """
    Args:
        rules: The rule list of rules/legal.yml with its anchors resolved.

    Returns:
        An .ort.yml that excludes every path the exempt list of
        legal.dependency-license names.
    """
    found = [rule for rule in rules if rule.get("id") == RULE]
    if len(found) != 1:
        raise ExcludeError(f"rules hold {len(found)} rules {RULE}, expected 1")
    exempt = found[0]["enforcer"]["any"]["exempt"]
    lines = ["excludes:", "  paths:"]
    for pattern in [pattern for entry in exempt for pattern in ant_patterns(entry)]:
        lines += [f"  - pattern: {json.dumps(pattern)}", f"    reason: {REASON}", f"    comment: {json.dumps(COMMENT)}"]
    return "\n".join(lines) + "\n"


def main(argv: list) -> int:
    """
    Args:
        argv: Empty; the rules come as JSON on stdin, as
            `yq -o=json 'explode(.)' rules/legal.yml` prints them.

    Returns:
        0 with the .ort.yml on stdout, 1 on rules without one exempt list or
        an exempt pattern Ant cannot express, 2 on a usage error.
    """
    if argv:
        sys.stderr.write("usage: excludes.py < rules.json > .ort.yml\n")
        return 2
    try:
        config = ort_config(json.load(sys.stdin))
    except (ExcludeError, KeyError, ValueError) as error:
        sys.stderr.write(f"excludes.py: {error}\n")
        return 1
    sys.stdout.write(config)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
