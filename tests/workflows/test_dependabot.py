import fnmatch
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
MANIFESTS = {
    "pip": ["requirements*.txt", "pyproject.toml"],
    "docker": ["Dockerfile"],
    "docker-compose": ["compose*.yml"],
    "github-actions": [".github/workflows/*.yml"],
}


def tracked() -> list:
    listing = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True)
    return listing.stdout.split()


def present(patterns: list, paths: list) -> bool:
    return any(fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(Path(path).name, pattern) for path in paths for pattern in patterns)


def test_every_manifest_kind_gets_automatic_updates():
    updates = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8"))["updates"]
    configured = {update["package-ecosystem"] for update in updates}
    paths = tracked()
    assert {ecosystem for ecosystem, patterns in MANIFESTS.items() if present(patterns, paths)} <= configured
    assert all(update["schedule"]["interval"] for update in updates)
