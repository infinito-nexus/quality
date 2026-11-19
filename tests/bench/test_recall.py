import json
import subprocess
from pathlib import Path, PurePosixPath

import pytest

from tests.bench.support import CORE_VARIABLE, core_dir
from tests.integration.support import git, git_env, keep_rules, quality, rules_copy

DEFAULT_VALUE = "clean.default-value"
RECALL = 1.0
HITS = Path(__file__).with_name("default-value-hits.json")
REGULAR_MODES = ("100644", "100755")
LANGUAGES = {
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
}


def in_scope(entry: str) -> bool:
    mode, _, rest = entry.partition(" ")
    return mode in REGULAR_MODES and PurePosixPath(rest.partition("\t")[2]).suffix in LANGUAGES


def core_copy(core: Path, destination: Path, commit: str) -> list:
    """
    Args:
        core: Core checkout, only read.
        destination: Directory for a clone that shares core's objects.
        commit: Core commit whose files are copied.

    Returns:
        The shell, Python and JavaScript files of that commit; the clone's
        HEAD, index and work tree hold exactly these.
    """
    common = git(core, "rev-parse", "--path-format=absolute", "--git-common-dir").stdout.strip()
    if git(core, "cat-file", "-e", f"{commit}^{{commit}}", tolerate_failure=True).returncode:
        pytest.fail(f"{CORE_VARIABLE} lacks core commit {commit} of {HITS.name}: run git fetch origin in it")
    git(destination.parent, "clone", "--quiet", "--shared", "--no-checkout", common, str(destination))
    kept = [entry for entry in git(destination, "ls-tree", "-r", "-z", commit).stdout.split("\0") if in_scope(entry)]
    subprocess.run(
        ["git", "update-index", "-z", "--index-info"],
        cwd=destination,
        env=git_env(),
        input="".join(f"{entry}\0" for entry in kept),
        capture_output=True,
        text=True,
        check=True,
    )
    tree = git(destination, "write-tree").stdout.strip()
    head = git(destination, "commit-tree", "-m", "bench", tree).stdout.strip()
    git(destination, "update-ref", "--no-deref", "HEAD", head)
    git(destination, "checkout-index", "--all", "--index")
    return [entry.partition("\t")[2] for entry in kept]


def quality_hits(copy: Path, rules: Path) -> set:
    result = quality(copy, "check", "--all", "--json", "--rules", str(rules))
    assert result.returncode in (0, 1), result.stderr
    document = json.loads(result.stdout)
    named = [*document["findings"], *document["nocheck"]]
    return {(item["path"], item["line"]) for item in named if item["rule"] == DEFAULT_VALUE}


def test_default_value_recall_against_the_frozen_hits_on_core(tmp_path):
    frozen = json.loads(HITS.read_text(encoding="utf-8"))
    copy = tmp_path / "core"
    core_copy(core_dir(), copy, frozen["core"])
    rules = rules_copy(tmp_path / "rules")
    keep_rules(rules, lambda rule: rule["id"] == DEFAULT_VALUE or isinstance(rule["enforcer"], str))
    expected = {(path, line) for path, line in frozen["hits"]}
    found = quality_hits(copy, rules)
    summary = {}
    for language in sorted(set(LANGUAGES.values())):
        wanted = {hit for hit in expected if LANGUAGES[PurePosixPath(hit[0]).suffix] == language}
        summary[language] = (len(wanted & found), len(wanted), sorted(wanted - found)[:10])
    assert all(0 < total and RECALL * total <= hit for hit, total, _missed in summary.values()), summary
