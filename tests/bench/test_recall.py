import json
import subprocess
import sys
from pathlib import Path, PurePosixPath

from tests.bench.support import core_dir, setting
from tests.integration.support import git, git_env, keep_rules, quality, rules_copy

DEFAULT_VALUE = "clean.default-value"
RECALL = 0.95
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


def core_copy(core: Path, destination: Path) -> list:
    """
    Args:
        core: Core checkout, only read.
        destination: Directory for a clone that shares core's objects.

    Returns:
        The shell, Python and JavaScript files of core's HEAD; the clone's
        HEAD, index and work tree hold exactly these.
    """
    common = git(core, "rev-parse", "--path-format=absolute", "--git-common-dir").stdout.strip()
    head = git(core, "rev-parse", "HEAD").stdout.strip()
    git(destination.parent, "clone", "--quiet", "--shared", "--no-checkout", common, str(destination))
    kept = [entry for entry in git(destination, "ls-tree", "-r", "-z", head).stdout.split("\0") if in_scope(entry)]
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
    commit = git(destination, "commit-tree", "-m", "bench", tree).stdout.strip()
    git(destination, "update-ref", "--no-deref", "HEAD", commit)
    git(destination, "checkout-index", "--all", "--index")
    return [entry.partition("\t")[2] for entry in kept]


def reference_hits(script: str, copy: Path, files: list) -> set:
    argv = [sys.executable, "-I", script, "--repo", str(copy), "--json", *(f"--file={name}" for name in files)]
    result = subprocess.run(argv, cwd=copy, env=git_env(), capture_output=True, text=True, check=False)
    assert result.returncode in (0, 1), result.stderr
    return {(hit["file"], hit["line"]) for hit in json.loads(result.stdout)}


def quality_hits(copy: Path, rules: Path) -> set:
    result = quality(copy, "check", "--all", "--json", "--rules", str(rules))
    assert result.returncode in (0, 1), result.stderr
    document = json.loads(result.stdout)
    named = [*document["findings"], *document["nocheck"]]
    return {(item["path"], item["line"]) for item in named if item["rule"] == DEFAULT_VALUE}


def test_default_value_recall_against_defaults_py_on_core(tmp_path):
    core = core_dir()
    script = setting("QUALITY_DEFAULTS_SCRIPT")
    copy = tmp_path / "core"
    files = core_copy(core, copy)
    rules = rules_copy(tmp_path / "rules")
    keep_rules(rules, lambda rule: rule["id"] == DEFAULT_VALUE or isinstance(rule["enforcer"], str))
    expected = reference_hits(script, copy, files)
    found = quality_hits(copy, rules)
    summary = {}
    for language in sorted(set(LANGUAGES.values())):
        wanted = {hit for hit in expected if LANGUAGES[PurePosixPath(hit[0]).suffix] == language}
        summary[language] = (len(wanted & found), len(wanted), sorted(wanted - found)[:10])
    assert all(0 < total and RECALL * total <= hit for hit, total, _missed in summary.values()), summary
