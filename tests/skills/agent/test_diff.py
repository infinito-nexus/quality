import os
import subprocess
from pathlib import Path

import pytest

from quality.agent import diff

GIT_ENV = {
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_AUTHOR_NAME": "Agent Diff",
    "GIT_AUTHOR_EMAIL": "agent-diff@example.invalid",
    "GIT_COMMITTER_NAME": "Agent Diff",
    "GIT_COMMITTER_EMAIL": "agent-diff@example.invalid",
}


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, check=True)
    return result.stdout.strip()


def write(repo: Path, name: str, text: str) -> None:
    path = repo / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def commit(repo: Path, files: dict) -> str:
    """
    Args:
        repo: The fixture repository.
        files: Path to the whole new text of each file the commit writes.

    Returns:
        The commit id.
    """
    for name, text in files.items():
        write(repo, name, text)
    git(repo, "add", "--all")
    git(repo, "commit", "--quiet", "--message", "fixture")
    return git(repo, "rev-parse", "HEAD")


@pytest.fixture
def repo(tmp_path, monkeypatch):
    for name, value in GIT_ENV.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("HOME", str(tmp_path))
    folder = tmp_path / "repo"
    folder.mkdir()
    git(folder, "init", "--quiet")
    return folder


def test_the_working_tree_against_head_counts_replaced_and_appended_lines(repo):
    commit(repo, {"a.py": "one\ntwo\nthree\n"})
    write(repo, "a.py", "one\nTWO\nthree\nfour\n")
    assert diff.added_lines(repo, staged=False, base=None) == {"a.py": {2, 4}}
    assert diff.added_lines(repo, staged=True, base=None) == {}


def test_staged_reads_the_index_and_the_working_tree_reads_both(repo):
    commit(repo, {"a.py": "one\n", "b.py": "x\n"})
    write(repo, "a.py", "one\nstaged\n")
    git(repo, "add", "a.py")
    write(repo, "b.py", "x\nunstaged\n")
    assert diff.added_lines(repo, staged=True, base=None) == {"a.py": {2}}
    assert diff.added_lines(repo, staged=False, base=None) == {"a.py": {2}, "b.py": {2}}


def test_a_base_replaces_head_as_the_side_the_diff_starts_from(repo):
    base = commit(repo, {"a.py": "one\n"})
    commit(repo, {"a.py": "one\ntwo\n"})
    write(repo, "a.py", "one\ntwo\nthree\n")
    assert diff.added_lines(repo, staged=False, base=base) == {"a.py": {2, 3}}
    assert diff.added_lines(repo, staged=True, base=base) == {"a.py": {2}}
    assert diff.added_lines(repo, staged=False, base=None) == {"a.py": {3}}


def test_an_unborn_branch_diffs_its_index_against_the_empty_tree(repo):
    write(repo, "a.py", "one\ntwo\n")
    git(repo, "add", "a.py")
    assert diff.added_lines(repo, staged=True, base=None) == {"a.py": {1, 2}}
    with pytest.raises(diff.DiffError):
        diff.added_lines(repo, staged=False, base=None)


def test_a_rename_reports_only_the_lines_it_changes_under_the_new_name(repo):
    commit(repo, {"old.py": "".join(f"line {number}\n" for number in range(1, 21))})
    git(repo, "mv", "old.py", "new.py")
    write(repo, "new.py", "".join(f"line {number}\n" for number in range(1, 20)) + "changed\n")
    git(repo, "add", "new.py")
    assert diff.added_lines(repo, staged=True, base=None) == {"new.py": {20}}


def test_deleted_and_binary_files_add_no_lines(repo):
    commit(repo, {"gone.py": "one\n", "kept.py": "one\n"})
    (repo / "gone.py").unlink()
    (repo / "blob.bin").write_bytes(b"\x00\x01\x02")
    git(repo, "add", "--all")
    assert diff.added_lines(repo, staged=True, base=None) == {}


def test_a_missing_final_newline_does_not_shift_the_numbers(repo):
    commit(repo, {"a.txt": "a"})
    write(repo, "a.txt", "a\nb")
    assert diff.added_lines(repo, staged=False, base=None) == {"a.txt": {1, 2}}


def test_a_quoted_path_is_reported_decoded(repo):
    commit(repo, {"ä b.py": "one\n"})
    write(repo, "ä b.py", "one\ntwo\n")
    assert diff.added_lines(repo, staged=False, base=None) == {"ä b.py": {2}}


def test_paths_stay_relative_to_the_work_tree_root_from_a_subfolder(repo):
    commit(repo, {"sub/c.py": "one\n", "top.py": "one\n"})
    write(repo, "sub/c.py", "one\ntwo\n")
    write(repo, "top.py", "zero\none\n")
    assert diff.added_lines(repo / "sub", staged=False, base=None) == {"sub/c.py": {2}, "top.py": {1}}


def test_a_base_that_looks_like_an_option_is_refused_before_git_runs(repo, tmp_path):
    commit(repo, {"a.py": "one\n"})
    written = tmp_path / "written"
    with pytest.raises(diff.DiffError):
        diff.added_lines(repo, staged=False, base=f"--output={written}")
    assert not written.exists()


def test_an_unknown_base_is_a_diff_error(repo):
    commit(repo, {"a.py": "one\n"})
    with pytest.raises(diff.DiffError):
        diff.added_lines(repo, staged=False, base="no-such-ref")


def test_a_hunk_header_git_never_prints_drops_its_file():
    text = "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ broken @@\n+x\n"
    assert diff.parse(text) == {}
