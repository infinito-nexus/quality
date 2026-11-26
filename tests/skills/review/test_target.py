import pytest

from tests.skills.review.support import module

target = module("target")

END = "e" * 40


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        (("merge-base", "a" * 40, "HEAD"), ("merge-base", "a" * 40, END)),
        (("rev-parse", "--quiet", "--verify", "HEAD^{commit}"), ("rev-parse", "--quiet", "--verify", f"{END}^{{commit}}")),
        (("rev-list", "--reverse", "base..HEAD", "--"), ("rev-list", "--reverse", f"base..{END}", "--")),
        (("ls-tree", "-r", "-z", "--full-tree", "HEAD"), ("ls-tree", "-r", "-z", "--full-tree", END)),
        (("rev-parse", "--quiet", "--verify", "MERGE_HEAD^{commit}"), ("rev-parse", "--quiet", "--verify", "MERGE_HEAD^{commit}")),
        (("ls-tree", "-z", "HEADER", "--", "x"), ("ls-tree", "-z", "HEADER", "--", "x")),
    ],
    ids=["merge-base", "head-commit", "rev-list-range", "ls-tree", "merge-head-untouched", "other-name-untouched"],
)
def test_revisions_before_the_separator_name_the_range_end(args, expected):
    assert target.pinned_args(args, END) == expected


def test_a_path_named_head_after_the_separator_stays_a_path():
    args = ("--literal-pathspecs", "diff-tree", "-p", "-r", "base", "HEAD", "--", "HEAD", "a..HEAD")
    assert target.pinned_args(args, END) == (
        "--literal-pathspecs",
        "diff-tree",
        "-p",
        "-r",
        "base",
        END,
        "--",
        "HEAD",
        "a..HEAD",
    )
