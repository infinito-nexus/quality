import os
from dataclasses import dataclass

from quality import QualityError
from quality.environment import open_repository, validated_path
from quality.process import run
from quality.repo import Repo

from .options import ALL, BASE, RANGE, Request

HEAD = "HEAD"
COMMIT_SUFFIX = "^{commit}"
SPAN = ".."
END_OF_OPTIONS = "--"
PATHS_PER_CALL = 500
DELETED = "deleted"


def pinned(arg: str, commit: str) -> str:
    """
    Args:
        arg: One git argument before `--`.
        commit: The commit HEAD stands for.

    Returns:
        The argument with HEAD, HEAD^{commit} and a trailing ..HEAD naming
        that commit instead.
    """
    if arg == HEAD:
        return commit
    if arg == HEAD + COMMIT_SUFFIX:
        return commit + COMMIT_SUFFIX
    if arg.endswith(SPAN + HEAD):
        return arg[: -len(HEAD)] + commit
    return arg


def pinned_args(args: tuple, commit: str) -> tuple:
    """
    Args:
        args: A git command line without the program.
        commit: The commit HEAD stands for.

    Returns:
        The command line with every revision argument before `--` pinned;
        the paths after it stay as they are, so a file named HEAD stays one.
    """
    cut = args.index(END_OF_OPTIONS) if END_OF_OPTIONS in args else len(args)
    return (*(pinned(arg, commit) for arg in args[:cut]), *args[cut:])


class PinnedRepo(Repo):
    def __init__(self, repo: Repo, commit: str):
        """
        Args:
            repo: The opened repository.
            commit: The commit every HEAD of `quality check --base` names
                instead, the end of a --range.
        """
        super().__init__(repo.root, repo.env, repo.timeout, repo.git)
        self.commit = commit

    def _capture(self, *args: str):
        return super()._capture(*pinned_args(args, self.commit))


@dataclass(frozen=True)
class Change:
    """
    Args:
        repo: The repository, its HEAD pinned to the end of a --range.
        base: The commit the change starts from: the merge base for --base
            and --range, HEAD for --staged; None for --all and an unborn HEAD.
        target: The revision the change ends at, HEAD or the end of a
            --range; None for the index of --staged and --all.
        pin: The end of a --range, or None.
        worktree: True when the working tree holds the change, so a lens
            that reads it sees the target.
    """

    repo: Repo
    base: str | None
    target: str | None
    pin: str | None
    worktree: bool


def commit_of(repo: Repo, ref: str) -> str:
    """
    Args:
        repo: The repository.
        ref: A revision the caller named.

    Returns:
        Its commit.

    Raises:
        QualityError: The ref names no commit.
    """
    result = run(
        [repo.git, "rev-parse", "--quiet", "--verify", "--end-of-options", ref + COMMIT_SUFFIX],
        repo.root,
        repo.env,
        repo.timeout,
    )
    if result.code != 0:
        raise QualityError(f"{ref} does not resolve to a commit")
    return result.stdout.decode("ascii").strip()


def resolve(request: Request, timeout: float) -> Change:
    """
    Args:
        request: The parsed command line.
        timeout: Seconds each git command may take.

    Returns:
        The change the request names.

    Raises:
        QualityError: --repo is no work tree, or a ref resolves to no commit.
    """
    if not os.path.isdir(request.repo):
        raise QualityError(f"--repo {request.repo} is not a directory")
    repo = open_repository(request.repo, timeout, validated_path(os.environ), os.environ)
    if request.mode == RANGE:
        start, end = commit_of(repo, request.ref), commit_of(repo, request.end)
        moved = PinnedRepo(repo, end)
        return Change(moved, moved.merge_base(start), end, end, end == repo.head())
    if request.mode == BASE:
        return Change(repo, repo.merge_base(request.ref), HEAD, None, True)
    if request.mode == ALL:
        return Change(repo, None, None, None, False)
    return Change(repo, repo.head(), None, None, True)


def listed(repo: Repo, command: tuple, paths: list) -> bytes:
    """
    Args:
        repo: The repository.
        command: A git command that takes literal paths after `--`.
        paths: Repository paths, called in chunks of PATHS_PER_CALL.

    Returns:
        The joined output of every chunk.

    Raises:
        QualityError: git failed.
    """
    output = b""
    for start in range(0, len(paths), PATHS_PER_CALL):
        chunk = paths[start : start + PATHS_PER_CALL]
        result = run([repo.git, "--literal-pathspecs", *command, END_OF_OPTIONS, *chunk], repo.root, repo.env, repo.timeout)
        if result.code != 0:
            raise QualityError(f"git {command[0]} failed with exit {result.code}")
        output += result.stdout
    return output


def changed_paths(change: Change) -> set:
    """
    Args:
        change: The reviewed change, one with a base.

    Returns:
        The paths the change adds or modifies between its base and its
        target, the index for --staged.
    """
    if change.target is None:
        changes = change.repo.staged_changes(change.base)
    else:
        changes = change.repo.range_changes(change.base, change.target)
    return {item.path for item in changes if item.status != DELETED}


def kept_blobs(entries: list, paths: set) -> dict:
    return {entry.path: entry.oid for entry in entries if entry.path in paths}


def finding_blobs(change: Change, hits: list) -> dict:
    """
    Args:
        change: The reviewed change.
        hits: Internal findings of quality check.

    Returns:
        (path, commit) to blob hash: at the target, the index for --staged
        and --all, for a finding without a commit, at its commit for a
        history finding; a path the tree does not hold, such as a folder,
        is left out.
    """
    found = target_blobs(change, {hit.path for hit in hits if hit.commit is None})
    for commit in sorted({hit.commit for hit in hits} - {None}):
        found |= commit_blobs(change.repo, commit, hits)
    return found


def target_blobs(change: Change, paths: set) -> dict:
    if not paths:
        return {}
    entries = change.repo.index_entries() if change.target is None else change.repo.tree_entries(change.target)
    return {(path, None): oid for path, oid in kept_blobs(entries, paths).items()}


def commit_blobs(repo: Repo, commit: str, hits: list) -> dict:
    paths = {hit.path for hit in hits if hit.commit == commit}
    return {(path, commit): oid for path, oid in kept_blobs(repo.tree_entries(commit), paths).items()}


def worktree_blobs(repo: Repo, paths: list) -> dict:
    """
    Args:
        repo: The repository.
        paths: Repository paths a lens read from the working tree.

    Returns:
        Path to the blob hash of its working tree content, for every path
        that is a regular file there.
    """
    present = [
        path
        for path in paths
        if os.path.isfile(os.path.join(repo.root, path)) and not os.path.islink(os.path.join(repo.root, path))
    ]
    hashes = listed(repo, ("hash-object",), present).decode("ascii").split()
    return dict(zip(present, hashes, strict=True))


def blob_text(repo: Repo, oid: str) -> str:
    """
    Args:
        repo: The repository.
        oid: A blob hash.

    Returns:
        The blob's content, UTF-8 decoded, undecodable bytes replaced.

    Raises:
        QualityError: git could not read the blob.
    """
    result = run([repo.git, "cat-file", "blob", oid], repo.root, repo.env, repo.timeout)
    if result.code != 0:
        raise QualityError(f"git cat-file failed with exit {result.code}")
    return result.stdout.decode("utf-8", errors="replace")
