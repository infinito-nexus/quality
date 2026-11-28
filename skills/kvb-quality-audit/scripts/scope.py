import os
import stat
import subprocess
from pathlib import Path

TAGS = "v[0-9]*.[0-9]*.[0-9]*"
DOCS = frozenset({".md", ".txt", ".rst", ".png", ".jpg", ".jpeg", ".gif", ".webp"})
BUILD_INPUTS = ("requirements", "constraints", "cmakelists")
INSTRUCTIONS = frozenset({"skill.md", "agents.md", "claude.md", "gemini.md"})
AGENT_DIRS = frozenset({"skills", ".claude", ".agents", ".codex", ".gemini"})
SHARED_WRITE = 0o022
PRIVATE = 0o700


class Usage(Exception):
    pass


def git(root: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise Usage(f"git {' '.join(args)} exited {result.returncode}: {result.stderr.strip()}")
    return result.stdout


def toplevel(repo: str) -> Path:
    return Path(git(Path(repo), "rev-parse", "--show-toplevel").strip())


def maps_root(uid_map: str) -> bool:
    """
    Args:
        uid_map: The text of /proc/self/uid_map.

    Returns:
        True when a range of the map covers uid 0 inside the namespace.
    """
    for row in uid_map.splitlines():
        inside, _, count = (int(field) for field in row.split())
        if inside <= 0 < inside + count:
            return True
    return False


def owners() -> set[int]:
    """
    Returns:
        Root and the caller, plus the overflow uid in a user namespace that
        maps no root: there root's directories show up as that uid.
    """
    trusted = {0, os.getuid()}
    try:
        if not maps_root(Path("/proc/self/uid_map").read_text(encoding="utf-8")):
            trusted.add(int(Path("/proc/sys/kernel/overflowuid").read_text(encoding="utf-8")))
    except OSError:
        pass
    return trusted


def foreign(status: os.stat_result, trusted: set[int]) -> bool:
    shared = status.st_mode & SHARED_WRITE and not status.st_mode & stat.S_ISVTX
    return status.st_uid not in trusted or bool(shared)


def output_dir(root: Path, out: str) -> Path:
    """
    Args:
        root: The target's work tree.
        out: The --out value.

    Returns:
        The directory, created private when missing. A path inside the tree
        must be ignored by git, the directory must belong to the caller and
        be writable by no one else, and every directory above it must belong
        to one of owners() and be sticky or writable by no one else, so no
        other user can swap it once checked.
    """
    folder = Path(out).resolve()
    if folder.is_relative_to(root):
        ignored = subprocess.run(["git", "check-ignore", "-q", "--", str(folder)], cwd=root, check=False)
        if ignored.returncode != 0:
            raise Usage(f"--out {folder} lies in the tracked tree: use /tmp or a git-ignored directory")
    folder.mkdir(mode=PRIVATE, parents=True, exist_ok=True)
    trusted = owners()
    for ancestor in folder.parents:
        if foreign(ancestor.stat(), trusted):
            raise Usage(f"--out {folder} lies under {ancestor}, which another user can change")
    status = folder.stat()
    if status.st_uid != os.getuid() or status.st_mode & SHARED_WRITE:
        raise Usage(f"--out {folder} must belong to you and be writable by no one else")
    return folder


def release_start(root: Path) -> str:
    """
    Returns:
        The newest vX.Y.Z tag on the first-parent line of HEAD: a tag on a
        merged side commit never moves the start past that commit.
    """
    line = set(git(root, "rev-list", "--first-parent", "HEAD").split())
    for tag in git(root, "tag", "--merged", "HEAD", "--list", TAGS, "--sort=-v:refname").split():
        if git(root, "rev-parse", f"{tag}^{{commit}}").strip() in line:
            return tag
    raise Usage("no vX.Y.Z tag lies on the first-parent line of HEAD: pass --range <a>..<b>")


def resolved_range(root: Path, option: str | None) -> tuple[str, str]:
    if option is None:
        start, end = release_start(root), "HEAD"
    else:
        start, separator, end = option.partition("..")
        if not separator or not start or not end:
            raise Usage(f"--range wants <a>..<b>, got {option!r}")
    for ref in (start, end):
        git(root, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")
    return start, end


def changed(root: Path, start: str, end: str) -> list[str]:
    listed_names = git(root, "diff", "--name-only", "--diff-filter=d", "-z", start, end)
    return sorted(name for name in listed_names.split("\0") if name)


def documentation(name: str) -> bool:
    path = Path(name)
    lowered = path.name.lower()
    return (
        path.suffix.lower() in DOCS
        and lowered not in INSTRUCTIONS
        and not lowered.startswith(BUILD_INPUTS)
        and not AGENT_DIRS & {part.lower() for part in path.parts[:-1]}
    )


def docs_only(root: Path, plan: dict) -> bool:
    """
    Args:
        root: The target's work tree.
        plan: The derived plan.

    Returns:
        True when the range has no seed and every added, changed, deleted or
        renamed path is documentation: no build input, no agent instruction
        and nothing under an agent directory.
    """
    if plan["seeds"]:
        return False
    start, end = plan["range"].split("..")
    names = git(root, "diff", "--name-only", "--no-renames", "-z", start, end).split("\0")
    return all(documentation(name) for name in names if name)
