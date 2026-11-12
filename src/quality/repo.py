import os
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path

from quality import QualityError
from quality.process import kill_group, run

CONFIG_OVERRIDES = (
    ("core.fsmonitor", "false"),
    ("core.hooksPath", os.devnull),
    ("core.attributesFile", os.devnull),
    ("core.excludesFile", os.devnull),
    ("core.sshCommand", "false"),
    ("core.pager", "cat"),
    ("diff.external", ""),
)
PASSED_VARIABLES = (
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_COMMON_DIR",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
)
STATUS_NAMES = {
    "A": "added",
    "M": "modified",
    "D": "deleted",
    "R": "renamed",
    "C": "copied",
    "T": "type",
}
ZERO_MODE = "000000"
COPY_CHUNK = 1 << 20
IGNORE_FILE = ".qualityignore.yml"


@dataclass(frozen=True)
class Entry:
    mode: str
    oid: str
    path: str


@dataclass(frozen=True)
class Change:
    status: str
    path: str
    old_path: str
    mode: str
    oid: str


def hardened_env(path_value: str, inherited: dict, trusted: Path | None) -> dict:
    """
    Args:
        path_value: Validated PATH.
        inherited: The caller's environment; only PASSED_VARIABLES survive it.
        trusted: The one work tree git may open although another user owns
            it, or None for none.

    Returns:
        The only environment git ever sees. It overrides repository config
        able to run commands.
    """
    overrides = list(CONFIG_OVERRIDES)
    if trusted is not None:
        overrides.append(("safe.directory", str(trusted)))
    env = {
        "PATH": path_value,
        "HOME": os.devnull,
        "LC_ALL": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_ALLOW_PROTOCOL": "none",
        "GIT_PAGER": "cat",
        "GIT_CONFIG_COUNT": str(len(overrides)),
    }
    for index, (key, value) in enumerate(overrides):
        env[f"GIT_CONFIG_KEY_{index}"] = key
        env[f"GIT_CONFIG_VALUE_{index}"] = value
    for name in PASSED_VARIABLES:
        if name in inherited:
            env[name] = inherited[name]
    return env


def parse_raw_diff(raw: bytes) -> list:
    """
    Args:
        raw: `git diff-* --raw -z` output, NUL-separated with one or two paths per record.

    Returns:
        Change records. `path` is the new path, or the old one when deleted.
        `old_path` is empty when added.
    """
    tokens = iter(raw.split(b"\0"))
    changes = []
    for header in tokens:
        if not header:
            continue
        old_mode, new_mode, old_oid, new_oid, code = header.decode("ascii").lstrip(":").split(" ")
        letter = code[0]
        first = os.fsdecode(next(tokens))
        second = os.fsdecode(next(tokens)) if letter in "RC" else first
        status = STATUS_NAMES[letter]
        if letter == "M" and old_oid == new_oid and old_mode != new_mode:
            status = "mode"
        old_path = "" if old_mode == ZERO_MODE else first
        changes.append(Change(status, second, old_path, new_mode, new_oid))
    return changes


def parse_combined_diff(raw: bytes) -> list:
    """
    Args:
        raw: `git diff-tree -c --raw -z` output: per record one mode and one
            object ID for each parent and the result, the status, then the path.

    Returns:
        Entry records of the result side, deleted paths left out.
    """
    tokens = iter(raw.split(b"\0"))
    entries = []
    for header in tokens:
        if not header:
            continue
        fields = header.decode("ascii").lstrip(":").split(" ")
        sides = len(fields) // 2
        path = os.fsdecode(next(tokens))
        mode, oid = fields[sides - 1], fields[2 * sides - 1]
        if mode != ZERO_MODE:
            entries.append(Entry(mode, oid, path))
    return entries


def parse_index_listing(raw: bytes) -> list:
    entries = []
    for token in raw.split(b"\0"):
        if token:
            meta, path = token.split(b"\t", 1)
            mode, oid, _stage = meta.decode("ascii").split(" ")
            entries.append(Entry(mode, oid, os.fsdecode(path)))
    return entries


def parse_tree_listing(raw: bytes) -> list:
    entries = []
    for token in raw.split(b"\0"):
        if token:
            meta, path = token.split(b"\t", 1)
            mode, _kind, oid = meta.decode("ascii").split(" ")
            entries.append(Entry(mode, oid, os.fsdecode(path)))
    return entries


class Repo:
    def __init__(self, root: str, env: dict, timeout: float, git: str):
        self.root = root
        self.env = env
        self.timeout = timeout
        self.git = git

    @classmethod
    def open(cls, cwd: str, env: dict, timeout: float, git: str):
        result = run([git, "rev-parse", "--show-toplevel"], cwd, env, timeout)
        if result.code != 0:
            raise QualityError("not inside a git work tree")
        return cls(os.fsdecode(result.stdout.rstrip(b"\n")), env, timeout, git)

    def _capture(self, *args: str):
        return run([self.git, *args], self.root, self.env, self.timeout)

    def _output(self, *args: str) -> bytes:
        result = self._capture(*args)
        if result.code != 0:
            raise QualityError(f"git {args[0]} failed with exit {result.code}")
        return result.stdout

    def head(self) -> str | None:
        result = self._capture("rev-parse", "--quiet", "--verify", "HEAD^{commit}")
        return result.stdout.decode("ascii").strip() if result.code == 0 else None

    def merge_head(self) -> str | None:
        result = self._capture("rev-parse", "--quiet", "--verify", "MERGE_HEAD^{commit}")
        return result.stdout.decode("ascii").strip() if result.code == 0 else None

    def empty_tree(self) -> str:
        result = run(
            [self.git, "hash-object", "-t", "tree", "--stdin"],
            self.root,
            self.env,
            self.timeout,
            b"",
        )
        if result.code != 0:
            raise QualityError("git hash-object failed")
        return result.stdout.decode("ascii").strip()

    def assert_no_conflict(self) -> None:
        if self._output("ls-files", "--unmerged", "-z"):
            raise QualityError("unresolved conflict in the index")

    def is_shallow(self) -> bool:
        return self._output("rev-parse", "--is-shallow-repository").strip() == b"true"

    def index_entries(self) -> list:
        return parse_index_listing(self._output("ls-files", "--stage", "-z"))

    def tree_entries(self, rev: str) -> list:
        return parse_tree_listing(self._output("ls-tree", "-r", "-z", "--full-tree", rev))

    def staged_changes(self, rev: str) -> list:
        raw = self._output(
            "diff-index",
            "--cached",
            "-M",
            "-z",
            "--raw",
            "--no-ext-diff",
            "--no-textconv",
            rev,
            "--",
        )
        return parse_raw_diff(raw)

    def range_changes(self, old: str, new: str) -> list:
        raw = self._output(
            "diff-tree",
            "-r",
            "-M",
            "-z",
            "--raw",
            "--no-ext-diff",
            "--no-textconv",
            old,
            new,
            "--",
        )
        return parse_raw_diff(raw)

    def merge_base(self, ref: str) -> str:
        if self.is_shallow():
            raise QualityError("no merge base: shallow clone, fetch full history for --base")
        resolved = self._capture(
            "rev-parse", "--quiet", "--verify", "--end-of-options", f"{ref}^{{commit}}"
        )
        if resolved.code != 0:
            raise QualityError(f"no merge base: {ref} does not resolve to a commit")
        base = self._capture("merge-base", resolved.stdout.decode("ascii").strip(), "HEAD")
        if base.code != 0:
            raise QualityError(f"no merge base between {ref} and HEAD")
        return base.stdout.decode("ascii").strip()

    def commits(self, base: str) -> list:
        raw = self._output("rev-list", "--reverse", f"{base}..HEAD", "--")
        return raw.decode("ascii").split()

    def commit_entries(self, commit: str) -> list:
        """
        Args:
            commit: One commit.

        Returns:
            Every entry the commit holds in a version none of its parents has;
            for a merge only what it resolved itself, never what it took
            over unchanged from the merged side.
        """
        raw = self._output(
            "diff-tree",
            "--root",
            "--no-commit-id",
            "-r",
            "-c",
            "--no-renames",
            "-z",
            "--raw",
            commit,
            "--",
        )
        return parse_combined_diff(raw)

    def touched_paths(self, commit: str) -> list:
        """
        Args:
            commit: One commit.

        Returns:
            Every path the commit adds, deletes, modifies, or changes the type
            or mode of, both sides of a rename included; for a merge only the
            paths it resolved itself.
        """
        raw = self._output(
            "diff-tree",
            "--root",
            "--no-commit-id",
            "-r",
            "-c",
            "--no-renames",
            "-z",
            "--name-only",
            commit,
            "--",
        )
        return [os.fsdecode(path) for path in raw.split(b"\0") if path]

    def ignore_blob(self, rev: str, limit: int) -> bytes | None:
        entries = parse_tree_listing(self._output("ls-tree", "-z", rev, "--", IGNORE_FILE))
        regular = [entry for entry in entries if entry.mode.startswith("100")]
        if not regular or self.sizes({regular[0].oid})[regular[0].oid] > limit:
            return None
        request = f"{regular[0].oid}\n".encode("ascii")
        result = run(
            [self.git, "cat-file", "--batch"], self.root, self.env, self.timeout, request
        )
        if result.code != 0:
            raise QualityError(f"git cat-file failed with exit {result.code}")
        return result.stdout.split(b"\n", 1)[1].removesuffix(b"\n")

    def sizes(self, oids: set) -> dict:
        """
        Args:
            oids: Object IDs to look up.

        Returns:
            A map of object ID to size in bytes, read without inflating any blob.

        Raises:
            QualityError: An object is missing.
        """
        if not oids:
            return {}
        request = "".join(f"{oid}\n" for oid in sorted(oids)).encode("ascii")
        result = run(
            [self.git, "cat-file", "--batch-check"],
            self.root,
            self.env,
            self.timeout,
            request,
        )
        if result.code != 0:
            raise QualityError(f"git cat-file failed with exit {result.code}")
        found = {}
        for line in result.stdout.decode("ascii").splitlines():
            fields = line.split(" ")
            if len(fields) != 3:
                raise QualityError("git object missing from the repository")
            found[fields[0]] = int(fields[2])
        return found

    def export_blobs(self, targets: dict, request_file: Path) -> None:
        """
        Args:
            targets: Map of object ID to the destination paths of that blob,
                streamed.
            request_file: Scratch file carrying the object IDs to git's stdin.

        Raises:
            QualityError: git failed or ended before delivering every blob.
        """
        request_file.write_text("".join(f"{oid}\n" for oid in targets), encoding="ascii")
        with request_file.open("rb") as stdin:
            proc = subprocess.Popen(
                [self.git, "cat-file", "--batch"],
                cwd=self.root,
                env=self.env,
                stdin=stdin,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        timer = threading.Timer(self.timeout, kill_group, (proc,))
        timer.start()
        try:
            for oid in targets:
                copy_one_blob(proc.stdout, oid, targets[oid])
        finally:
            timer.cancel()
            proc.stdout.close()
            code = proc.wait()
        if code != 0:
            raise QualityError(f"git cat-file ended with exit {code}")


def copy_one_blob(stream, oid: str, destinations: list) -> None:
    fields = stream.readline().decode("ascii", "replace").split(" ")
    if len(fields) != 3 or fields[0] != oid:
        raise QualityError("git cat-file ended before delivering every blob")
    outputs = [create_exclusive(path) for path in destinations]
    try:
        remaining = int(fields[2])
        while remaining:
            chunk = stream.read(min(remaining, COPY_CHUNK))
            if not chunk:
                raise QualityError("git cat-file ended inside a blob")
            remaining -= len(chunk)
            for output in outputs:
                output.write(chunk)
    finally:
        for output in outputs:
            output.close()
    stream.read(1)


def create_exclusive(path: Path):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    return os.fdopen(os.open(path, flags, 0o600), "wb")
