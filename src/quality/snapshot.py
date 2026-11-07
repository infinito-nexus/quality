import re
from dataclasses import dataclass, field
from pathlib import Path

from quality import QualityError
from quality.repo import IGNORE_FILE
from quality.ruledata import KindMap
from quality.suppress import marker_comments, python_comments

REGULAR_MODES = ("100644", "100755", "100664")
LINE_BREAK = re.compile(rb"\r\n|\r|\n")
BLANKS = re.compile(r"\s+")
FIRST_LINE_BYTES = 256
PYTHON_KIND = "python"


def safe_path(path: str) -> str:
    parts = path.split("/")
    unsafe = {"", ".", ".."}
    # Exception: a top-level file named `-` reaches tools after `--`, and ruff,
    # rg and shellcheck then read an empty stdin instead, so it would pass unread.
    hostile = path == "-" or path.startswith("/")
    if hostile or any(p in unsafe or p.lower() == ".git" for p in parts):
        raise QualityError(f"unsafe path in the git tree: {path!r}")
    return path


@dataclass(eq=False)
class Snapshot:
    root: Path
    files: dict
    unchecked: list
    irregular: set
    kind_map: KindMap
    line_cache: dict = field(default_factory=dict)
    comment_cache: dict = field(default_factory=dict)

    def paths(self) -> list:
        return sorted(self.files)

    def data(self, path: str) -> bytes:
        return (self.root / path).read_bytes()

    def lines(self, path: str) -> list:
        if path not in self.line_cache:
            pieces = LINE_BREAK.split(self.data(path))
            if pieces and not pieces[-1]:
                pieces.pop()
            self.line_cache[path] = [piece.decode("utf-8", "replace") for piece in pieces]
        return self.line_cache[path]

    def line_count(self, path: str) -> int:
        data = self.data(path)
        breaks = len(LINE_BREAK.findall(data))
        return breaks if not data or data[-1:] in (b"\n", b"\r") else breaks + 1

    def source_key(self, path: str, row: int) -> str:
        lines = self.lines(path)
        return BLANKS.sub("", lines[row - 1]) if 0 < row <= len(lines) else ""

    def kinds_of(self, path: str) -> frozenset:
        first_line = b""
        if self.kind_map.needs_first_line(path):
            with (self.root / path).open("rb") as stream:
                first_line = stream.readline(FIRST_LINE_BYTES)
        return self.kind_map.kinds_of(path, first_line)

    def comment(self, path: str, row: int) -> str | None:
        if path not in self.comment_cache:
            self.comment_cache[path] = self.comments_of(path)
        return self.comment_cache[path].get(row)

    def comments_of(self, path: str) -> dict:
        kinds = self.kinds_of(path)
        if PYTHON_KIND in kinds:
            return python_comments(self.data(path))
        for kind in sorted(kinds):
            if kind in self.kind_map.markers:
                return marker_comments(self.lines(path), self.kind_map.markers[kind])
        return {}

    def ignore_data(self) -> bytes | None:
        """
        Returns:
            The ignore file of this side, or None when the side holds no such file.

        Raises:
            QualityError: The file is a symlink or over the size limit.
        """
        if IGNORE_FILE in self.irregular or IGNORE_FILE in self.unchecked:
            raise QualityError(f"{IGNORE_FILE} must be a regular file under the size limit")
        return self.data(IGNORE_FILE) if IGNORE_FILE in self.files else None


def materialize(repo, entries: list, root: Path, blob_limit: int, kind_map: KindMap) -> Snapshot:
    """
    Args:
        repo: Repository the objects come from.
        entries: Tree or index entries.
        root: Directory to create; it must not exist.
        blob_limit: Size above which a blob stays unread and is named unchecked.
        kind_map: File kind classification.

    Returns:
        The snapshot. Symlinks and gitlinks are recorded as irregular, never written.
    """
    root.mkdir(mode=0o700)
    regular = [entry for entry in entries if entry.mode in REGULAR_MODES]
    sizes = repo.sizes({entry.oid for entry in regular})
    kept, unchecked = split_by_size(regular, sizes, blob_limit)
    targets = blob_targets(kept, root)
    if targets:
        repo.export_blobs(targets, root.with_name(f"{root.name}.request"))
    return Snapshot(root, kept, unchecked, irregular_paths(entries), kind_map)


def irregular_paths(entries: list) -> set:
    return {entry.path for entry in entries if entry.mode not in REGULAR_MODES}


def split_by_size(regular: list, sizes: dict, blob_limit: int) -> tuple:
    kept = {}
    unchecked = []
    for entry in regular:
        if sizes[entry.oid] > blob_limit:
            unchecked.append(entry.path)
        else:
            kept[entry.path] = entry
    return kept, sorted(unchecked)


def blob_targets(kept: dict, root: Path) -> dict:
    targets = {}
    for entry in kept.values():
        destination = root / safe_path(entry.path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        targets.setdefault(entry.oid, []).append(destination)
    return targets
