from __future__ import annotations

import contextlib
import errno
import fcntl
import os
import stat
import time
from collections.abc import Iterator
from pathlib import Path
from typing import TextIO

DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
DIRECTORY_MODE = 0o700
READ_LIMIT = 1 << 26
LOCK_POLL = 0.05


def parts_below(root: Path, path: Path) -> tuple[str, ...]:
    """
    Args:
        root: The trusted directory.
        path: A path below root.

    Returns:
        The parts of path relative to root; OSError for root itself, a path
        outside it or one holding `..`.
    """
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        parts = ()
    if not parts or ".." in parts:
        raise OSError(errno.EINVAL, f"not a path below {root}", str(path))
    return parts


def directory(root: Path, parts: tuple[str, ...], create: bool) -> int:
    """
    Args:
        root: The trusted directory; a symlink there is refused.
        parts: Directory names below root, opened one by one.
        create: True makes a missing level with mode 0o700.

    Returns:
        The descriptor of the innermost directory, no link followed on the
        way; the caller closes it.
    """
    fd = os.open(root, DIRECTORY)
    try:
        for part in parts:
            if create:
                with contextlib.suppress(FileExistsError):
                    os.mkdir(part, DIRECTORY_MODE, dir_fd=fd)
            child = os.open(part, DIRECTORY, dir_fd=fd)
            os.close(fd)
            fd = child
    except BaseException:
        os.close(fd)
        raise
    return fd


def open_below(root: Path, path: Path, flags: int, mode: int) -> int:
    """
    Args:
        root: The trusted directory; a symlink there is refused too.
        path: The file, below root; with O_CREAT in flags its missing
            directories are made with mode 0o700.
        flags: os.open flags; O_NOFOLLOW, O_NONBLOCK and O_CLOEXEC are added.
        mode: Permission bits of a created file.

    Returns:
        The file descriptor of a regular file with a single link; the caller
        closes it.
    """
    *dirs, name = parts_below(root, path)
    fd = directory(root, tuple(dirs), bool(flags & os.O_CREAT))
    try:
        file = os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, mode, dir_fd=fd)
    finally:
        os.close(fd)
    info = os.fstat(file)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        os.close(file)
        raise OSError(errno.EINVAL, "not a regular file with a single link", str(path))
    return file


def read_text(root: Path, path: Path) -> str:
    """
    Args:
        root: The trusted directory.
        path: The file, below root; one over READ_LIMIT bytes raises OSError.

    Returns:
        Its content, UTF-8 decoded, undecodable bytes replaced.
    """
    with open(open_below(root, path, os.O_RDONLY, 0), "rb") as handle:
        data = handle.read(READ_LIMIT + 1)
    if len(data) > READ_LIMIT:
        raise OSError(errno.EFBIG, f"larger than {READ_LIMIT} bytes", str(path))
    return data.decode("utf-8", errors="replace")


def read_tail(root: Path, path: Path, limit: int) -> str:
    """
    Args:
        root: The trusted directory.
        path: The file, below root.
        limit: Bytes to read at most; a longer file yields its last limit
            bytes after the first line break in them, so only whole lines.

    Returns:
        That text, UTF-8 decoded, undecodable bytes replaced.
    """
    with open(open_below(root, path, os.O_RDONLY, 0), "rb") as handle:
        size = os.fstat(handle.fileno()).st_size
        if size <= limit:
            return handle.read(limit).decode("utf-8", errors="replace")
        handle.seek(size - limit)
        data = handle.read(limit)
    return data[data.find(b"\n") + 1 :].decode("utf-8", errors="replace")


@contextlib.contextmanager
def locked(root: Path, path: Path, mode: int, wait: float | None) -> Iterator[TextIO]:
    """
    Args:
        root: The trusted directory.
        path: The lock file, below root, created without truncation.
        mode: Permission bits of a created lock file.
        wait: Seconds to wait for the exclusive flock before TimeoutError, or
            None to wait as long as another holder keeps it.

    Yields:
        The open lock file, held under an exclusive flock.
    """
    with open(open_below(root, path, os.O_WRONLY | os.O_CREAT, mode), "w", encoding="utf-8") as handle:
        if wait is None:
            fcntl.flock(handle, fcntl.LOCK_EX)
        else:
            deadline = time.monotonic() + wait
            while not try_lock(handle):
                if time.monotonic() >= deadline:
                    raise TimeoutError(errno.ETIMEDOUT, f"lock held for over {wait} s", str(path))
                time.sleep(LOCK_POLL)
        yield handle


def try_lock(handle: TextIO) -> bool:
    """
    Args:
        handle: An open file.

    Returns:
        True when an exclusive flock on it was taken without waiting, False
        while another holder keeps it.
    """
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    return True


def append(root: Path, path: Path, text: str, mode: int) -> None:
    """
    Args:
        root: The trusted directory.
        path: The file, below root, appended to.
        text: What to append, UTF-8 encoded.
        mode: Permission bits of a created file.
    """
    with open(open_below(root, path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, mode), "a", encoding="utf-8") as handle:
        handle.write(text)


def replace(root: Path, path: Path, text: str, mode: int) -> None:
    """
    Args:
        root: The trusted directory.
        path: The file, below root, replaced atomically through a fresh temp
            file beside it; a symlink there is replaced, never followed, and
            missing directories are made with mode 0o700.
        text: The new content, UTF-8 encoded.
        mode: Permission bits of the new file.
    """
    swap(root, path, text, mode, True)


def rewrite(root: Path, path: Path, text: str, mode: int) -> None:
    """
    Args:
        root: The trusted directory.
        path: The file, below root, replaced like replace does; a missing
            directory on the way raises FileNotFoundError and nothing is made.
        text: The new content, UTF-8 encoded.
        mode: Permission bits of the new file.
    """
    swap(root, path, text, mode, False)


def swap(root: Path, path: Path, text: str, mode: int, create: bool) -> None:
    """
    Args:
        root: The trusted directory.
        path: The file, below root, renamed over by a temp file beside it.
        text: The new content, UTF-8 encoded.
        mode: Permission bits of the new file.
        create: True makes missing directories with mode 0o700.
    """
    *dirs, name = parts_below(root, path)
    fd = directory(root, tuple(dirs), create)
    try:
        temp = f".{name}.{os.urandom(8).hex()}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            with open(os.open(temp, flags, mode, dir_fd=fd), "w", encoding="utf-8") as handle:
                handle.write(text)
            os.replace(temp, name, src_dir_fd=fd, dst_dir_fd=fd)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(temp, dir_fd=fd)
            raise
    finally:
        os.close(fd)


def unlink(root: Path, path: Path) -> None:
    """
    Args:
        root: The trusted directory.
        path: The name, below root, removed; a symlink there is removed, never
            followed.
    """
    *dirs, name = parts_below(root, path)
    fd = directory(root, tuple(dirs), False)
    try:
        os.unlink(name, dir_fd=fd)
    finally:
        os.close(fd)
