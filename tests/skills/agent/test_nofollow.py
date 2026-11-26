import os
import signal
import stat
import time
from pathlib import Path

import pytest

from quality.agent import nofollow

MODE = 0o600


def lock(root: Path, path: Path) -> None:
    with nofollow.locked(root, path, MODE, None):
        pass


def create(root: Path, path: Path) -> None:
    os.close(nofollow.open_below(root, path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, MODE))


ACCESS = {
    "replace": lambda root, path: nofollow.replace(root, path, "x", MODE),
    "rewrite": lambda root, path: nofollow.rewrite(root, path, "x", MODE),
    "append": lambda root, path: nofollow.append(root, path, "x", MODE),
    "lock": lock,
    "read": nofollow.read_text,
    "tail": lambda root, path: nofollow.read_tail(root, path, 8),
    "create": create,
}
SWAPPING = ("replace", "rewrite")
FOLLOWERS = [name for name in ACCESS if name not in SWAPPING]


@pytest.fixture
def root(tmp_path):
    folder = tmp_path / "council"
    folder.mkdir(mode=0o700)
    return folder


@pytest.fixture
def victim(tmp_path):
    path = tmp_path / "victim"
    path.write_text("keep", encoding="utf-8")
    return path


@pytest.fixture
def victims(tmp_path):
    folder = tmp_path / "victims"
    folder.mkdir()
    return folder


def test_writes_land_below_the_root_in_private_directories(root):
    target = root / "a" / "b" / "f"
    nofollow.replace(root, target, "one", MODE)
    nofollow.replace(root, target, "two", MODE)
    nofollow.append(root, target, "+", MODE)
    assert target.read_text(encoding="utf-8") == "two+"
    assert sorted(os.listdir(target.parent)) == ["f"]
    assert stat.S_IMODE((root / "a").stat().st_mode) == 0o700
    assert stat.S_IMODE(target.stat().st_mode) == MODE
    with nofollow.locked(root, root / "c" / "lock", MODE, None) as handle:
        handle.write("held")
    assert (root / "c" / "lock").read_text(encoding="utf-8") == "held"
    with nofollow.locked(root, root / "c" / "lock", MODE, 1):
        pass
    assert (root / "c" / "lock").read_text(encoding="utf-8") == "held"
    nofollow.unlink(root, target)
    assert not target.exists()


def test_rewrite_replaces_inside_existing_directories_and_makes_none(root):
    (root / "d").mkdir()
    nofollow.rewrite(root, root / "d" / "f", "one", MODE)
    nofollow.rewrite(root, root / "d" / "f", "two", MODE)
    assert (root / "d" / "f").read_text(encoding="utf-8") == "two"
    assert os.listdir(root / "d") == ["f"]
    with pytest.raises(FileNotFoundError):
        nofollow.rewrite(root, root / "missing" / "f", "x", MODE)
    assert not (root / "missing").exists()


@pytest.mark.parametrize("name", SWAPPING)
def test_a_swap_replaces_a_planted_link_and_keeps_its_target(root, victim, tmp_path, name):
    dangling = tmp_path / "created"
    for target in (victim, dangling):
        link = root / "f"
        link.symlink_to(target)
        ACCESS[name](root, link)
        assert not link.is_symlink()
        assert link.read_text(encoding="utf-8") == "x"
        link.unlink()
    assert victim.read_text(encoding="utf-8") == "keep"
    assert not dangling.exists()


@pytest.mark.parametrize("name", FOLLOWERS)
def test_a_symlinked_name_is_refused_and_its_target_kept(root, victim, tmp_path, name):
    dangling = tmp_path / "created"
    link = root / name
    link.symlink_to(victim)
    with pytest.raises(OSError):
        ACCESS[name](root, link)
    assert victim.read_text(encoding="utf-8") == "keep"
    link.unlink()
    link.symlink_to(dangling)
    with pytest.raises(OSError):
        ACCESS[name](root, link)
    assert not dangling.exists()


@pytest.mark.parametrize("name", [name for name in FOLLOWERS if name != "create"])
def test_a_hard_linked_name_is_refused_and_its_target_kept(root, victim, name):
    link = root / name
    os.link(victim, link)
    with pytest.raises(OSError):
        ACCESS[name](root, link)
    assert victim.read_text(encoding="utf-8") == "keep"


@pytest.mark.parametrize("name", list(ACCESS))
def test_a_symlinked_directory_is_refused_and_nothing_lands_in_its_target(root, victims, name):
    (root / "d").symlink_to(victims)
    (victims / "f").write_text("keep", encoding="utf-8")
    with pytest.raises(OSError):
        ACCESS[name](root, root / "d" / name)
    with pytest.raises(OSError):
        ACCESS[name](root, root / "d" / "deeper" / name)
    with pytest.raises(OSError):
        nofollow.unlink(root, root / "d" / "f")
    assert os.listdir(victims) == ["f"]
    assert (victims / "f").read_text(encoding="utf-8") == "keep"


@pytest.mark.parametrize("name", list(ACCESS))
def test_a_symlinked_root_is_refused(tmp_path, victims, name):
    link = tmp_path / "link"
    link.symlink_to(victims)
    with pytest.raises(OSError):
        ACCESS[name](link, link / name)
    assert os.listdir(victims) == []


@pytest.mark.parametrize("name", list(ACCESS))
def test_a_path_outside_the_root_is_refused(root, tmp_path, name):
    escaped = tmp_path / "escaped"
    for path in (root / ".." / "escaped", root / "a" / ".." / ".." / "escaped", escaped, root):
        with pytest.raises(OSError):
            ACCESS[name](root, path)
    assert not escaped.exists()
    assert not (root / "a").exists()


def test_parts_below_names_each_level_and_refuses_the_root_itself(root, tmp_path):
    assert nofollow.parts_below(root, root / "a" / "b") == ("a", "b")
    for path in (root, tmp_path / "other", root / ".." / "council" / "f"):
        with pytest.raises(OSError):
            nofollow.parts_below(root, path)


def test_directory_makes_private_levels_only_when_asked(root):
    with pytest.raises(FileNotFoundError):
        nofollow.directory(root, ("a", "b"), False)
    fd = nofollow.directory(root, ("a", "b"), True)
    os.close(fd)
    assert stat.S_IMODE((root / "a" / "b").stat().st_mode) == 0o700


@pytest.mark.parametrize("name", FOLLOWERS)
def test_a_fifo_at_a_name_is_refused_without_blocking(root, name):
    def blocked(*_args) -> None:
        raise AssertionError("blocked on a FIFO")

    previous = signal.signal(signal.SIGALRM, blocked)
    fifo = root / name
    os.mkfifo(fifo, MODE)
    signal.alarm(5)
    try:
        with pytest.raises(OSError):
            ACCESS[name](root, fifo)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def test_a_held_lock_times_out_instead_of_hanging(root):
    path = root / "lock"
    with nofollow.locked(root, path, MODE, None):
        start = time.monotonic()
        with pytest.raises(TimeoutError), nofollow.locked(root, path, MODE, 0.2):
            pass
        assert time.monotonic() - start < 5


def test_try_lock_reports_a_lock_another_handle_holds(root):
    path = root / "lock"
    with path.open("w", encoding="utf-8") as other:
        with nofollow.locked(root, path, MODE, None):
            assert nofollow.try_lock(other) is False
        assert nofollow.try_lock(other) is True


def test_read_refuses_a_file_over_the_limit_and_replaces_undecodable_bytes(root, monkeypatch):
    monkeypatch.setattr(nofollow, "READ_LIMIT", 4)
    (root / "f").write_bytes(b"\xff\n")
    assert nofollow.read_text(root, root / "f") == "�\n"
    (root / "f").write_bytes(b"12345")
    with pytest.raises(OSError):
        nofollow.read_text(root, root / "f")


def test_read_tail_yields_only_whole_lines_of_the_last_bytes(root):
    (root / "f").write_bytes(b"one\ntwo\nthree\n")
    assert nofollow.read_tail(root, root / "f", 8) == "three\n"
    assert nofollow.read_tail(root, root / "f", 64) == "one\ntwo\nthree\n"


def test_unlink_removes_a_planted_link_and_keeps_its_target(root, victim):
    (root / "l").symlink_to(victim)
    nofollow.unlink(root, root / "l")
    assert not (root / "l").is_symlink()
    assert victim.read_text(encoding="utf-8") == "keep"
