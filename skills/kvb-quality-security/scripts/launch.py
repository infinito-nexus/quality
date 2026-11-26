#!/usr/bin/env kvb-quality-python
from __future__ import annotations

import contextlib
import ctypes
import functools
import json
import os
import re
import shutil
import signal
import subprocess
import time
from collections.abc import Iterable
from pathlib import Path
from typing import NamedTuple

CORE_SHARE = 0.95
CPUINFO = Path("/proc/cpuinfo")
KNOB = "MEDUSA_SCANNER_TIMEOUT"
TIMEOUT = 900
DEADLINE = 3600
CEILING = 86400
STOPS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
PR_SET_PDEATHSIG = 1
TIMED = re.compile(r"scanner error\(s\)/timeout\(s\) during scan")
RERUN = "rerun once the host is idle"
CAPPED = (
    "a scanner crashed or hit medusa's fixed {cap} s cap (medusa counts both together): rerun when idle; "
    f"if it repeats, give medusa the {KNOB} knob"
)
ERRED = "scanner error (no scanner reached the {cap} s cap): rerun when idle"
MEDUSA = "medusa"
PINNED = "Quality's pinned tool set"
SEARCHED = "PATH"


class Incomplete(Exception):
    pass


class Stopped(BaseException):
    pass


class Budget(NamedTuple):
    """
    Attributes:
        timeout: whole seconds each medusa scanner may spend on one file,
            handed to medusa as KNOB.
        deadline: whole seconds the whole medusa run may take.
    """

    timeout: int
    deadline: int


def medusa(pins: Path) -> tuple[str, str] | None:
    """
    Args:
        pins: the pin manifest of Quality's pinned tool set, tool name to its
            package, version and executable path.

    Returns:
        medusa's executable and where it came from: the manifest's medusa
        when it names an executable file (PINNED), else the medusa on PATH
        (SEARCHED); None when neither has one.
    """
    try:
        pinned = json.loads(pins.read_text(encoding="utf-8")).get(MEDUSA)
    except (OSError, ValueError, AttributeError):
        pinned = None
    path = pinned.get("path") if isinstance(pinned, dict) else None
    if isinstance(path, str) and os.path.isfile(path) and os.access(path, os.X_OK):
        return path, PINNED
    found = shutil.which(MEDUSA)
    return (found, SEARCHED) if found else None


def physical_cores(cpuinfo: str) -> int:
    """Returns:
        The distinct physical id and core id pairs cpuinfo lists, else the
        logical CPU count.
    """
    pairs, socket = set(), ""
    for line in cpuinfo.splitlines():
        key, _, value = line.partition(":")
        if key.strip() == "physical id":
            socket = value.strip()
        elif key.strip() == "core id":
            pairs.add((socket, value.strip()))
    return len(pairs) or os.cpu_count() or 1  # nocheck: clean.default-value -- os.cpu_count() is None on a host that hides its CPUs, and one worker still scans there


def scan_workers(cores: int) -> int:
    """Returns:
        CORE_SHARE of the cores rounded down, at least one core left free and
        at least one worker.
    """
    return max(1, min(int(cores * CORE_SHARE), cores - 1))


def host_workers() -> int:
    try:
        cpuinfo = CPUINFO.read_text(encoding="utf-8", errors="replace")
    except OSError:
        cpuinfo = ""
    return scan_workers(physical_cores(cpuinfo))


def advice(short: str, cap: int | None, lasted: float) -> str:
    """Returns:
        what to do about the FAULT or shortfall short of a run that lasted these
        seconds under medusa's fixed cap: CAPPED, ERRED or RERUN.
    """
    if cap is None or not TIMED.search(short):
        return RERUN
    return (CAPPED if lasted >= cap else ERRED).format(cap=cap)


def halt(group: list[int], handled: Iterable[int]) -> None:
    """Args:
        group: process group ids to kill with SIGKILL.
        handled: signals set to SIG_IGN before the kill.
    """
    for number in handled:
        signal.signal(number, signal.SIG_IGN)
    for pid in group:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(pid, signal.SIGKILL)


def deathsig() -> functools.partial | None:
    """Returns:
        the preexec_fn that kills medusa when this process dies, None for a libc without prctl.
    """
    prctl = getattr(ctypes.CDLL(None), "prctl", None)
    return functools.partial(prctl, PR_SET_PDEATHSIG, int(signal.SIGKILL)) if prctl else None


def medusa_run(command: list[str], work: Path, env: dict[str, str], deadline: int) -> tuple[int, str, float]:
    """Returns:
        medusa's exit code, stdout and seconds. medusa runs in its own process
        group, dies with this process (deathsig) and its group is killed past
        deadline seconds (Incomplete), on a STOPS signal the caller does not
        ignore (Stopped) or on any other exception.
    """
    group: list[int] = []
    previous = {number: signal.getsignal(number) for number in STOPS}
    previous = {number: handler for number, handler in previous.items() if handler not in (signal.SIG_IGN, None)}

    def stop(number: int, frame: object) -> None:
        halt(group, previous)
        raise Stopped(number)

    for number in previous:
        signal.signal(number, stop)
    start = time.monotonic()
    try:
        with subprocess.Popen(
            command, cwd=work, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env,
            start_new_session=True, preexec_fn=deathsig(),
        ) as process:
            group.append(process.pid)
            try:
                out, _ = process.communicate(timeout=deadline)
            except BaseException:
                halt(group, previous)
                raise
    except subprocess.TimeoutExpired:
        raise Incomplete(
            f"medusa ran past its {deadline} s --deadline: rerun it in the background with --deadline raised, up to {CEILING}"
        ) from None
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
    return process.returncode, out.decode(errors="replace"), time.monotonic() - start
