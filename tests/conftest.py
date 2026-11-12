import json
import os
import resource
import threading
import time
from pathlib import Path

import pytest

PROBE = os.environ.get("QUALITY_TEST_PROBE")
INTERVAL = 0.25
TICKS = os.sysconf("SC_CLK_TCK")
PAGE = os.sysconf("SC_PAGE_SIZE")
MIB = 1 << 20


def stat_line(raw: str) -> tuple:
    """
    Args:
        raw: Content of one /proc/<pid>/stat.

    Returns:
        pid, parent pid, a key of pid and start time, and the sample: name,
        CPU ticks, threads, resident bytes.
    """
    head, _, tail = raw.rpartition(")")
    pid, _, name = head.partition(" (")
    fields = tail.split()
    sample = (name, int(fields[11]) + int(fields[12]), int(fields[17]), int(fields[21]) * PAGE)
    return int(pid), int(fields[1]), (int(pid), int(fields[19])), sample


def processes() -> list:
    """
    Returns:
        A stat_line() of every process /proc shows. Only stat is read, never
        cmdline or environ.
    """
    found = []
    for entry in os.scandir("/proc"):
        if entry.name.isdigit():
            try:
                found.append(stat_line(Path(entry.path, "stat").read_text(errors="replace")))
            except (OSError, IndexError, ValueError):
                continue
    return found


def descendants(root: int) -> dict:
    listed = processes()
    children = {}
    for pid, parent, _key, _sample in listed:
        children.setdefault(parent, []).append(pid)
    wanted = {root}
    pending = [root]
    while pending:
        for child in children.get(pending.pop(), []):
            wanted.add(child)
            pending.append(child)
    return {key: sample for pid, _parent, key, sample in listed if pid in wanted}


class Sampler(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.halt = threading.Event()
        self.started = time.monotonic()
        self.seen = descendants(os.getpid())
        self.test = None
        self.peaks = {}
        self.tools = {}
        self.timeline = []

    def run(self) -> None:
        last = time.monotonic()
        while not self.halt.wait(INTERVAL):
            now = time.monotonic()
            self.sample(now - last)
            last = now

    def sample(self, elapsed: float) -> None:
        current = descendants(os.getpid())
        usage = {}
        for key, (name, ticks, threads, size) in current.items():
            spent = (ticks - self.seen[key][1] if key in self.seen else ticks) / TICKS
            entry = usage.setdefault(name, [0.0, 0.0, 0, 0])
            entry[0] += spent
            entry[1] += spent / elapsed
            entry[2] += threads
            entry[3] += size
        self.seen = current
        self.record(usage)

    def record(self, usage: dict) -> None:
        cores = sum(entry[1] for entry in usage.values())
        rss = sum(entry[3] for entry in usage.values()) / MIB
        top = sorted(usage, key=lambda name: -usage[name][1])[:3]
        self.timeline.append([round(time.monotonic(), 2), round(cores, 2), round(rss), self.test, top])
        for name, (cpu, share, threads, size) in usage.items():
            tool = self.tools.setdefault(name, {"cpu_s": 0.0, "peak_cores": 0.0, "peak_threads": 0, "peak_rss_mib": 0})
            tool["cpu_s"] += cpu
            tool["peak_cores"] = max(tool["peak_cores"], share)
            tool["peak_threads"] = max(tool["peak_threads"], threads)
            tool["peak_rss_mib"] = max(tool["peak_rss_mib"], round(size / MIB))
        if self.test:
            peak = self.peaks.setdefault(self.test, [0.0, 0])
            peak[0] = max(peak[0], cores)
            peak[1] = max(peak[1], round(rss))


SAMPLER = Sampler() if PROBE else None


def worker() -> str:
    return os.environ.get("PYTEST_XDIST_WORKER") or "controller"  # nocheck: clean.default-value -- pytest without xdist sets no worker id, its one process is the controller


def output(suffix: str) -> Path:
    return Path(PROBE) / f"{worker()}-{suffix}"


def spent() -> tuple:
    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    own = resource.getrusage(resource.RUSAGE_SELF)
    return children.ru_utime + children.ru_stime, own.ru_utime + own.ru_stime, children.ru_maxrss


def pytest_configure():
    if SAMPLER is not None:
        Path(PROBE).mkdir(parents=True, exist_ok=True)
        SAMPLER.start()


@pytest.hookimpl(wrapper=True)
def pytest_runtest_protocol(item):
    if SAMPLER is None:
        return (yield)
    SAMPLER.test = item.nodeid
    before, started = spent(), time.monotonic()
    result = yield
    after, wall = spent(), time.monotonic() - started
    SAMPLER.test = None
    peak = SAMPLER.peaks.get(item.nodeid) or [0.0, 0]  # nocheck: clean.default-value -- a test shorter than one INTERVAL was never sampled, so its measured peak is zero
    line = {
        "test": item.nodeid,
        "wall_s": round(wall, 3),
        "children_cpu_s": round(after[0] - before[0], 3),
        "own_cpu_s": round(after[1] - before[1], 3),
        "peak_cores": round(peak[0], 2),
        "peak_rss_mib": peak[1],
        "children_maxrss_mib": round(after[2] / 1024),
    }
    with output("tests.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(line) + "\n")
    return result


def pytest_unconfigure():
    if SAMPLER is None or not SAMPLER.is_alive():
        return
    SAMPLER.halt.set()
    SAMPLER.join()
    timeline = SAMPLER.timeline
    summary = {
        "wall_s": round(time.monotonic() - SAMPLER.started, 1),
        "peak_cores": max((point[1] for point in timeline), default=0),
        "peak_rss_mib": max((point[2] for point in timeline), default=0),
        "tools": dict(sorted(SAMPLER.tools.items(), key=lambda item: -item[1]["cpu_s"])),
    }
    output("summary.json").write_text(json.dumps(summary, indent=1), encoding="utf-8")
    output("timeline.json").write_text(json.dumps(timeline), encoding="utf-8")
