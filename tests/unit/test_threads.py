import argparse
import os
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from quality import QualityError
from quality.adapters import REGISTRY, Collector
from quality.adapters.base import Bound, thread_environment
from quality.cli import thread_count
from quality.ruledata import BUILTIN, load

RULES = Path(__file__).resolve().parents[2] / "rules"
DATA = load(RULES)
CAPS = {
    "rg": ("Dockerfile", "dockerfile", ["--threads", "2"]),
    "ast-grep": ("a.py", "python", ["--threads", "2"]),
    "hadolint": ("Dockerfile", "dockerfile", ["+RTS", "-N2", "-RTS"]),
    "jscpd": ("a.c", "c", ["--workers", "2"]),
    "semgrep": ("a.js", "javascript", ["--jobs", "2"]),
    "scancode": ("a.py", "any", ["--processes", "2"]),
}


def prefixes(tool: str, threads, tmp_path: Path) -> list:
    path, kind, _cap = CAPS[tool]
    binding = next(item for item in DATA.bindings()[tool] if kind in item.kinds)
    bound = [Bound(binding, [path], {path: frozenset({kind})})]
    empty_json = tmp_path / "empty.json"
    empty_json.write_text("{}\n", encoding="utf-8")
    values = {"rules_dir": RULES, "database": None, "work_dir": tmp_path, "empty_json": empty_json, "threads": threads}
    commands = REGISTRY[tool].commands(bound, {**DATA.tool(tool), **values}, tmp_path / "empty.yaml")
    return [command.prefix for command in commands]


def holds(prefix: list, cap: list) -> bool:
    return any(prefix[start : start + len(cap)] == cap for start in range(len(prefix)))


@pytest.mark.parametrize("tool", sorted(CAPS))
def test_each_tool_gets_the_cap_only_when_one_is_set(tool, tmp_path):
    cap = CAPS[tool][2]
    capped = prefixes(tool, 2, tmp_path)
    assert capped and all(holds(prefix, cap) for prefix in capped)
    uncapped = prefixes(tool, None, tmp_path)
    assert uncapped and not any(cap[0] in prefix for prefix in uncapped)
    assert [len(prefix) - len(cap) for prefix in capped] == [len(prefix) for prefix in uncapped]


def test_the_go_tools_and_ruff_take_the_cap_from_the_environment():
    assert thread_environment(None) == {}
    assert thread_environment(3) == {"GOMAXPROCS": "3", "RAYON_NUM_THREADS": "3"}


def test_threads_accepts_one_to_the_host_cores():
    assert thread_count("1") == 1
    assert thread_count(str(os.cpu_count())) == os.cpu_count()


@pytest.mark.parametrize("text", ["0", "-1", "", " 1", "+1", "1.0", "abc", "١", "²", str(os.cpu_count() + 1), "9" * 20])
def test_threads_refuses_anything_else(text):
    with pytest.raises(argparse.ArgumentTypeError):
        thread_count(text)


TOOLS = [("ruff", []), (BUILTIN, []), ("rg", []), ("lizard", [])]


class Recorder:
    def __init__(self, barrier):
        self.barrier = barrier
        self.lock = threading.Lock()
        self.running = 0
        self.peak = 0
        self.calling_thread = {}

    def __call__(self, tool: str, _bound: list, _snapshot) -> list:
        self.calling_thread[tool] = threading.current_thread() is threading.main_thread()
        with self.lock:
            self.running += 1
            self.peak = max(self.peak, self.running)
        if self.barrier is not None and tool != BUILTIN:
            self.barrier.wait(timeout=30)
        with self.lock:
            self.running -= 1
        if tool == "rg":
            raise QualityError("rg failed")
        return [tool]


def run_all(threads, recorder: Recorder) -> list:
    collector = Collector(DATA, SimpleNamespace(resources={"threads": threads}))
    collector.run_tool = recorder
    return [(hits, None if error is None else str(error)) for hits, error in collector.run_all(TOOLS, None)]


def test_the_external_tools_run_side_by_side_and_the_builtin_rules_in_the_calling_thread():
    recorder = Recorder(threading.Barrier(3))
    assert run_all(None, recorder) == [(["ruff"], None), ([BUILTIN], None), ([], "rg failed"), (["lizard"], None)]
    assert recorder.calling_thread == {"ruff": False, BUILTIN: True, "rg": False, "lizard": False}


def test_negative_control_a_thread_cap_runs_one_tool_at_a_time():
    recorder = Recorder(None)
    assert run_all(2, recorder) == [(["ruff"], None), ([BUILTIN], None), ([], "rg failed"), (["lizard"], None)]
    assert recorder.peak == 1
