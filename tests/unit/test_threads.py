import argparse
import os
from pathlib import Path

import pytest

from quality.adapters import REGISTRY
from quality.adapters.base import Bound, thread_environment
from quality.cli import thread_count
from quality.ruledata import load

RULES = Path(__file__).resolve().parents[2] / "rules"
DATA = load(RULES)
CAPS = {
    "rg": ("Dockerfile", "dockerfile", ["--threads", "2"]),
    "ast-grep": ("a.py", "python", ["--threads", "2"]),
    "hadolint": ("Dockerfile", "dockerfile", ["+RTS", "-N2", "-RTS"]),
    "jscpd": ("a.c", "c", ["--workers", "2"]),
    "semgrep": ("a.js", "javascript", ["--jobs", "2"]),
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
