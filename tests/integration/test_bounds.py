import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from tests.integration.support import (
    Target,
    branchy,
    edit_yaml,
    git,
    launcher_argv,
    path_with,
    raw_tool,
    report,
    rule_for,
    rule_ids,
    rules_copy,
    tools,
    write_every_kind,
    write_shim,
)

F401 = rule_for("F401")
SYNTAX = "coding.syntax-error"
OVERSIZED = "security.oversized-code"
TOOL_NAMES = sorted(tools())
CANARY = "QUALITYSHIMCANARY"


def every_kind_target(target: Target) -> Target:
    write_every_kind(target)
    target.commit()
    return target


@pytest.mark.parametrize("tool", TOOL_NAMES)
@pytest.mark.parametrize(
    "body",
    [
        f"echo {CANARY} >&2\nkill -KILL $$",
        f"echo {CANARY}\necho {CANARY} >&2\nexit 77",
    ],
    ids=["signal", "undocumented_exit"],
)
def test_tool_crash_exits_2(target, tmp_path, tool, body):
    every_kind_target(target)
    shims = tmp_path / "shims"
    write_shim(shims, tool, body)
    result = target.check("--all", path_value=path_with(shims))
    assert result.returncode == 2
    assert tool in result.stderr
    assert CANARY not in result.stdout + result.stderr


@pytest.mark.parametrize("tool", TOOL_NAMES)
def test_undocumented_output_exits_2(target, tmp_path, tool):
    every_kind_target(target)
    shims = tmp_path / "shims"
    write_shim(shims, tool, f"echo {CANARY}\nexit 0")
    result = target.check("--all", path_value=path_with(shims))
    assert result.returncode == 2
    assert tool in result.stderr
    assert CANARY not in result.stdout + result.stderr


def test_git_failure_exits_2(target, tmp_path):
    every_kind_target(target)
    shims = tmp_path / "shims"
    write_shim(shims, "git", f"echo {CANARY} >&2\nexit 77")
    result = target.check("--all", path_value=path_with(shims))
    assert result.returncode == 2
    assert CANARY not in result.stdout + result.stderr


def test_undecodable_python_is_a_finding(target):
    target.write("seed.py", "x = 1\n")
    target.commit()
    (target.path / "a.py").write_bytes(b'x = "caf\xe9"\ny = eval(input())\n')
    target.stage()
    control = raw_tool(target.path, "ruff", "check", "--isolated", "--select", "S307", "a.py")
    assert control.returncode == 0
    assert "Failed to lint" in control.stderr
    result = target.check("--staged", "--json")
    assert result.returncode == 1
    assert rule_ids(result) == [SYNTAX]


def test_argv_limit_splits_commands(target, tmp_path):
    every_kind_target(target)
    whole = sorted(rule_ids(target.check("--all", "--json")))
    rules = rules_copy(tmp_path / "rules")
    edit_yaml(rules / "limits.yml", lambda document: document.update(argv_max_bytes=1))
    result = target.check("--all", "--json", "--verbose", "--rules", str(rules))
    assert sorted(rule_ids(result)) == whole
    lines = [line for line in result.stderr.splitlines() if "tool rg:" in line]
    assert len(lines) > 1


def test_tool_stderr_on_clean_exit_fails_closed_for_lizard(target, tmp_path):
    every_kind_target(target)
    shims = tmp_path / "shims"
    write_shim(shims, "lizard", f"echo {CANARY} >&2\nexit 0")
    result = target.check("--all", path_value=path_with(shims))
    assert result.returncode == 2
    assert CANARY not in result.stdout + result.stderr


@pytest.mark.parametrize("tool", TOOL_NAMES)
def test_tool_timeout_exits_2(target, tmp_path, tool):
    every_kind_target(target)
    rules = rules_copy(tmp_path / "rules")
    edit_yaml(rules / "tools.yml", lambda document: document[tool].update(timeout=1))
    pid_file = tmp_path / "child.pid"
    shims = tmp_path / "shims"
    write_shim(shims, tool, f'sleep 60 &\necho $! > "{pid_file}"\nwait')
    started = time.monotonic()
    result = target.check("--all", "--rules", str(rules), path_value=path_with(shims))
    assert time.monotonic() - started < 30
    assert result.returncode == 2
    assert tool in result.stderr
    assert "timeout" in result.stderr
    pid = int(pid_file.read_text(encoding="utf-8"))
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and process_alive(pid):
        time.sleep(0.05)
    assert not process_alive(pid)


def process_alive(pid: int) -> bool:
    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    except OSError:
        return False
    return stat.rsplit(") ", 1)[1].split(" ", 1)[0] != "Z"


def test_lizard_refuses_a_quote_in_a_file_name(target):
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.write("real.py", "x = 2\n")
    target.write('a","real.py', branchy("f", 15))
    target.stage()
    result = target.check("--staged")
    assert result.returncode == 2
    assert "double quote" in result.stderr


def test_all_zero_files_exits_2(target, tmp_path):
    target.write("a.py", "import os\n")
    target.write("sub/b.py", "import sys\n")
    target.write("sub/__init__.py", "")
    target.commit()
    clone = tmp_path / "clone"
    git(tmp_path, "clone", "-q", "--no-checkout", str(target.path), str(clone))
    cloned = Target(clone)
    assert cloned.git("ls-files").stdout == ""
    result = cloned.check("--all")
    assert result.returncode == 2
    assert "zero files" in result.stderr
    cloned.git("read-tree", "HEAD")
    assert sorted(cloned.git("ls-files").stdout.split()) == ["a.py", "sub/__init__.py", "sub/b.py"]
    assert not (clone / "a.py").exists()
    result = cloned.check("--all", "--json")
    assert result.returncode == 1
    assert sorted(item["path"] for item in report(result)["findings"]) == ["a.py", "sub/b.py"]


def test_empty_staged_exits_0(target):
    target.write("a.py", "import os\n")
    target.commit()
    result = target.check("--staged", "--json")
    assert result.returncode == 0
    assert rule_ids(result) == []
    target.write("dirty.py", "import sys\n")
    assert target.check("--staged").returncode == 0


def shallow_clone(target: Target, tmp_path) -> Target:
    target.write("a.py", "import os\n")
    target.commit()
    target.write("b.py", "x = 1\n")
    target.commit()
    clone = tmp_path / "clone"
    git(
        tmp_path,
        "clone",
        "-q",
        "--depth",
        "1",
        "--no-single-branch",
        f"file://{target.path}",
        str(clone),
    )
    return Target(clone)


def test_shallow_base_exits_2(target, tmp_path):
    cloned = shallow_clone(target, tmp_path)
    assert cloned.git("rev-parse", "--is-shallow-repository").stdout.strip() == "true"
    for ref in ("origin/main", "main", "HEAD"):
        result = cloned.check("--base", ref)
        assert result.returncode == 2
        assert "merge base" in result.stderr


def test_unrelated_history_exits_2_naming_the_merge_base(target):
    target.write("a.py", "x = 1\n")
    target.commit()
    target.git("checkout", "-q", "--orphan", "other")
    target.git("rm", "-rqf", ".")
    target.write("b.py", "y = 1\n")
    target.commit()
    result = target.check("--base", "main")
    assert result.returncode == 2
    assert "merge base" in result.stderr


def test_shallow_all_labelled(target, tmp_path):
    cloned = shallow_clone(target, tmp_path)
    result = cloned.check("--all")
    assert result.returncode == 1
    assert "HEAD only: history not scanned" in result.stdout
    document = report(cloned.check("--all", "--json"))
    assert "HEAD only: history not scanned" in document["notes"]
    full = target.check("--all")
    assert "HEAD only" not in full.stdout


MEMORY_WRAPPER = (
    "import resource, subprocess, sys\n"
    "subprocess.run(sys.argv[1:], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
    "print(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)\n"
)


def peak_kib(argv: list, cwd: Path, env: dict) -> int:
    result = subprocess.run(
        [sys.executable, "-I", "-c", MEMORY_WRAPPER, *argv],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    return int(result.stdout.strip())


def test_large_blob_unread(target, tmp_path):
    rules = rules_copy(tmp_path / "rules")
    edit_yaml(rules / "limits.yml", lambda document: document.update(blob_max_bytes=1_048_576))
    blob_bytes = 268_435_456
    line = b"value = 1\n"
    with (target.path / "big.py").open("wb") as stream:
        stream.write(b"import os\n")
        for _ in range(blob_bytes // (len(line) * 4096)):
            stream.write(line * 4096)
    target.write("small.py", "import sys\n")
    target.commit()
    env = {"PATH": os.environ["PATH"], "TMPDIR": tempfile.gettempdir()}

    oid = target.git("rev-parse", "HEAD:big.py").stdout.strip()
    unprotected = (
        "import subprocess, sys\n"
        "argv = ['git', 'cat-file', 'blob', sys.argv[1]]\n"
        "subprocess.run(argv, capture_output=True, check=True)\n"
    )
    read_whole = peak_kib([sys.executable, "-I", "-c", unprotected, oid], target.path, env)
    assert read_whole * 1024 >= blob_bytes * 0.99

    args = launcher_argv("check", "--all", "--json", "--rules", str(rules))
    peak = peak_kib(args, target.path, env)
    assert peak * 1024 < blob_bytes / 2

    result = target.check("--all", "--json", "--rules", str(rules))
    document = report(result)
    assert document["unchecked"] == ["big.py"]
    assert [(item["rule"], item["path"]) for item in document["findings"]] == [
        (OVERSIZED, "big.py"),
        (F401, "small.py"),
    ]
    text = target.check("--all", "--rules", str(rules))
    assert "unchecked: big.py" in text.stdout


def test_large_blob_named_when_touched_only(target, tmp_path):
    rules = rules_copy(tmp_path / "rules")
    edit_yaml(rules / "limits.yml", lambda document: document.update(blob_max_bytes=64))
    target.write("big.py", "x = 1\n" * 100)
    target.write("small.py", "y = 1\n")
    target.commit()
    target.write("small.py", "y = 2\n")
    target.stage()
    untouched = report(target.check("--staged", "--json", "--rules", str(rules)))
    assert untouched["unchecked"] == []
    target.write("big.py", "x = 2\n" * 100)
    target.stage()
    touched = report(target.check("--staged", "--json", "--rules", str(rules)))
    assert touched["unchecked"] == ["big.py"]


def test_large_code_file_is_a_hard_finding(target, tmp_path):
    rules = rules_copy(tmp_path / "rules")
    edit_yaml(rules / "limits.yml", lambda document: document.update(blob_max_bytes=128))
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    padded = "# pad\n" * 30 + "X = eval(input())\n"
    for name in ("big.py", "tool", ".bashrc"):
        target.write(name, padded)
    for name in ("logo.png", "data.json", "notes.v2"):
        target.write(name, padded)
    target.stage()
    oversized = [(OVERSIZED, name) for name in (".bashrc", "big.py", "tool")]
    every_large = [".bashrc", "big.py", "data.json", "logo.png", "notes.v2", "tool"]
    staged = target.check("--staged", "--json", "--rules", str(rules))
    target.commit()
    for result in (
        staged,
        target.check("--base", "main", "--json", "--rules", str(rules)),
        target.check("--all", "--json", "--rules", str(rules)),
    ):
        assert result.returncode == 1
        document = report(result)
        assert [(item["rule"], item["path"]) for item in document["findings"]] == oversized
        assert document["unchecked"] == every_large
    target.write("seed.py", "x = 2\n")
    target.stage()
    assert target.check("--staged", "--rules", str(rules)).returncode == 0


def test_large_code_file_opted_out_per_path(target, tmp_path):
    rules = rules_copy(tmp_path / "rules")
    edit_yaml(rules / "limits.yml", lambda document: document.update(blob_max_bytes=128))
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.write("big.py", "# pad\n" * 30)
    target.write(".qualityignore.yml", f"- rule: {OVERSIZED}\n  paths: [big.py]\n  reason: r\n")
    target.stage()
    result = target.check("--staged", "--json", "--rules", str(rules))
    assert result.returncode == 0
    assert report(result)["ignored"][0]["rule"] == OVERSIZED


def test_missing_rule_setting_aborts_naming_the_key(target, tmp_path):
    target.write("a.py", "x = 1\n")
    target.commit()
    rules = rules_copy(tmp_path / "rules")
    edit_yaml(rules / "limits.yml", lambda document: document.pop("blob_max_bytes"))
    result = target.check("--all", "--rules", str(rules))
    assert result.returncode == 2
    assert "blob_max_bytes" in result.stderr
