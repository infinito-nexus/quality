#!/bin/python3
"""
Args:
    argv[0]: Name the probe image installs this file under.
        quality: stands in for the scanner. `quality check ...` runs in the scan step and prints a valid
            report whose one note is the JSON of what it observed; `quality db update --db <dir>/bundle` runs in
            the database step and writes that JSON to <dir>/probe-result.json.
        git: sleeps HOLD_SECONDS before `git add` and before any call naming "hold", then runs the real git.
    argv[1:]: Arguments of that command.
    probe: the "probe" object of the first tracked file holding one, or of <dir>/probe.json in the database
        step; tokens in upper-case hex.
    hold: seconds to sleep before reporting.
    leave: token written to the temporary directory.
    seek: token searched in every file outside SKIPPED.
    isolation: {"targets": ["host:port"], "fork_cap": count, "tmp_cap": bytes} runs the sandbox checks.
    egress: ["host:port"] each connected through https_proxy and directly.
    stay: true ignores SIGTERM and never exits.
"""

import errno
import hashlib
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit

GIT = "/bin/git"
HOLD_SECONDS = 3
CONNECT_SECONDS = 3
SKIPPED = ("/proc", "/sys", "/dev", "/nix")
SEEK_MAX_BYTES = 4 << 20
CHUNK = b"\0" * (1 << 20)
EMPTY_REPORT = {"findings": [], "ignored": [], "nocheck": [], "unchecked": [], "incomplete": [], "parse_incomplete": [], "architecture": None, "legal": None, "legal_blockers": None, "legal_unchecked": None}


def run_git(*args):
    result = subprocess.run([GIT, *args], capture_output=True, check=False)
    return result.stdout if result.returncode == 0 else None


def names(listing):
    return None if listing is None else [name.decode() for name in listing.split(b"\0") if name]


def instructions(paths):
    for path in paths:
        try:
            document = json.loads(run_git("show", f":{path}"))
        except (TypeError, ValueError):
            continue
        if isinstance(document, dict) and "probe" in document:
            return document["probe"]
    return {}


def mounts():
    with open("/proc/self/mountinfo", encoding="utf-8") as handle:
        return [[fields[4], fields[5]] for fields in (line.split() for line in handle)]


def worktree():
    found = []
    for directory, subdirectories, files in os.walk("."):
        subdirectories[:] = [name for name in subdirectories if name != ".git"]
        found += [os.path.relpath(os.path.join(directory, name)) for name in files]
    return sorted(found)


def blobs(paths):
    contents = {path: run_git("show", f":{path}") for path in paths}
    return {path: hashlib.sha256(content).hexdigest() for path, content in contents.items() if content is not None}


def observe():
    head = run_git("rev-parse", "HEAD")
    tracked = names(run_git("ls-files", "-z")) or []
    return {
        "ls_files": tracked,
        "ls_tree": names(run_git("ls-tree", "-r", "-z", "--name-only", "HEAD")),
        "head": None if head is None else head.decode().strip(),
        "blobs": blobs(tracked),
        "worktree": worktree(),
        "mounts": mounts(),
        "uid": os.getuid(),
    }


def failure(error):
    return errno.errorcode.get(error.errno, str(error))  # nocheck: clean.default-value -- an error without a symbolic errno name is reported by its message


def connect(target):
    host, port = target.rsplit(":", 1)
    try:
        socket.create_connection((host, int(port)), timeout=CONNECT_SECONDS).close()
    except TimeoutError:
        return "timeout"
    except OSError as error:
        return failure(error)
    return "connected"


def through_proxy(target):
    proxy = urlsplit(os.environ["https_proxy"])
    try:
        with socket.create_connection((proxy.hostname, proxy.port), timeout=10) as connection:
            connection.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
            fields = connection.makefile("rb").readline().split()
    except OSError as error:
        return failure(error)
    return int(fields[1]) if len(fields) > 1 else 0


def write(path):
    try:
        with open(path, "x", encoding="utf-8") as handle:
            handle.write("probe")
    except OSError as error:
        return failure(error)
    os.unlink(path)
    return "written"


def fork_bomb(cap):
    children, stopped_by = [], "cap"
    try:
        while len(children) < cap:
            child = os.fork()
            if child == 0:
                time.sleep(60)
                os._exit(0)
            children.append(child)
    except OSError as error:
        stopped_by = failure(error)
    for child in children:
        os.kill(child, signal.SIGKILL)
        os.waitpid(child, 0)
    return {"forked": len(children), "stopped_by": stopped_by}


def fill(cap):
    path, written, stopped_by = os.path.join(tempfile.gettempdir(), "fill"), 0, "cap"
    try:
        with open(path, "wb", buffering=0) as handle:
            while written < cap:
                written += handle.write(CHUNK)
    except OSError as error:
        stopped_by = failure(error)
    os.unlink(path)
    return {"written": written, "stopped_by": stopped_by}


def resolve(name):
    try:
        socket.getaddrinfo(name, 443)
    except OSError:
        return "failed"
    return "resolved"


def isolation(spec):
    return {
        "interfaces": sorted(name for _index, name in socket.if_nameindex()),
        "connect": {target: connect(target) for target in spec["targets"]},
        "resolve": resolve("example.org"),
        "write": {path: write(path) for path in ("/src/probe-write", "/src/repo/probe-write", "/db/probe-write")},
        "forks": fork_bomb(spec["fork_cap"]),
        "tmp": fill(spec["tmp_cap"]),
    }


def leave(token):
    path = os.path.join(tempfile.gettempdir(), "left")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(token.upper())
    return path


def holds(path, needle):
    try:
        if os.path.islink(path) or not os.path.isfile(path) or os.path.getsize(path) > SEEK_MAX_BYTES:
            return False
        with open(path, "rb") as handle:
            return needle in handle.read()
    except OSError:
        return False


def seek(token):
    needle, found = token.upper().encode(), []
    for directory, subdirectories, files in os.walk("/"):
        if directory.startswith(SKIPPED):
            subdirectories[:] = []
            continue
        found += [os.path.join(directory, name) for name in files if holds(os.path.join(directory, name), needle)]
    return found


def stay():
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    while True:
        time.sleep(60)


def act(probe, notes):
    if "leave" in probe:
        notes["left"] = leave(probe["leave"])
    if "isolation" in probe:
        notes["isolation"] = isolation(probe["isolation"])
    if "seek" in probe:
        notes["found"] = seek(probe["seek"])
    if "egress" in probe:
        notes["egress"] = {target: {"proxy": through_proxy(target), "direct": connect(target)} for target in probe["egress"]}
    if "stay" in probe:
        stay()
    if "hold" in probe:
        time.sleep(probe["hold"])
    return notes


def check():
    notes = act(instructions(names(run_git("ls-files", "-z")) or []), observe())
    print(json.dumps({**EMPTY_REPORT, "notes": [json.dumps(notes, sort_keys=True)]}))
    return 0


def database(bundle):
    directory = os.path.dirname(bundle)
    path = os.path.join(directory, "probe.json")
    probe = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as handle:
            probe = json.load(handle)["probe"]
    notes = act(probe, {"mounts": mounts(), "environment": dict(os.environ), "uid": os.getuid()})
    result = os.path.join(directory, "probe-result.json")
    with open(result, "w", encoding="utf-8") as handle:
        json.dump(notes, handle, sort_keys=True)
    os.chmod(result, 0o644)
    return 0


def quality(args):
    if args[:1] == ["check"]:
        return check()
    if args[:2] == ["db", "update"]:
        return database(args[args.index("--db") + 1])
    return 2


def git_holding(args):
    if "add" in args[:3] or any("hold" in arg for arg in args):
        time.sleep(HOLD_SECONDS)
    os.execv(GIT, [GIT, *args])


if __name__ == "__main__":
    if os.path.basename(sys.argv[0]) == "git":
        git_holding(sys.argv[1:])
    sys.exit(quality(sys.argv[1:]))
