# nocheck: mirrored-unit-test - its tests live in this role's own repository under tests/service, which core cannot mirror
"""
Args:
    argv[1]: path of the launcher configuration (JSON) the role renders.

Exit codes:
    0 the run worked, 1 the database update failed, 2 the sandbox runtime is not installed.
"""

import base64
import binascii
import concurrent.futures
import ipaddress
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit

JOB_FILE = re.compile(r"^([0-2])-([0-9a-f]{32})\.json$")
JOB_ID = re.compile(r"^[0-9a-f]{32}$")
REPORT_FILE = re.compile(r"^([0-9a-f]{32})\.(json|running)$")
HOST_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
TOP_LABEL = re.compile(r"^[a-z][a-z0-9-]*$")
URL_TEXT = re.compile(r"^https://[^\s?#@\\%]{1,2040}$")
URL_PATH = re.compile(r"^/[A-Za-z0-9._~/-]+$")
UNSAFE_NAME = re.compile(r"[^A-Za-z0-9._-]")
TIERS = ("member", "registered", "anonymous")
EXTENSIONS = {"python": "py", "javascript": "js", "typescript": "ts", "shell": "sh", "php": "php"}
EXTENSIONS.update({"go": "go", "rust": "rs", "java": "java", "ruby": "rb", "yaml": "yml"})
LANGUAGES = {**{name: f"snippet.{ext}" for name, ext in EXTENSIONS.items()}, "dockerfile": "Dockerfile"}
TEXT, LINE, NOTHING = (str,), (int, type(None)), type(None)
FINDING = {"rule": TEXT, "path": TEXT, "line": LINE, "summary": TEXT, "commit": (str, NOTHING)}
FINDING.update({"severity": {"critical", "high", "medium", "low"}, "value": (int, float, NOTHING)})
IGNORED = {"rule": TEXT, "paths": "strings", "reason": TEXT}
NOCHECK = {"path": TEXT, "line": LINE, "rule": TEXT}
REPORT = {"findings": [FINDING], "ignored": [IGNORED], "nocheck": [NOCHECK]}
REPORT.update({"unchecked": "strings", "notes": "strings", "incomplete": "strings"})
LABEL = "quality-check.job"
STEP_USER = "65534:65534"
TIMEOUT_EXIT = 124
CLEAN_ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
STOP_GRACE_SECONDS = 15
STALE_TEMPORARY_SECONDS = 3600
FETCH_SCRIPT = (
    'git -c http.followRedirects=false -c transfer.fsckObjects=true -c "http.userAgent=$2" '
    'clone --quiet --depth 1 --no-checkout --single-branch -- "$1" /src/repo '
    "&& git -C /src/repo read-tree HEAD && git -C /src/repo rev-parse HEAD"
)
PREPARE_SCRIPT = 'git init -q /src/repo && cat > "/src/repo/$1" && git -C /src/repo add -- "$1"'
SCAN_SCRIPT = "cd /src/repo && exec quality check --all --json"
FETCH_ENVIRONMENT = ("--env=GIT_ALLOW_PROTOCOL=https", "--env=GIT_TERMINAL_PROMPT=0")
FETCH_ENVIRONMENT += ("--env=GIT_CONFIG_NOSYSTEM=1", "--env=GIT_CONFIG_GLOBAL=/dev/null")


class JobFailed(Exception):
    pass


def valid_url(url):
    """
    Args:
        url: Submitted repository URL.

    Returns:
        True only for an https URL to a named public host on port 443 with a plain path.
    """
    if not isinstance(url, str) or not URL_TEXT.match(url):
        return False
    parts = urlsplit(url)
    host = parts.hostname or ""
    return parts.netloc in (host, f"{host}:443") and bool(URL_PATH.match(parts.path)) and valid_host(host)


def valid_host(host):
    labels = host.split(".")
    if len(labels) < 2 or not all(HOST_LABEL.match(label) for label in labels):
        return False
    if not TOP_LABEL.match(labels[-1]):
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return True
    return False


def safe_name(name):
    base = re.split(r"[/\\]", str(name))[-1]
    # Exception: a name of only dots and dashes strips to nothing, yet the scan still needs a file to write the upload to
    return UNSAFE_NAME.sub("_", base).lstrip(".-")[:100] or "upload"


def job_file_name(tier, job_id):
    return f"{TIERS.index(tier)}-{job_id}.json"


def parse_job(raw, upload_bytes):
    job = json.loads(raw)
    if not isinstance(job, dict) or job.get("kind") not in ("url", "file", "text"):
        raise JobFailed("invalid job")
    if job["kind"] == "url":
        if not valid_url(job.get("url")):
            raise JobFailed("invalid url")
        return {"kind": "url", "url": job["url"]}
    content = decoded(job.get("content"), upload_bytes)
    if job["kind"] == "text":
        if job.get("language") not in LANGUAGES:
            raise JobFailed("invalid language")
        return {"kind": "text", "name": LANGUAGES[job["language"]], "content": content}
    return {"kind": "file", "name": safe_name(job.get("name", "")), "content": content}


def decoded(text, limit):
    if not isinstance(text, str):
        raise JobFailed("invalid content")
    try:
        content = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as error:
        raise JobFailed("invalid content") from error
    if len(content) > limit:
        raise JobFailed("too large")
    return content


def fits(value, kind):
    """
    Args:
        value: Parsed JSON value of the scan step.
        kind: "strings", a one-item list, a key map, a set of allowed strings, or a tuple of exact types.

    Returns:
        True when value has exactly that shape; bool never counts as a number.
    """
    if kind == "strings":
        return isinstance(value, list) and all(type(item) is str for item in value)
    if isinstance(kind, list):
        return isinstance(value, list) and all(fits(item, kind[0]) for item in value)
    if isinstance(kind, dict):
        return fits_map(value, kind)
    if isinstance(kind, set):
        return isinstance(value, str) and value in kind
    return type(value) in kind


def fits_map(value, kind):
    shaped = isinstance(value, dict) and set(value) == set(kind)
    return shaped and all(fits(value[key], inner) for key, inner in kind.items())


def failed(reason):
    return {"status": "failed", "reason": reason, "finished": int(time.time())}


def feed(process, stdin):
    if stdin is None:
        return
    try:
        process.stdin.write(stdin)
        process.stdin.close()
    except BrokenPipeError:
        pass


def discard(directory, name):
    target = os.path.join(directory, name)
    if os.path.isdir(target) and not os.path.islink(target):
        shutil.rmtree(target)
    elif os.path.lexists(target):
        os.unlink(target)


class Launcher:
    def __init__(self, config):
        self.config = config
        self.limits = config["limits"]
        self.state = config["state_dir"]
        self.database = config["database"]

    def path(self, *parts):
        return os.path.join(self.state, *parts)

    def cli(self, *args, timeout):
        argv = [*self.config["container"], *args]
        return subprocess.run(argv, env=CLEAN_ENV, capture_output=True, text=True, timeout=timeout, check=False)

    def require_runtime(self):
        result = self.cli("info", "--format", "{{json .Runtimes}}", timeout=60)
        runtimes = json.loads(result.stdout or "{}") if result.returncode == 0 else {}
        if self.config["runtime"] not in runtimes:
            print(f"launcher: runtime {self.config['runtime']} is not installed", file=sys.stderr)
            raise SystemExit(2)

    def reap(self):
        containers = self.cli("ps", "-aq", "--filter", f"label={LABEL}", timeout=60).stdout.split()
        if containers:
            self.cli("rm", "-f", *containers, timeout=120)
        if self.config["job_storage"] == "volume":
            volumes = self.cli("volume", "ls", "-q", "--filter", f"label={LABEL}", timeout=60).stdout.split()
            if volumes:
                self.cli("volume", "rm", "-f", *volumes, timeout=120)
            return
        for name in os.listdir(self.config["jobs_dir"]):
            self.unmount(os.path.join(self.config["jobs_dir"], name))

    def unmount(self, path):
        if os.path.ismount(path):
            subprocess.run(["umount", path], env=CLEAN_ENV, check=False)
        if os.path.isdir(path) and not os.path.islink(path):
            os.rmdir(path)

    def recover(self):
        claimed = self.path("claimed")
        for name in os.listdir(claimed):
            match = JOB_FILE.match(name)
            if match:
                self.write_report(match.group(2), failed("interrupted"))
            discard(claimed, name)
        for entry in os.scandir(self.path("reports")):
            match = REPORT_FILE.match(entry.name)
            if match and match.group(2) == "running":
                self.write_report(match.group(1), failed("interrupted"))
                os.unlink(entry.path)
            elif entry.name.startswith("."):
                os.unlink(entry.path)

    def expire(self):
        cutoff = time.time() - self.limits["retention_hours"] * 3600
        for entry in os.scandir(self.path("reports")):
            if REPORT_FILE.match(entry.name) and entry.stat(follow_symlinks=False).st_mtime < cutoff:
                os.unlink(entry.path)

    def claim(self):
        spool = self.path("spool")
        candidates = []
        for entry in os.scandir(spool):
            modified = entry.stat(follow_symlinks=False).st_mtime
            if entry.name.startswith("."):
                if modified < time.time() - STALE_TEMPORARY_SECONDS:
                    discard(spool, entry.name)
            elif JOB_FILE.match(entry.name):
                candidates.append((entry.name[0], modified, entry.name))
            else:
                discard(spool, entry.name)
        names = [name for _tier, _modified, name in sorted(candidates)[: self.limits["jobs_per_run"]]]
        for name in names:
            # Exception: the marker comes first, so the web app's report link always finds the job in one place
            marker = self.path("reports", f"{name[2:34]}.running")
            with open(marker, "w", encoding="utf-8"):
                os.chmod(marker, 0o644)
            os.rename(os.path.join(spool, name), self.path("claimed", name))
        return names

    def read_claimed(self, name):
        directory = os.open(self.path("claimed"), os.O_RDONLY | os.O_DIRECTORY)
        try:
            handle = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        finally:
            os.close(directory)
        if not stat.S_ISREG(os.fstat(handle).st_mode):
            os.close(handle)
            raise JobFailed("invalid job")
        with os.fdopen(handle, "rb") as stream:
            raw = stream.read(self.limits["job_bytes"] + 1)
        if len(raw) > self.limits["job_bytes"]:
            raise JobFailed("too large")
        return raw

    def run_job(self, name):
        tier, job_id = TIERS[int(name[0])], name[2:34]
        marker = self.path("reports", f"{job_id}.running")
        try:
            if not os.path.lexists(self.path("reports", f"{job_id}.json")):
                self.write_report(job_id, self.outcome(name, tier, job_id))
        # Exception: deliberately blind, a hostile or broken job must end as "not checked", never stop the launcher serving every other job
        except Exception:
            self.write_report(job_id, failed("not checked"))
        finally:
            discard(self.path("claimed"), name)
            if os.path.lexists(marker):
                os.unlink(marker)

    def outcome(self, name, tier, job_id):
        try:
            job = parse_job(self.read_claimed(name), self.limits["upload_bytes"])
            discard(self.path("claimed"), name)
            self.require_fresh_database()
            with JobStorage(self, job_id, tier) as storage:
                commit = self.fetch(storage, job) if job["kind"] == "url" else self.prepare(storage, job)
                return self.scan(storage, job, commit)
        except JobFailed as error:
            return failed(str(error))
        except (ValueError, RecursionError):
            return failed("invalid job")

    def database_age(self):
        stamp = os.path.join(self.database["dir"], ".updated")
        return time.time() - os.path.getmtime(stamp) if os.path.exists(stamp) else None

    def require_fresh_database(self):
        if self.database["update_hours"] is None:
            return
        age = self.database_age()
        if age is None or age > self.database["max_age_hours"] * 3600:
            raise JobFailed("database too old")

    def sandbox(self, name, network):
        step = self.limits["step"]
        return [
            *self.config["container"], "run", "--rm", "--interactive", f"--name={name}",
            f"--label={LABEL}={name}", "--read-only", f"--user={STEP_USER}", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", f"--pids-limit={step['pids']}",
            f"--memory={step['memory']}", f"--memory-swap={step['memory']}", f"--cpus={step['cpus']}",
            f"--tmpfs=/tmp:size={step['tmp_bytes']}", f"--runtime={self.config['runtime']}",
            f"--network={network}", "--env=HOME=/tmp", "--env=XDG_CACHE_HOME=/tmp", "--log-driver=none",
        ]

    def step(self, storage, step_name, command, stdin=None):
        seconds = self.limits["timeouts"][step_name]
        container = f"quality-check-{storage.job_id}-{step_name}"
        fetching = step_name == "fetch"
        argv = self.sandbox(container, self.config["fetch"]["network"] if fetching else "none")
        if fetching:
            argv += [f"--env=https_proxy={self.config['fetch']['proxy']}", *FETCH_ENVIRONMENT]
        argv.append(storage.mount_flag(step_name == "scan"))
        if step_name == "scan" and self.database["update_hours"] is not None:
            argv.append(f"--mount=type=bind,source={self.database['dir']},target=/db,readonly")
        argv += ["--workdir=/src", self.config["images"]["scan"], "timeout", str(seconds), *command]
        return self.bounded(argv, container, stdin, seconds)

    def bounded(self, argv, container, stdin, seconds):
        limit = self.limits["report_bytes"]
        killer = threading.Timer(seconds + STOP_GRACE_SECONDS, self.remove, (container,))
        killer.start()
        stdin_mode = subprocess.PIPE if stdin is not None else subprocess.DEVNULL
        try:
            with subprocess.Popen(
                argv, stdin=stdin_mode, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=CLEAN_ENV
            ) as process:
                feed(process, stdin)
                output = process.stdout.read(limit + 1)
                if len(output) > limit:
                    self.remove(container)
                    output = b""
                code = process.wait()
        finally:
            killer.cancel()
        return code, output

    def remove(self, container):
        self.cli("rm", "-f", container, timeout=120)

    def fetch(self, storage, job):
        url = job["url"]
        for candidate in [url] if url.endswith(".git") else [url, url + ".git"]:
            command = ["sh", "-c", FETCH_SCRIPT, "sh", candidate, self.config["fetch"]["user_agent"]]
            code, output = self.step(storage, "fetch", command)
            if code == 0:
                return output.decode("ascii", "replace").strip()[:64]
            if code == TIMEOUT_EXIT:
                raise JobFailed("timeout")
            if storage.full():
                raise JobFailed("too large")
        raise JobFailed("not reachable")

    def prepare(self, storage, job):
        command = ["sh", "-c", PREPARE_SCRIPT, "sh", job["name"]]
        code, _output = self.step(storage, "prepare", command, stdin=job["content"])
        if code == TIMEOUT_EXIT:
            raise JobFailed("timeout")
        if code != 0:
            raise JobFailed("too large" if storage.full() else "not checked")

    def scan(self, storage, job, commit):
        code, output = self.step(storage, "scan", ["sh", "-c", SCAN_SCRIPT])
        if code == TIMEOUT_EXIT:
            raise JobFailed("timeout")
        if code not in (0, 1):
            raise JobFailed("not checked")
        try:
            document = json.loads(output)
        except ValueError as error:
            raise JobFailed("invalid report") from error
        if not fits(document, REPORT):
            raise JobFailed("invalid report")
        history = "HEAD only: history not scanned" if job["kind"] == "url" else None
        report = {"status": "done", "reason": None, "kind": job["kind"], "commit": commit, "history": history}
        report.update({"quality": self.config["images"]["scan_version"], "database": self.database_header()})
        return {**report, "result": document, "finished": int(time.time())}

    def database_header(self):
        age = self.database_age() if self.database["update_hours"] is not None else None
        return None if age is None else {"updated": int(time.time() - age)}

    def write_report(self, job_id, document):
        if not JOB_ID.match(job_id):
            return
        final = self.path("reports", f"{job_id}.json")
        temporary = self.path("reports", f".{job_id}.{threading.get_ident()}.tmp")
        with open(temporary, "x", encoding="utf-8") as handle:
            json.dump(document, handle, sort_keys=True)
        os.chmod(temporary, 0o644)
        try:
            os.link(temporary, final)
        except FileExistsError:
            pass
        finally:
            os.unlink(temporary)

    def update_database(self):
        if self.database["update_hours"] is None:
            return True
        age = self.database_age()
        if age is not None and age < self.database["update_hours"] * 3600:
            return True
        argv = self.sandbox("quality-check-database", self.config["fetch"]["network"])
        argv += [
            f"--env=https_proxy={self.config['fetch']['proxy']}",
            f"--mount=type=bind,source={self.database['dir']},target=/db",
            self.config["images"]["scan"],
            "timeout",
            str(self.limits["timeouts"]["database"]),
            *("quality", "db", "update", "--db", "/db"),
        ]
        if subprocess.run(argv, env=CLEAN_ENV, capture_output=True, check=False).returncode != 0:
            return False
        with open(os.path.join(self.database["dir"], ".updated"), "w", encoding="utf-8"):
            return True


class JobStorage:
    def __init__(self, launcher, job_id, tier):
        self.launcher = launcher
        self.job_id = job_id
        self.tier = tier
        self.mode = launcher.config["job_storage"]
        self.volume = f"quality-check-job-{job_id}"
        self.mountpoint = os.path.join(launcher.config["jobs_dir"], job_id)

    def __enter__(self):
        limits = self.launcher.limits
        if self.mode == "volume":
            self.launcher.cli("volume", "create", f"--label={LABEL}={self.job_id}", self.volume, timeout=60)
            return self
        os.mkdir(self.mountpoint, 0o700)
        options = (
            f"size={limits['repo_bytes'][self.tier]},nr_inodes={limits['inodes']},"
            "uid=65534,gid=65534,mode=0700,nosuid,nodev,noexec"
        )
        subprocess.run(["mount", "-t", "tmpfs", "-o", options, "tmpfs", self.mountpoint], env=CLEAN_ENV, check=True)
        return self

    def __exit__(self, *_exception):
        if self.mode == "volume":
            self.launcher.cli("volume", "rm", "-f", self.volume, timeout=120)
            return
        self.launcher.unmount(self.mountpoint)

    def mount_flag(self, readonly):
        suffix = ",readonly" if readonly else ""
        if self.mode == "volume":
            return f"--mount=type=volume,source={self.volume},target=/src{suffix}"
        return f"--mount=type=bind,source={self.mountpoint},target=/src{suffix}"

    def full(self):
        if self.mode == "volume":
            return False
        usage = os.statvfs(self.mountpoint)
        return usage.f_bavail * usage.f_frsize < 1024 * 1024 or usage.f_favail < 16


def stop(launcher):
    launcher.reap()
    os._exit(143)


def main(argv):
    with open(argv[1], encoding="utf-8") as handle:
        launcher = Launcher(json.load(handle))
    signal.signal(signal.SIGTERM, lambda *_signal: stop(launcher))
    launcher.reap()
    launcher.recover()
    launcher.require_runtime()
    launcher.expire()
    names = launcher.claim()
    with concurrent.futures.ThreadPoolExecutor(launcher.limits["concurrency"]) as pool:
        list(pool.map(launcher.run_job, names))
    print(f"launcher: {len(names)} job(s)", file=sys.stderr)
    return 0 if launcher.update_database() else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
