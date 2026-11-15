import base64
import json
import os
import secrets
import shutil
import string
import subprocess
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from tests.egress.support import (
    COMPOSE,
    DEV_CONFIG,
    FETCH_NETWORK,
    LABEL,
    LOW_PORTS,
    ROOT,
    SCAN_IMAGE,
    address,
    docker,
    peer,
    start_proxy,
)
from tests.integration.support import TEST_DB

HERE = Path(__file__).parent
PROBE_DIR = HERE / "probe"
BENCH = PROBE_DIR / "bench.py"
GITSERVER = HERE / "gitserver.py"
FIXTURES = HERE / "fixtures"
ROLE = ROOT / "ansible" / "roles" / "web-app-cst-quality-check"
SCRIPT = ROLE / "files" / "python" / "script.py"
LAUNCHER_IMAGE = "quality-check/launcher:local"
WEB_IMAGE = "quality-check/web:local"
TRUSTING_IMAGE = "quality-check/egress-trusting:test"
PROBE_IMAGE = "quality-check/egress-probe:test"
JOB_LABEL = "quality-check.job"
FRONT_NETWORK = "quality-check-inspect_front"
SOCKET = "/var/run/docker.sock"
GIT_HOST = "git.fixture.test"
CANARY_HOST = "canary.fixture.test"
WEB_ORIGIN = "https://quality.fixture.test"
CORE_WRAPPER = "/opt/core/container.py"
LAUNCHER_CONFIG = "/etc/quality-check/config.json"
MIB = 1 << 20
RUN_SECONDS = 900
READY_SECONDS = 120
DATABASE_HOURS = 24
BUNDLE_MODE = 0o555
TOKEN_ALPHABET = string.ascii_letters + string.digits


def logs(container):
    result = subprocess.run(["docker", "logs", container], capture_output=True, text=True, timeout=60, check=False)
    return result.stdout + result.stderr


def wait_until(predicate, seconds, what):
    deadline = time.monotonic() + seconds
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError(f"{what} did not happen within {seconds} seconds")
        time.sleep(0.5)


def job_containers():
    return docker("ps", "-aq", "--filter", f"label={JOB_LABEL}").split()


def running_steps():
    return docker("ps", "--filter", f"label={JOB_LABEL}", "--format", "{{.Names}}").split()


def root_writes(container):
    """
    Returns:
        Lines of `docker container diff` for paths that are neither a mount point of the container nor a parent of one.
    """
    info = json.loads(docker("inspect", container))[0]
    points = [mount["Destination"] for mount in info["Mounts"]] + list(info["HostConfig"].get("Tmpfs") or {})
    resolve = "import os, sys; print('\\n'.join(os.path.realpath(point) for point in sys.argv[1:]))"
    points += docker("run", "--rm", "--network=none", "--entrypoint=python3", info["Image"], "-c", resolve, *points).splitlines()
    stubs = {str(path) for point in points for path in (Path(point), *Path(point).parents)}
    return [line for line in docker("container", "diff", container).splitlines() if line.split(" ", 1)[1] not in stubs]


def image_environment(image):
    return json.loads(docker("image", "inspect", "--format", "{{json .Config.Env}}", image))


def github_token():
    return "ghp_" + "".join(secrets.choice(TOKEN_ALPHABET) for _ in range(36))


def url_job(path):
    return {"kind": "url", "url": f"https://{GIT_HOST}/{path}"}


def file_job(name, content):
    data = content if isinstance(content, bytes) else content.encode()
    return {"kind": "file", "name": name, "content": base64.b64encode(data).decode()}


def text_job(language, content):
    return {"kind": "text", "language": language, "content": base64.b64encode(content.encode()).decode()}


def probe_job(probe, **extra):
    """
    Args:
        probe: Instructions tests/egress/probe/probe.py follows in the scan step.
        extra: Further top-level fields of the instruction file, such as a payload another job seeks.
    """
    return file_job("probe.json", json.dumps({"probe": probe, **extra}))


def certificate(directory):
    """
    Returns:
        (certificate, key) of a self-signed certificate for GIT_HOST, readable by the server's user.
    """
    pem, key = directory / "certificate.pem", directory / "key.pem"
    request = ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes"]
    request += ["-days", "2", "-subj", f"/CN={GIT_HOST}", "-addext", f"subjectAltName=DNS:{GIT_HOST}"]
    subprocess.run([*request, "-keyout", str(key), "-out", str(pem)], check=True, capture_output=True, timeout=60)
    for path in (pem, key):
        path.chmod(0o644)
    return pem, key


def build_images(directory):
    """
    Args:
        directory: Scratch directory for the certificate and the build context.

    Returns:
        (certificate, key) the trusting and probe images accept for GIT_HOST.
    """
    pem, key = certificate(directory)
    context = directory / "context"
    context.mkdir()
    shutil.copy(pem, context / "certificate.pem")
    shutil.copy(PROBE_DIR / "probe.py", context / "probe.py")
    (context / "probe.py").chmod(0o755)
    for target, tag in (("trusting", TRUSTING_IMAGE), ("probe", PROBE_IMAGE)):
        docker("build", "--quiet", f"--target={target}", f"--tag={tag}", f"--file={PROBE_DIR / 'Dockerfile'}", str(context), timeout=600)
    return pem, key


@contextmanager
def stack_launcher_stopped():
    docker("compose", "-f", str(COMPOSE), "stop", "launcher")
    try:
        yield
    finally:
        docker("compose", "-f", str(COMPOSE), "start", "launcher")


class FetchWorld:
    def __init__(self, directory, pair, repositories, runtime):
        """
        Args:
            directory: Scratch directory for the repository spec and the proxy's site.conf.
            pair: (certificate, key) the git server presents.
            repositories: Repositories added to fixtures/repositories.json.
            runtime: Container runtime the test proxy runs under.
        """
        spec = directory / "repositories.json"
        spec.write_text(json.dumps({**json.loads((FIXTURES / "repositories.json").read_text(encoding="utf-8")), **repositories}))
        spec.chmod(0o644)
        mounts = [f"{GITSERVER}:/gitserver.py:ro", f"{spec}:/repositories.json:ro", f"{pair[0]}:/certificate.pem:ro", f"{pair[1]}:/key.pem:ro"]
        flags = ["--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=256", "--tmpfs=/tmp:size=64m"]
        flags += ["--env=HOME=/tmp", LOW_PORTS, *(item for mount in mounts for item in ("-v", mount))]
        command = ["python3", "/gitserver.py", "/repositories.json", "/certificate.pem", "/key.pem"]
        self.server = docker("run", "-d", "--label", LABEL, f"--network={FETCH_NETWORK}", *flags, SCAN_IMAGE, *command)
        wait_until(lambda: "ready" in logs(self.server), READY_SECONDS, "the fixture git server's start")
        self.listener = peer("listen", detach=True, extra=[LOW_PORTS])
        hosts = {GIT_HOST: address(self.server), CANARY_HOST: address(self.listener)}
        site = directory / "test-proxy.conf"
        site.write_text((FIXTURES / "test-proxy.conf").read_text(encoding="utf-8").format(servers=" ".join(hosts.values())))
        site.chmod(0o644)
        self.proxy = start_proxy(site, hosts, runtime)
        self.control = json.loads(peer("request", self.proxy, f"CONNECT {CANARY_HOST}:443"))
        if self.control == [200]:
            wait_until(lambda: self.hits() == 1, READY_SECONDS, "the canary listener's hit from the control request")

    def hits(self):
        return logs(self.listener).split().count("hit")

    def requests(self):
        return logs(self.server).splitlines()


class Bench:
    state_bytes = 64 * MIB

    def __init__(self, directory, image, proxy, runtime):
        """
        Args:
            directory: Fresh scratch directory; jobs/ and db/ below it are bound into the launcher at their own paths,
                db/bundle holds hard links to the integration suite's bundle and db/.updated is fresh.
            image: Image every step of the launcher runs.
            proxy: Address of the egress proxy the fetch and database steps use.
            runtime: Container runtime every step runs under, in place of the one service/dev/config.json names.
        """
        self.directory = directory
        self.state = f"quality-check-egress-{secrets.token_hex(6)}"
        self.jobs, self.db = directory / "jobs", directory / "db"
        self.jobs.mkdir(parents=True)
        self.db.mkdir()
        self.db.chmod(0o777)
        shutil.copytree(TEST_DB, self.db / "bundle", copy_function=os.link)
        (self.db / "bundle").chmod(BUNDLE_MODE)
        self.stamp = self.db / ".updated"
        self.stamp.write_text("", encoding="utf-8")
        self.config = json.loads(DEV_CONFIG.read_text(encoding="utf-8"))
        self.config.update(state_dir="/state", jobs_dir=str(self.jobs), job_storage="tmpfs", container=["docker"], runtime=runtime)
        self.config["images"] = {"scan": image, "scan_version": "egress-test"}
        self.config["fetch"].update(proxy=f"http://{proxy}:3128", user_agent="quality-check egress test")
        self.config["database"] = {"dir": str(self.db), "update_hours": DATABASE_HOURS, "max_age_hours": 168}
        self.config["limits"]["timeouts"].update(fetch=60, prepare=30, scan=300, database=120)
        self.config["limits"]["step"]["memory"] = "1g"
        self.keeper, self.launchers, self.flags = None, [], []

    def __enter__(self):
        options = ["--driver=local", "--opt=type=tmpfs", "--opt=device=tmpfs", f"--opt=o=size={self.state_bytes}"]
        docker("volume", "create", "--label", LABEL, *options, self.state)
        self.keeper = docker("run", "-d", "--label", LABEL, "--network=none", *self.state_mount(), PROBE_IMAGE, "sleep", "infinity")
        self.tool("init")
        return self

    def __exit__(self, *_exception):
        docker("rm", "-f", *self.launchers, self.keeper)
        docker("volume", "rm", "-f", self.state)
        bundle = self.db / "bundle"
        for directory in [bundle, *(path for path in bundle.rglob("*") if path.is_dir())]:
            directory.chmod(0o755)
        shutil.rmtree(bundle)

    def state_mount(self):
        return ["--mount", f"type=volume,source={self.state},target=/state"]

    def tool(self, *args, stdin=b""):
        command = ["docker", "run", "--rm", "-i", "--label", LABEL, "--user=0:0", "--network=none", *self.state_mount()]
        command += ["-v", f"{BENCH}:/bench.py:ro", PROBE_IMAGE, "python3", "/bench.py", *args]
        result = subprocess.run(command, input=stdin, capture_output=True, timeout=180, check=False)
        if result.returncode != 0:
            raise AssertionError(f"bench {args[0]} failed: {result.stderr.decode(errors='replace').strip()}")
        return result.stdout.decode()

    def wrap(self, wrapper, environment):
        """
        Args:
            wrapper: Host path of core's container.py, which the launcher then calls instead of docker.
            environment: {name: value} the launcher process starts with.
        """
        self.config["container"] = ["python3", CORE_WRAPPER]
        self.flags += ["-v", f"{wrapper}:{CORE_WRAPPER}:ro", *(f"--env={name}={value}" for name, value in environment.items())]

    def database(self, probe, age_hours):
        """
        Args:
            probe: Instructions the probe follows in the database step.
            age_hours: Age of the database stamp; None removes it and the run updates the database.
        """
        instructions = self.db / "probe.json"
        instructions.write_text(json.dumps({"probe": probe}), encoding="utf-8")
        instructions.chmod(0o644)
        if age_hours is None:
            self.stamp.unlink()
            return
        then = time.time() - age_hours * 3600
        os.utime(self.stamp, (then, then))

    def database_result(self):
        return json.loads((self.db / "probe-result.json").read_text(encoding="utf-8"))

    def submit(self, job, tier=2):  # nocheck: clean.default-value -- anonymous, the tier that needs no account
        """
        Args:
            job: Job object as the web app spools it.
            tier: Index into the launcher's TIERS; 2 (anonymous) by default, the tier that needs no account.
        """
        job_id = secrets.token_hex(16)
        self.tool("put", f"{tier}-{job_id}.json", stdin=json.dumps(job).encode())
        return job_id

    def start(self):
        config = self.directory / f"launcher-{len(self.launchers)}.json"
        config.write_text(json.dumps(self.config), encoding="utf-8")
        config.chmod(0o644)
        flags = ["-d", "--label", LABEL, "--network=none", "--cap-add=SYS_ADMIN", "--security-opt=apparmor=unconfined"]
        flags += ["-v", f"{SOCKET}:{SOCKET}", *self.state_mount()]
        flags += ["--mount", f"type=bind,source={self.jobs},target={self.jobs},bind-propagation=rshared"]
        flags += ["--mount", f"type=bind,source={self.db},target={self.db}", "-v", f"{config}:{LAUNCHER_CONFIG}:ro"]
        flags += ["-v", f"{SCRIPT}:/launcher.py:ro", *self.flags, "--entrypoint=python3"]
        container = docker("run", *flags, LAUNCHER_IMAGE, "/launcher.py", LAUNCHER_CONFIG)
        self.launchers.append(container)
        return container

    def finish(self, container):
        return int(docker("wait", container, timeout=RUN_SECONDS)), logs(container)

    def run(self):
        return self.finish(self.start())

    def report(self, job_id):
        document = json.loads(self.tool("cat", f"reports/{job_id}.json"))
        return json.loads(document["text"]) if document["exists"] else None

    def notes(self, job_id):
        report = self.report(job_id)
        if report is None or report["status"] != "done":
            raise AssertionError(f"probe job {job_id} ended as {report}")
        return json.loads(report["result"]["notes"][0])

    def find(self, needle):
        return json.loads(self.tool("find", needle))

    def job_mounts(self):
        return sorted(os.listdir(self.jobs))


class Web:
    def __init__(self, bench):
        """
        Args:
            bench: Bench whose state volume the web app spools into.
        """
        self.bench = bench
        self.name = f"quality-check-egress-web-{secrets.token_hex(4)}"
        self.url = f"http://{self.name}:8080"
        config = json.loads(DEV_CONFIG.read_text(encoding="utf-8"))
        config.update(state_dir="/state", public_url=WEB_ORIGIN)
        config["access"]["captcha"] = False
        self.config, self.secret = bench.directory / "web.json", bench.directory / "web-secret"
        self.config.write_text(json.dumps(config), encoding="utf-8")
        self.secret.write_text(base64.b64encode(secrets.token_bytes(48)).decode(), encoding="utf-8")
        for path in (self.config, self.secret):
            path.chmod(0o644)
        self.container = None

    def __enter__(self):
        state = self.bench.state
        flags = ["--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--tmpfs=/tmp:size=16m"]
        flags += ["-v", f"{self.config}:/etc/quality-web/config.json:ro", "-v", f"{self.secret}:/run/secrets/web:ro"]
        flags += ["-v", f"{ROLE / 'files' / 'legal'}:/legal:ro"]
        flags += ["--mount", f"type=volume,source={state},target=/state/spool,volume-subpath=spool"]
        flags += ["--mount", f"type=volume,source={state},target=/state/reports,readonly,volume-subpath=reports"]
        self.container = docker("run", "-d", "--label", LABEL, f"--name={self.name}", f"--network={FRONT_NETWORK}", *flags, WEB_IMAGE)
        self.client("wait", f"{self.url}/healthz")
        return self

    def __exit__(self, *_exception):
        docker("rm", "-f", self.container)

    def client(self, *args):
        command = ["run", "--rm", "--label", LABEL, f"--network={FRONT_NETWORK}", "-v", f"{BENCH}:/bench.py:ro"]
        return docker(*command, PROBE_IMAGE, "python3", "/bench.py", *args)

    def submit(self, **fields):
        """
        Returns:
            (status, job id from the report link or None) of an anonymous form submission.
        """
        form = [f"{name}={value}" for name, value in fields.items()]
        answer = json.loads(self.client("submit", f"{self.url}/submit", WEB_ORIGIN, *form))
        location = answer["location"]
        return answer["status"], None if location is None else location.rsplit("/", 1)[-1]

    def page(self, job_id):
        return json.loads(self.client("get", f"{self.url}/r/{job_id}"))


class Watcher:
    def __init__(self):
        self.seen, self.stopped = {}, threading.Event()
        self.thread = threading.Thread(target=self.watch, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_exception):
        self.stopped.set()
        self.thread.join()

    def watch(self):
        while not self.stopped.is_set():
            for container in docker("ps", "-q", "--filter", f"label={JOB_LABEL}").split():
                if container not in self.seen:
                    self.inspect(container)
            time.sleep(0.2)

    def inspect(self, container):
        try:
            self.seen[container] = json.loads(docker("inspect", container))[0]
        except AssertionError:
            pass

    def steps(self):
        """
        Returns:
            {container name: docker inspect document} of every job container seen while running.
        """
        return {info["Name"].lstrip("/"): info for info in self.seen.values()}
