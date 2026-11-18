import json
import os
import secrets
import time
from pathlib import Path

import pytest

from tests.egress.isolation_support import (
    GIT_HOST,
    MIB,
    PROBE_IMAGE,
    TRUSTING_IMAGE,
    Bench,
    FetchWorld,
    Watcher,
    Web,
    github_token,
    image_environment,
    job_containers,
    logs,
    probe_job,
    root_writes,
    running_steps,
    url_job,
    wait_until,
)
from tests.egress.support import FETCH_NETWORK, STACK_PROXY, docker

pytestmark = pytest.mark.usefixtures("vulnerability_database", "quiet_stack", "pair")
CORE_DIR = "INFINITO_CORE_DIR"
CORE_WRAPPER = Path("roles") / "sys-svc-container" / "files" / "python" / "container.py"
PIDS = 32
TMP_BYTES = 8 * MIB
STAY_SECONDS = 10
DUE_HOURS = 100
STOP_GRACE_SECONDS = 15
SLACK_SECONDS = 60
UNREACHABLE = {"ENETUNREACH", "EHOSTUNREACH", "timeout"}
WRITES = ("/src/probe-write", "/src/repo/probe-write", "/db/probe-write")
STEP_ENVIRONMENT = ["HOME=/tmp", "XDG_CACHE_HOME=/tmp"]
STEP_HOME = STEP_ENVIRONMENT[0].partition("=")[2]
FETCH_ENVIRONMENT = ["GIT_ALLOW_PROTOCOL=https", "GIT_TERMINAL_PROMPT=0", "LC_ALL=C", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"]


@pytest.fixture(scope="module")
def canary():
    return github_token()


@pytest.fixture(scope="module")
def world(tmp_path_factory, pair, canary, runtime):
    leaking = {"answer": "repository", "files": {"config/settings.py": f'API_TOKEN = "{canary}"\n'}, "random": {}, "gitlinks": {}}
    world = FetchWorld(tmp_path_factory.mktemp("world"), pair, {"canary": leaking}, runtime)
    assert world.control == [200]
    return world


@pytest.fixture
def bench(tmp_path, runtime):
    with Bench(tmp_path / "bench", PROBE_IMAGE, STACK_PROXY, runtime) as bench:
        yield bench


@pytest.fixture(scope="module")
def core_wrapper():
    if CORE_DIR not in os.environ:
        pytest.skip(f"{CORE_DIR} names no core checkout, so core's container wrapper is not at hand")
    wrapper = Path(os.environ[CORE_DIR]) / CORE_WRAPPER
    assert wrapper.is_file(), wrapper
    return wrapper


def trust_environment(directory):
    """
    Returns:
        The calling environment core's wrapper turns into CA injection, plus a credential no step may inherit.
    """
    directory.mkdir()
    certificate, wrapper = directory / "ca.crt", directory / "ca-wrapper"
    for path in (certificate, wrapper):
        path.write_text("egress test\n", encoding="utf-8")
        path.chmod(0o644)
    environment = {"CA_CONTAINER_ENABLED": "1", "CA_TRUST_CERT_HOST": certificate, "CA_TRUST_WRAPPER_HOST": wrapper}
    environment.update(CA_TRUST_NAME="egress-test", CA_TRUST_CERT_CONTAINER="/etc/egress-ca.crt")
    environment.update(CA_TRUST_WRAPPER_CONTAINER="/usr/local/bin/egress-ca", QUALITY_EGRESS_CREDENTIAL=secrets.token_hex(16))
    mounts = [item for path in (certificate, wrapper) for item in ("-v", f"{path}:{path}:ro")]
    return environment, mounts


def expected_sandbox(step, proxy):
    """
    Returns:
        (network, {mount destination: writable}, extra environment) decision 8 gives the named step.
    """
    proxied = [f"https_proxy={proxy}"]
    return {
        "fetch": (FETCH_NETWORK, {"/src": True}, proxied + FETCH_ENVIRONMENT),
        "prepare": ("none", {"/src": True}, []),
        "scan": ("none", {"/src": False, "/db": False}, []),
        "database": (FETCH_NETWORK, {"/db": True}, proxied),
    }[step]


def assert_sandbox(info, step, bench, image_env):
    limits = bench.config["limits"]["step"]
    network, mounts, extra = expected_sandbox(step, bench.config["fetch"]["proxy"])
    host, config = info["HostConfig"], info["Config"]
    assert host["ReadonlyRootfs"] is True and host["AutoRemove"] is True
    assert config["User"] == "65534:65534" and host["CapDrop"] == ["ALL"]
    assert host["SecurityOpt"] == ["no-new-privileges"]
    assert host["PidsLimit"] == limits["pids"]
    assert host["Memory"] == host["MemorySwap"] == 1 << 30
    assert host["NanoCpus"] == int(float(limits["cpus"]) * 1e9)
    assert host["Tmpfs"] == {STEP_HOME: f"size={limits['tmp_bytes']}"}
    assert host["Runtime"] == bench.config["runtime"] and host["NetworkMode"] == network
    assert host["LogConfig"]["Type"] == "none" and not config["Entrypoint"]
    assert {mount["Destination"]: mount["RW"] for mount in info["Mounts"]} == mounts
    assert sorted(config["Env"]) == sorted(image_env + STEP_ENVIRONMENT + extra)


def test_stage_flags(tmp_path, world, core_wrapper, runtime):
    environment, mounts = trust_environment(tmp_path / "trust")
    with Bench(tmp_path / "bench", PROBE_IMAGE, world.proxy, runtime) as bench:
        bench.wrap(core_wrapper, environment)
        bench.flags += mounts
        bench.database({"hold": 4}, age_hours=DUE_HOURS)
        fetched = bench.submit(url_job("hold.git"))
        prepared = bench.submit(probe_job({"hold": 4}))
        with Watcher() as watcher:
            code, _journal = bench.run()
        steps = watcher.steps()
    expected = [f"quality-check-{fetched}-fetch", f"quality-check-{fetched}-scan", f"quality-check-{prepared}-prepare"]
    assert code == 0
    assert sorted(steps) == sorted([*expected, f"quality-check-{prepared}-scan", "quality-check-database"])
    image_env = image_environment(PROBE_IMAGE)
    for name, info in steps.items():
        assert_sandbox(info, name.rsplit("-", 1)[-1], bench, image_env)
        assert environment["QUALITY_EGRESS_CREDENTIAL"] not in json.dumps(info)


def test_isolation_probe(bench):
    bench.config["limits"]["step"].update(pids=PIDS, tmp_bytes=TMP_BYTES)
    bench.database({}, age_hours=0)
    token = secrets.token_hex(16)
    checks = {"targets": [f"{STACK_PROXY}:3128", "9.9.9.9:443"], "fork_cap": 4 * PIDS, "tmp_cap": 4 * TMP_BYTES}
    prober = bench.submit(probe_job({"isolation": checks, "seek": token}))
    neighbour = bench.submit(probe_job({"hold": 30}, payload=token.upper()))
    bench.run()
    notes = bench.notes(prober)
    isolation = notes["isolation"]
    assert isolation["interfaces"] == ["lo"]
    assert set(isolation["connect"].values()) <= UNREACHABLE and isolation["resolve"] == "failed"
    assert isolation["write"] == dict.fromkeys(WRITES, "EROFS")
    mounts = dict(notes["mounts"])
    assert "ro" in mounts["/src"].split(",") and "ro" in mounts["/db"].split(",")
    assert [point for point, _options in notes["mounts"] if point.startswith("/src")] == ["/src"]
    assert isolation["forks"]["stopped_by"] == "EAGAIN" and 0 < isolation["forks"]["forked"] < PIDS
    assert isolation["tmp"]["stopped_by"] == "ENOSPC" and isolation["tmp"]["written"] <= TMP_BYTES
    assert notes["found"] == []
    assert bench.report(neighbour)["status"] == "done"


def test_probe_cannot_stay(bench):
    bench.config["limits"]["concurrency"] = 1
    bench.config["limits"]["timeouts"]["scan"] = STAY_SECONDS
    token = secrets.token_hex(16)
    stayer = bench.submit(probe_job({"leave": token, "stay": True}))
    follower = bench.submit(probe_job({"seek": token}))
    started = time.time()
    bench.run()
    report = bench.report(stayer)
    assert (report["status"], report["reason"]) == ("failed", "timeout")
    assert report["finished"] - started < STAY_SECONDS + STOP_GRACE_SECONDS + SLACK_SECONDS
    assert bench.notes(follower)["found"] == []
    assert job_containers() == []
    assert bench.job_mounts() == []


def test_job_separation(bench):
    bench.config["limits"]["concurrency"] = 1
    token = secrets.token_hex(16)
    first = bench.submit(probe_job({"leave": token, "seek": token}))
    second = bench.submit(probe_job({"seek": token}))
    bench.run()
    leaving = bench.notes(first)
    assert leaving["found"] == [leaving["left"]]
    assert bench.notes(second)["found"] == []


def interrupted_mid_job(bench, signal: str) -> tuple:
    """
    Args:
        bench: Bench whose launcher runs one held probe job.
        signal: Signal docker kill sends the launcher once the job's scan step runs.

    Returns:
        The job id and the launcher's exit code.
    """
    job = bench.submit(probe_job({"hold": 600}))
    launcher = bench.start()
    wait_until(lambda: f"quality-check-{job}-scan" in running_steps(), 180, "the scan step's start")
    docker("kill", f"--signal={signal}", launcher)
    code, _journal = bench.finish(launcher)
    return job, code


def assert_next_run_recovers(bench, job: str) -> None:
    bench.run()
    assert job_containers() == []
    assert bench.job_mounts() == []
    report = bench.report(job)
    assert (report["status"], report["reason"]) == ("failed", "interrupted")


def test_stop_mid_job(bench):
    job, code = interrupted_mid_job(bench, "TERM")
    assert code == 143
    assert_next_run_recovers(bench, job)


def test_launcher_recovers(bench):
    job, code = interrupted_mid_job(bench, "KILL")
    assert code == 137
    assert f"quality-check-{job}-scan" in running_steps()
    assert_next_run_recovers(bench, job)


def test_spool_full(tmp_path, runtime):
    bench = Bench(tmp_path / "bench", PROBE_IMAGE, STACK_PROXY, runtime)
    bench.state_bytes = MIB
    with bench, Web(bench) as web:
        status, held = web.submit(kind="text", language="python", text=json.dumps({"probe": {"hold": 20}}))
        assert status == 303
        bench.tool("fill")
        assert web.submit(kind="text", language="python", text="print(1)\n")[0] == 429
        launcher = bench.start()
        wait_until(lambda: "The scan is running." in web.page(held)["body"], 180, "the running mark of the spooled job")
        bench.finish(launcher)
        changes = [root_writes(container) for container in (web.container, launcher)]
        mounts = bench.job_mounts()
    assert changes == [[], []]
    assert mounts == []


def test_canary_end_to_end(tmp_path, world, canary, runtime):
    with Bench(tmp_path / "bench", TRUSTING_IMAGE, world.proxy, runtime) as bench, Web(bench) as web:
        status, job = web.submit(kind="url", url=f"https://{GIT_HOST}/canary.git")
        _code, journal = bench.run()
        report, page = bench.report(job), web.page(job)["body"]
        stored, web_log = bench.find(canary), logs(web.container)
        mounts = bench.job_mounts()
    assert status == 303 and report["status"] == "done", report
    assert ("security.secret", "config/settings.py") in {(finding["rule"], finding["path"]) for finding in report["result"]["findings"]}
    assert canary not in json.dumps(report) and canary not in page
    assert stored == [] and mounts == []
    assert canary not in journal and canary not in web_log


@pytest.mark.usefixtures("internet")
def test_db_update_isolated(bench):
    bench.database({"egress": ["example.org:443", "9.9.9.9:443"]}, age_hours=None)
    code, _journal = bench.run()
    result = bench.database_result()
    assert code == 0
    assert result["egress"]["example.org:443"]["proxy"] == 200
    assert all(outcome["direct"] != "connected" for outcome in result["egress"].values())
    assert result["uid"] == 65534
    mounts = {point: options for point, options in result["mounts"]}
    assert "/src" not in mounts and "rw" in mounts["/db"].split(",")
    assert result["environment"]["https_proxy"] == bench.config["fetch"]["proxy"]
    assert not os.listdir(bench.jobs)
