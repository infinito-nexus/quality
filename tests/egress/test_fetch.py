import hashlib
import io
import json
import time
import zipfile

import pytest

from tests.egress.isolation_support import (
    FIXTURES,
    MIB,
    PROBE_IMAGE,
    TRUSTING_IMAGE,
    Bench,
    FetchWorld,
    Watcher,
    file_job,
    github_token,
    job_containers,
    text_job,
    url_job,
)
from tests.egress.support import STACK_PROXY

pytestmark = pytest.mark.usefixtures("vulnerability_database", "quiet_stack", "pair")
PLAIN = json.loads((FIXTURES / "repositories.json").read_text(encoding="utf-8"))["plain"]["files"]
LARGE_BYTES = 8 * MIB
TIER_BYTES = 2 * MIB
FETCH_SECONDS = 15
STOP_GRACE_SECONDS = 15
SLACK_SECONDS = 60


def comparable(report):
    return {key: value for key, value in report.items() if key != "finished"}


@pytest.fixture(scope="module")
def world(tmp_path_factory, pair, runtime):
    large = {"answer": "repository", "files": {}, "random": {"blob.bin": LARGE_BYTES}, "gitlinks": {}}
    world = FetchWorld(tmp_path_factory.mktemp("world"), pair, {"large": large}, runtime)
    assert world.control == [200]
    return world


@pytest.fixture
def bench(tmp_path, world, runtime):
    with Bench(tmp_path / "bench", PROBE_IMAGE, world.proxy, runtime) as bench:
        yield bench


def test_redirect_not_followed(bench, world):
    hits = world.hits()
    job = bench.submit(url_job("redirect"))
    bench.run()
    assert comparable(bench.report(job)) == {"status": "failed", "reason": "not reachable"}
    assert {"GET /redirect/info/refs 302", "GET /redirect.git/info/refs 302"} <= set(world.requests())
    assert world.hits() == hits


def test_submodule_not_fetched(bench, world):
    hits = world.hits()
    job = bench.submit(url_job("submodule.git"))
    bench.run()
    notes = bench.notes(job)
    assert notes["ls_files"] == [".gitmodules", "README.md", "sub"]
    assert notes["worktree"] == []
    assert world.hits() == hits


def test_index_populated(bench):
    job = bench.submit(url_job("plain.git"))
    bench.run()
    notes = bench.notes(job)
    assert notes["ls_files"] == notes["ls_tree"]
    assert sorted(notes["ls_files"]) == sorted(PLAIN)


def test_fetch_visible_in_scan(tmp_path, bench, world, runtime):
    probed = bench.submit(url_job("plain.git"))
    bench.run()
    notes, report = bench.notes(probed), bench.report(probed)
    assert notes["head"] == report["commit"]
    assert notes["blobs"] == {path: hashlib.sha256(text.encode()).hexdigest() for path, text in PLAIN.items()}
    with Bench(tmp_path / "scan", TRUSTING_IMAGE, world.proxy, runtime) as scanner:
        scanned = scanner.submit(url_job("plain.git"))
        scanner.run()
        report = scanner.report(scanned)
    assert report["status"] == "done", report
    assert ("coding.unused-import", "src/app.py") in {(finding["rule"], finding["path"]) for finding in report["result"]["findings"]}


def test_repo_too_large(bench):
    bench.config["limits"]["repo_bytes"]["anonymous"] = TIER_BYTES
    job = bench.submit(url_job("large.git"))
    bench.run()
    assert comparable(bench.report(job)) == {"status": "failed", "reason": "too large"}
    assert bench.job_mounts() == []


def test_fetch_timeout(bench, world):
    bench.config["limits"]["timeouts"]["fetch"] = FETCH_SECONDS
    job = bench.submit(url_job("stall.git"))
    started = time.time()
    bench.run()
    report = bench.report(job)
    assert comparable(report) == {"status": "failed", "reason": "timeout"}
    assert report["finished"] - started < FETCH_SECONDS + STOP_GRACE_SECONDS + SLACK_SECONDS
    assert "GET /stall.git/info/refs stalled" in world.requests()
    assert job_containers() == []
    assert bench.job_mounts() == []


def test_private_same_as_missing(bench, world):
    private = bench.submit(url_job("private"))
    missing = bench.submit(url_job("missing"))
    bench.run()
    assert [comparable(bench.report(job)) for job in (private, missing)] == [{"status": "failed", "reason": "not reachable"}] * 2
    assert {"GET /private.git/info/refs 401", "GET /missing.git/info/refs 404"} <= set(world.requests())


def test_prepare_step(bench):
    named = bench.submit(file_job("../../x.py", "print(1)\n"))
    typed = bench.submit(text_job("python", "print(1)\n"))
    with Watcher() as watcher:
        bench.run()
    prepares = [info for name, info in watcher.steps().items() if name.endswith("-prepare")]
    assert [info["HostConfig"]["NetworkMode"] for info in prepares] == ["none", "none"]
    assert bench.notes(named)["ls_files"] == ["x.py"]
    assert bench.notes(typed)["ls_files"] == ["snippet.py"]


def test_upload_opaque(tmp_path, runtime):
    canary = github_token()
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_STORED) as bundle:
        bundle.writestr("inner.py", f'TOKEN = "{canary}"\n')
    upload = file_job("bundle.zip", archive.getvalue())
    with Bench(tmp_path / "probe", PROBE_IMAGE, STACK_PROXY, runtime) as bench:
        probed = bench.submit(upload)
        bench.run()
        notes = bench.notes(probed)
    with Bench(tmp_path / "scan", TRUSTING_IMAGE, STACK_PROXY, runtime) as bench:
        scanned = bench.submit(upload)
        bench.run()
        report, leaked = bench.report(scanned), bench.find(canary)
    assert notes["ls_files"] == ["bundle.zip"] and notes["worktree"] == ["bundle.zip"]
    assert report["status"] == "done", report
    assert {finding["path"] for finding in report["result"]["findings"]} <= {"bundle.zip"}
    assert "inner.py" not in json.dumps(report) and canary not in json.dumps(report)
    assert leaked == []
