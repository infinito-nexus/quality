import base64
import json
import os
import sys
import time
from pathlib import Path

import pytest

from tests.service.support import ROOT, load_launcher

launcher = load_launcher()
FAKE = Path(__file__).with_name("fake_container.py")
DEV_CONFIG = ROOT / "service" / "dev" / "config.json"
FINDING = {"rule": "r", "path": "p", "line": 1, "severity": "high", "summary": "s", "value": None, "commit": None}
REPORT = {"findings": [FINDING], "ignored": [], "nocheck": [], "unchecked": [], "notes": [], "incomplete": []}
SANDBOX_FLAGS = {
    "--read-only",
    "--user=65534:65534",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges",
    "--pids-limit=512",
    "--memory=2g",
    "--cpus=2",
    "--tmpfs=/tmp:size=268435456",
    "--runtime=runc",
}


def ident(number):
    return f"{number:032x}"


def text_job(content="import os\n", **extra):
    """
    Args:
        content: Python source of the job; an unused import by default, the smallest text that yields a finding.
        extra: Further job fields.
    """
    return {"kind": "text", "language": "python", "content": base64.b64encode(content.encode()).decode(), **extra}


class Harness:
    def __init__(self, tmp_path):
        self.root = tmp_path
        self.state = tmp_path / "state"
        for name in ("spool", "reports", "claimed"):
            (self.state / name).mkdir(parents=True)
        self.calls = tmp_path / "calls.jsonl"
        self.behaviour = {"runtimes": {"runc": {}}, "containers": [], "steps": {}}
        self.step(fetch=(0, "0123abc\n"), prepare=(0, ""), scan=(0, json.dumps(REPORT)), database=(0, ""))
        self.config = json.loads(DEV_CONFIG.read_text(encoding="utf-8"))
        behaviour = str(tmp_path / "behaviour.json")
        self.config.update(state_dir=str(self.state), jobs_dir=str(tmp_path / "jobs"))
        self.config.update(container=[sys.executable, str(FAKE), behaviour, str(self.calls)])
        self.config["database"]["dir"] = str(tmp_path / "db")

    def step(self, **steps):
        for name, (code, stdout) in steps.items():
            self.behaviour["steps"][name] = {"exit": code, "stdout": stdout}

    def submit(self, number, job, tier=2, age=0):
        """
        Args:
            number: Job number, turned into its 32-digit id.
            job: Job object, or raw text for a malformed job file.
            tier: Index into the launcher's TIERS; 2 (anonymous) by default, the tier that needs no account.
            age: Seconds the job file is backdated; 0 by default, a job that just arrived.
        """
        path = self.state / "spool" / f"{tier}-{ident(number)}.json"
        path.write_text(job if isinstance(job, str) else json.dumps(job), encoding="utf-8")
        os.utime(path, (time.time() - age, time.time() - age))
        return path

    def run(self):
        (self.root / "behaviour.json").write_text(json.dumps(self.behaviour), encoding="utf-8")
        (self.root / "config.json").write_text(json.dumps(self.config), encoding="utf-8")
        return launcher.main(["launcher", str(self.root / "config.json")])

    def report(self, number):
        path = self.state / "reports" / f"{ident(number)}.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None

    def calls_made(self):
        if not self.calls.exists():
            return []
        return [json.loads(line) for line in self.calls.read_text(encoding="utf-8").splitlines()]

    def runs(self):
        return [call for call in self.calls_made() if call["argv"][0] == "run"]


def step_of(call):
    return next(arg for arg in call["argv"] if arg.startswith("--name=")).rsplit("-", 1)[-1]


@pytest.fixture
def harness(tmp_path):
    return Harness(tmp_path)


def test_no_runtime_no_job(harness):
    harness.config["runtime"] = "runsc"
    harness.submit(1, text_job())
    with pytest.raises(SystemExit) as stopped:
        harness.run()
    assert stopped.value.code == 2
    assert harness.runs() == []
    assert harness.report(1) is None


def test_member_first(harness):
    harness.config["limits"].update(concurrency=1, jobs_per_run=1)
    harness.submit(1, text_job(), tier=2, age=600)
    harness.submit(2, text_job(), tier=1, age=300)
    harness.submit(3, text_job(), tier=0)
    harness.run()
    assert harness.report(3)["status"] == "done"
    assert harness.report(1) is None and harness.report(2) is None


def test_launcher_revalidates(harness):
    harness.submit(1, {"kind": "url", "url": "http://example.org/a/b"})
    harness.run()
    assert harness.report(1)["reason"] == "invalid url"
    assert harness.runs() == []


def test_fetch_argv(harness):
    harness.submit(1, {"kind": "url", "url": "https://example.org/a/b"})
    harness.run()
    fetch = harness.runs()[0]["argv"]
    assert step_of(harness.runs()[0]) == "fetch"
    assert {"--env=https_proxy=http://10.213.0.2:3128", "--network=quality-check-fetch"} <= set(fetch)
    assert set(launcher.FETCH_ENVIRONMENT) <= set(fetch)
    assert not any(proxy in arg.lower() for arg in fetch for proxy in ("no_proxy", "all_proxy", "http_proxy="))
    script = fetch[fetch.index("-c") + 1]
    for setting in ("http.followRedirects=false", "transfer.fsckObjects=true", "http.userAgent=$2"):
        assert setting in script
    assert '--depth 1 --no-checkout --single-branch -- "$1"' in script
    assert fetch[-2:] == ["https://example.org/a/b", harness.config["fetch"]["user_agent"]]
    report = harness.report(1)
    assert (report["status"], report["commit"], report["history"]) == ("done", "0123abc", "HEAD only: history not scanned")


def test_fetch_tries_dot_git(harness):
    harness.step(fetch=(128, ""))
    harness.submit(1, {"kind": "url", "url": "https://example.org/a/b"})
    harness.run()
    tried = [call["argv"][-2] for call in harness.runs()]
    assert tried == ["https://example.org/a/b", "https://example.org/a/b.git"]
    assert harness.report(1)["reason"] == "not reachable"


def test_step_flags(harness):
    harness.submit(1, text_job())
    harness.run()
    prepare, scan = harness.runs()
    for call in (prepare, scan):
        argv = call["argv"]
        assert SANDBOX_FLAGS <= set(argv)
        assert "--network=none" in argv
        assert {arg for arg in argv if arg.startswith("--env")} == {"--env=HOME=/tmp", "--env=XDG_CACHE_HOME=/tmp"}
        assert argv[argv.index("--workdir=/src") + 1] == "quality-check/scan:local"
    assert any(arg.endswith("target=/src,readonly") for arg in scan["argv"])
    assert not any(arg.endswith(",readonly") for arg in prepare["argv"])


def test_text_language(harness):
    harness.submit(1, text_job("import os\n"))
    harness.run()
    prepare = harness.runs()[0]
    assert prepare["argv"][-1] == "snippet.py"
    assert prepare["stdin"] == "import os\n"


def test_image_not_from_job(harness):
    harness.submit(1, text_job(image="evil/image", container=["evil"]))
    harness.run()
    assert harness.report(1)["status"] == "done"
    assert not any("evil" in arg for call in harness.calls_made() for arg in call["argv"])


def test_spool_hostile_file(harness, tmp_path):
    target = tmp_path / "target"
    target.write_text("canary-target", encoding="utf-8")
    spool = harness.state / "spool"
    (spool / f"2-{ident(1)}.json").symlink_to(target)
    os.mkfifo(spool / f"2-{ident(2)}.json")
    (spool / f"2-{ident(3)}.json").mkdir()
    harness.submit(4, "x" * (harness.config["limits"]["job_bytes"] + 1))
    harness.submit(5, text_job())
    harness.run()
    assert [harness.report(number)["status"] for number in range(1, 6)] == ["failed"] * 4 + ["done"]
    assert target.read_text(encoding="utf-8") == "canary-target"
    assert not any("canary" in (call["stdin"] or "") for call in harness.calls_made())
    assert list(spool.iterdir()) == [] and list((harness.state / "claimed").iterdir()) == []


@pytest.mark.parametrize("name", [f"2-{'A' * 32}.json", f"-2-{'a' * 32}.json", f"2-..{'a' * 30}.json", f"3-{'a' * 32}.json"])
def test_job_id_hostile(harness, name):
    (harness.state / "spool" / name).write_text(json.dumps(text_job()), encoding="utf-8")
    harness.run()
    assert harness.runs() == []
    assert list((harness.state / "reports").iterdir()) == []
    assert list((harness.state / "spool").iterdir()) == []


def test_report_no_overwrite(harness):
    existing = harness.state / "reports" / f"{ident(1)}.json"
    existing.write_text('{"status": "done", "sentinel": true}', encoding="utf-8")
    harness.submit(1, text_job())
    harness.run()
    assert harness.report(1) == {"status": "done", "sentinel": True}
    assert harness.runs() == []


def test_poison_job_isolated(harness):
    harness.config["limits"]["concurrency"] = 1
    harness.submit(1, "[" * 100000 + "]" * 100000, age=60)
    harness.submit(2, text_job())
    harness.run()
    assert harness.report(1)["reason"] == "invalid job"
    assert harness.report(2)["status"] == "done"


@pytest.mark.parametrize(
    ("code", "status", "reason"),
    [(0, "done", None), (1, "done", None), (2, "failed", "not checked"), (124, "failed", "timeout"), (137, "failed", "not checked")],
)
def test_exit_mapping(harness, code, status, reason):
    harness.step(scan=(code, json.dumps(REPORT)))
    harness.submit(1, text_job())
    harness.run()
    report = harness.report(1)
    assert (report["status"], report["reason"]) == (status, reason)
    assert ("result" in report) == (status == "done")


@pytest.mark.parametrize("stdout", ["not json", json.dumps({**REPORT, "extra": 1}), json.dumps(REPORT) + " " * 2000])
def test_report_schema(harness, stdout):
    harness.config["limits"]["report_bytes"] = 1000
    harness.step(scan=(0, stdout))
    harness.submit(1, text_job())
    harness.run()
    assert harness.report(1)["reason"] == "invalid report"


def test_oversized_report_removes_step(harness):
    harness.config["limits"]["report_bytes"] = 100
    harness.submit(1, text_job())
    harness.run()
    assert ["rm", "-f", f"quality-check-{ident(1)}-scan"] in [call["argv"] for call in harness.calls_made()]


def test_claimed_jobs_show_as_running(harness):
    for number in (1, 2, 3):
        harness.submit(number, text_job())
    assert len(launcher.Launcher(harness.config).claim()) == 3
    assert list((harness.state / "spool").iterdir()) == []
    assert sorted(path.name for path in (harness.state / "reports").iterdir()) == [f"{ident(n)}.running" for n in (1, 2, 3)]


def test_launcher_recovers(harness):
    harness.behaviour["containers"] = ["left-behind"]
    (harness.state / "claimed" / f"2-{ident(1)}.json").write_text(json.dumps(text_job()), encoding="utf-8")
    (harness.state / "reports" / f"{ident(2)}.running").write_text("", encoding="utf-8")
    harness.run()
    assert harness.report(1)["reason"] == "interrupted" and harness.report(2)["reason"] == "interrupted"
    assert ["rm", "-f", "left-behind"] in [call["argv"] for call in harness.calls_made()]
    assert not (harness.state / "reports" / f"{ident(2)}.running").exists()


def test_retention(harness):
    harness.config["limits"]["retention_hours"] = 1
    old, young = (harness.state / "reports" / f"{ident(number)}.json" for number in (1, 2))
    for path, age in ((old, 7200), (young, 600)):
        path.write_text("{}", encoding="utf-8")
        os.utime(path, (time.time() - age, time.time() - age))
    harness.run()
    assert not old.exists() and young.exists()


def database(harness, age_hours):
    harness.config["database"].update(update_hours=24, max_age_hours=168)
    stamp = harness.root / "db" / ".updated"
    stamp.parent.mkdir()
    stamp.write_text("", encoding="utf-8")
    os.utime(stamp, (time.time() - age_hours * 3600, time.time() - age_hours * 3600))


def test_db_too_old_job_fails(harness):
    database(harness, 200)
    harness.step(database=(1, ""))
    harness.submit(1, text_job())
    assert harness.run() == 1
    assert harness.report(1)["reason"] == "database too old"


def test_db_update_failure_alerts(harness):
    database(harness, 30)
    harness.step(database=(1, ""))
    harness.submit(1, text_job())
    assert harness.run() == 1
    assert harness.report(1)["status"] == "done"
    assert [step_of(call) for call in harness.runs()] == ["prepare", "scan", "database"]
    scan = harness.runs()[1]["argv"]
    assert f"--mount=type=bind,source={harness.root / 'db'},target=/db,readonly" in scan
    assert scan[-6:] == [*launcher.SCAN_COMMAND, "/src/repo", "/db/bundle"]
    update = harness.runs()[2]["argv"]
    assert f"--mount=type=bind,source={harness.root / 'db'},target=/db" in update
    assert update[-4:] == ["db", "update", "--db", "/db/bundle"]


def test_steps_keep_no_container_log(harness):
    database(harness, 30)
    harness.submit(1, {"kind": "url", "url": "https://example.org/a/b"})
    harness.submit(2, text_job())
    harness.run()
    runs = harness.runs()
    assert {step_of(call) for call in runs} == {"fetch", "prepare", "scan", "database"}
    assert all("--log-driver=none" in call["argv"] for call in runs)


def test_submission_deleted(harness):
    harness.submit(1, text_job("canary-submission = 1\n"))
    harness.run()
    files = [path for path in harness.state.rglob("*") if path.is_file()]
    assert files and not any("canary-submission" in path.read_text(encoding="utf-8") for path in files)
    assert not any(b"Y2FuYXJ5" in path.read_bytes() for path in files)
