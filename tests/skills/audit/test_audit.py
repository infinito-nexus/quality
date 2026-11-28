import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import urllib.parse
from pathlib import Path

import pytest

from tests.skills.gitcase import GitCase

REPO_ROOT = Path(__file__).resolve().parents[3]
SKILL = REPO_ROOT / "skills" / "kvb-quality-audit"
AUDIT = SKILL / "scripts" / "audit.py"
SEEDED = "token = request.args['t']  # MARK-HIGH"
SHA1 = hashlib.sha1(SEEDED.encode()).hexdigest()
HIGH = {"rule": "FAKE-HIGH", "path": "app.py", "line": 2, "sha1": SHA1, "severity": "high"}


def seed_print(item: dict) -> str:
    place = hashlib.sha256(f"{item['path']}\0{item['line']}\0{item['sha1']}".encode()).hexdigest()
    return f"medusa:{item['rule']}:{place}"
needs_node = pytest.mark.skipif(shutil.which("node") is None, reason="node runs the upstream validators")


class Target(GitCase):
    def __init__(self, base: Path):
        """
        Args:
            base: Directory for the fixture repository, the council and the output.
        """
        self.repo = base / "repo"
        self.repo.mkdir()
        self.out = base / "out"
        self.env = {
            "PATH": os.environ["PATH"],
            "HOME": str(base),
            "PYTHONPATH": str(REPO_ROOT / "src"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "AGENTS_COUNCIL_ROOT": str(base / "council"),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": "Test",
            "GIT_AUTHOR_EMAIL": "test@example.org",
            "GIT_COMMITTER_NAME": "Test",
            "GIT_COMMITTER_EMAIL": "test@example.org",
        }
        self.git("init", "-q", "-b", "main")
        self.commit({"app.py": "print(1)\n", "README.md": "# app\n"})
        self.git("tag", "v1.0.0")

    def medusa(self, findings: list) -> Path:
        report = self.repo.parent / "medusa.json"
        report.write_text(json.dumps({"security": 100, "findings": findings}), encoding="utf-8")
        return report

    def run(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, str(AUDIT), *args], env=self.env, capture_output=True, text=True, check=False)

    def shared(self, command: str, findings: list | None) -> list:
        report = self.medusa([] if findings is None else findings)
        return [command, "--repo", str(self.repo), "--out", str(self.out), "--budget", "4", "--medusa", str(report)]

    def prepare(self, *extra: str, findings: list | None = None) -> subprocess.CompletedProcess:
        return self.run(*self.shared("prepare", findings), *extra)

    def attest(self, invocations: str, findings: list | None = None) -> subprocess.CompletedProcess:
        counters = ("--invocations", invocations, "--tokens", "1200", "--minutes", "3")
        return self.run(*self.shared("attest", findings), *counters)


def place(kind: str, line: int) -> dict:
    return {"file": "app.py", "line": line, "description": "Read in the audit."} | ({"kind": kind, "scope": "main"} if kind else {})


def record(verdict: str, fingerprint: str, severity: str | None = None) -> dict:
    common = {"verdict": verdict, "fingerprint": fingerprint, "title": "Candidate", "description": "Checked.", "trace": [place("entrypoint", 2)], "evidence": [place("", 2)]}
    if verdict == "rejected":
        return common | {"claimed_root_cause": "Input reaches the token.", "reason": "Only a test constant\nreaches it."}
    if verdict == "needs_validation":
        return common | {"claimed_root_cause": "Input reaches the token.", "blockers": ["No sandbox."], "validation_plan": {"local": "Run it."}}
    score = {"score": severity, "reason": "Fixture."}
    return common | {
        "root_cause": "The token is echoed.",
        "intended_behavior": "A generic message.",
        "conditions": [{"kind": "data_state", "description": "A token."}],
        "execution": {"attacker_perspective": "A client.", "payloads": ["t"], "instructions": ["Send it."], "observed_result": "Echoed."},
        "remediation": {"strategy": "Drop the echo."},
        "severity": {"likelihood": score, "impact": score, "overall_severity": severity},
        "confidence": {"score": "high", "reason": "Reproduced."},
    }


def ledger(paths: list, fingerprints: list | None = None) -> list:
    refs = {"surface": "app.py#main", "boundary": "app.py#main", "subsystem": "app", "attack_class": "ATTACK-CLASSES.md#Injection"}
    check = {"agent_id": "hunter-1", "reviewed_paths": paths, "invariant": "No input reaches the call.", "method": "source", "result": "Held.", "artifact": None}
    unit = {
        "coverage_id": "::".join(urllib.parse.quote(refs[key], safe="-._~") for key in ("surface", "boundary", "subsystem", "attack_class")),
        "canonical_refs": refs,
        "surface": "Main entry",
        "boundary": "Input handling",
        "subsystem": "App",
        "attack_class": "Injection",
        "starting_paths": paths,
        "ordinary_attack_class_block": "ATTACK-CLASSES.md#Injection",
        "selected_companion_blocks": [],
        "excluded_blocks": [],
        "prior_status": "new",
        "attempts": [],
        "wave": 1,
        "status": "candidate" if fingerprints else "covered",
        "agent_id": "hunter-1",
        "reviewed_paths": paths,
        "local_checks": [check],
        "result_fingerprints": fingerprints or [],
        "unresolved": [],
    }
    return [unit]


def archived(status: str, fingerprints: list | None = None) -> dict:
    unit = ledger(["app.py"])[0]
    refs = unit["canonical_refs"] | {"surface": "app.py#other"}
    check = unit["local_checks"][0] | {"agent_id": "hunter-2"}
    attempt = {
        "wave": 1,
        "status": status,
        "agent_id": "hunter-2",
        "reviewed_paths": ["app.py"],
        "local_checks": [check],
        "result_fingerprints": fingerprints or [],
        "unresolved": ["Needs a sandbox."] if status == "blocked" else [],
        "reassignment_reason": "The critic reassigned it.",
    }
    return unit | {
        "coverage_id": "::".join(urllib.parse.quote(refs[key], safe="-._~") for key in ("surface", "boundary", "subsystem", "attack_class")),
        "canonical_refs": refs,
        "surface": "Other entry",
        "attempts": [attempt],
        "wave": 2,
        "status": "deferred",
        "agent_id": None,
        "reviewed_paths": [],
        "local_checks": [],
        "result_fingerprints": [],
        "unresolved": ["quick_profile_final_critic: reassigned."],
    }


def prepared(target: Target, records: list, units: list, findings: list | None = None) -> Path:
    plan = json.loads(target.prepare(findings=findings).stdout)
    run = target.out / f"run-{plan['tree']}"
    run.mkdir()
    (run / "findings.json").write_text(json.dumps(sorted(records, key=lambda item: item["fingerprint"])), encoding="utf-8")
    (run / "coverage-ledger.json").write_text(json.dumps(sorted(units, key=lambda unit: unit["coverage_id"])), encoding="utf-8")
    return run


def audited(target: Target, records: list, units: list, findings: list | None = None) -> subprocess.CompletedProcess:
    prepared(target, records, units, findings)
    return target.attest("3", findings=findings)


def rejected_high() -> dict:
    return record("rejected", seed_print(HIGH))


@pytest.fixture
def target(tmp_path):
    return Target(tmp_path)


def test_the_vendored_upstream_matches_its_lock_file_byte_for_byte(target, tmp_path):
    lock = json.loads((SKILL / "lock.json").read_text(encoding="utf-8"))
    assert sorted(path.name for path in (SKILL / "upstream").iterdir()) == sorted(item["name"] for item in lock["files"])
    copy = tmp_path / "skills" / "kvb-quality-audit"
    shutil.copytree(SKILL, copy, ignore=shutil.ignore_patterns("__pycache__"))
    (copy / "upstream" / "HUNTING.md").write_bytes((copy / "upstream" / "HUNTING.md").read_bytes() + b" ")
    result = subprocess.run([sys.executable, str(copy / "scripts" / "audit.py"), "prepare", "--repo", str(target.repo), "--out", str(target.out), "--budget", "1", "--medusa", str(target.medusa([]))], env=target.env, capture_output=True, text=True, check=False)
    assert result.returncode == 2
    assert "HUNTING.md differs from lock.json" in result.stderr


def test_the_range_starts_at_the_newest_release_tag(target):
    target.commit({"app.py": f"print(1)\n{SEEDED}\n"})
    plan = json.loads(target.prepare().stdout)
    assert plan["range"] == "v1.0.0..HEAD"
    assert plan["files"] == ["app.py"]
    assert plan["profile"] == "quick"


def test_without_a_release_tag_the_range_must_be_named(target):
    target.git("tag", "-d", "v1.0.0")
    result = target.prepare()
    assert result.returncode == 2
    assert "--range" in result.stderr


def test_a_docs_only_range_is_skipped_without_a_plan(target):
    target.commit({"README.md": "# app\n\nMore.\n"})
    result = target.prepare()
    assert result.returncode == 0
    document = json.loads(result.stdout)
    assert document["verdict"] == "skipped: docs-only"
    assert [path.name for path in target.out.iterdir()] == [f"attestation-{document['tree']}.json"]


@pytest.mark.parametrize("inside", ["tracked", "missing"])
def test_out_must_lie_outside_the_tracked_tree(target, inside):
    if inside == "missing":
        result = target.run("prepare", "--repo", str(target.repo), "--budget", "1", "--medusa", str(target.medusa([])))
    else:
        result = target.run("prepare", "--repo", str(target.repo), "--out", str(target.repo / "audit"), "--budget", "1", "--medusa", str(target.medusa([])))
    assert result.returncode == 2
    assert not (target.repo / "audit").exists()


def test_seeds_are_the_medusa_findings_of_changed_files(target):
    target.commit({"app.py": f"print(1)\n{SEEDED}\n"})
    other = {"rule": "FAKE-LOW", "path": "README.md", "line": 1, "sha1": "b" * 40, "severity": "low"}
    plan = json.loads(target.prepare(findings=[other, HIGH]).stdout)
    assert [seed["fingerprint"] for seed in plan["seeds"]] == [seed_print(HIGH)]


def test_identical_lines_in_two_files_are_two_seeds(target):
    target.commit({"app.py": f"print(1)\n{SEEDED}\n", "lib.py": f"print(2)\n{SEEDED}\n"})
    twin = HIGH | {"path": "lib.py"}
    plan = json.loads(target.prepare(findings=[HIGH, twin]).stdout)
    assert sorted(seed["fingerprint"] for seed in plan["seeds"]) == sorted([seed_print(HIGH), seed_print(twin)])


@needs_node
def test_a_rejected_seed_becomes_one_acceptance_and_a_low_finding_passes(target):
    target.commit({"app.py": f"print(1)\n{SEEDED}\n"})
    result = audited(target, [rejected_high(), record("confirmed", "audit:echo", "low")], ledger(["app.py"]), findings=[HIGH])
    assert result.returncode == 0, result.stderr
    document = json.loads(result.stdout)
    assert (document["verdict"], document["verdicts"], document["severities"]["low"]) == ("pass", {"confirmed": 1, "needs_validation": 0, "rejected": 1}, 1)
    assert document["accepted"] == [{"rule": "FAKE-HIGH", "path": "app.py", "line": 2, "sha1": SHA1}]
    rows = (Path(target.env["AGENTS_COUNCIL_ROOT"]) / "security-accepted.jsonl").read_text(encoding="utf-8").splitlines()
    assert [json.loads(row)["reason"] for row in rows] == ["audit: Only a test constant reaches it."]
    again = target.prepare()
    assert (again.returncode, json.loads(again.stdout)) == (0, document)


@needs_node
@pytest.mark.parametrize(("verdict", "severity"), [("confirmed", "high"), ("confirmed", "critical"), ("needs_validation", None)])
def test_a_grave_or_unvalidated_finding_blocks(target, verdict, severity):
    target.commit({"app.py": f"print(1)\n{SEEDED}\n"})
    result = audited(target, [record(verdict, "audit:token", severity)], ledger(["app.py"]))
    assert result.returncode == 1, result.stderr
    assert json.loads(result.stdout)["verdict"] == "blocked"


@needs_node
def test_a_ledger_that_skips_a_changed_file_is_refused(target):
    target.commit({"app.py": f"print(1)\n{SEEDED}\n", "lib.py": "x = 1\n"})
    result = audited(target, [record("confirmed", "audit:echo", "low")], ledger(["app.py"]))
    assert result.returncode == 2
    assert "lib.py" in result.stderr


@needs_node
def test_more_invocations_than_the_budget_are_refused(target):
    target.commit({"app.py": f"print(1)\n{SEEDED}\n"})
    prepared(target, [record("confirmed", "audit:echo", "low")], ledger(["app.py"]))
    result = target.attest("5")
    assert result.returncode == 2
    assert "exceed the budget of 4" in result.stderr


@needs_node
def test_findings_the_upstream_validator_refuses_stop_the_attestation(target):
    target.commit({"app.py": f"print(1)\n{SEEDED}\n"})
    broken = record("confirmed", "audit:echo", "low")
    del broken["remediation"]
    result = audited(target, [broken], ledger(["app.py"]))
    assert result.returncode == 2
    assert "validate-findings.cjs refused" in result.stderr


@needs_node
def test_attest_derives_the_plan_and_never_trusts_the_plan_file(target):
    target.commit({"app.py": f"print(1)\n{SEEDED}\n", "lib.py": "x = 1\n"})
    plan = json.loads(target.prepare().stdout)
    forged = target.out / f"plan-{plan['tree']}.json"
    forged.write_text(json.dumps(plan | {"files": ["app.py"]}), encoding="utf-8")
    run = target.out / f"run-{plan['tree']}"
    run.mkdir()
    (run / "findings.json").write_text("[]", encoding="utf-8")
    (run / "coverage-ledger.json").write_text(json.dumps(ledger(["app.py"])), encoding="utf-8")
    result = target.attest("3")
    assert result.returncode == 2
    assert "lib.py" in result.stderr


@needs_node
def test_a_seed_without_a_record_leaves_the_audit_unfinished(target):
    target.commit({"app.py": f"print(1)\n{SEEDED}\n"})
    result = audited(target, [record("confirmed", "audit:echo", "low")], ledger(["app.py"]), findings=[HIGH])
    assert result.returncode == 2
    assert seed_print(HIGH) in result.stderr


@needs_node
def test_a_ledger_candidate_without_a_record_leaves_the_audit_unfinished(target):
    target.commit({"app.py": f"print(1)\n{SEEDED}\n"})
    result = audited(target, [record("confirmed", "audit:echo", "low")], ledger(["app.py"], ["audit:open"]))
    assert result.returncode == 2
    assert "audit:open" in result.stderr


@needs_node
def test_a_rejection_that_never_names_the_seed_is_refused(target):
    target.commit({"app.py": f"print(1)\n{SEEDED}\n"})
    elsewhere = rejected_high()
    elsewhere["trace"] = [{"kind": "entrypoint", "scope": "main", "file": "lib.py", "line": 2, "description": "Read in the audit."}]
    elsewhere["evidence"] = [{"file": "lib.py", "line": 2, "description": "Read in the audit."}]
    result = audited(target, [elsewhere], ledger(["app.py"]), findings=[HIGH])
    assert result.returncode == 2
    assert "never names app.py:2" in result.stderr
    assert not (Path(target.env["AGENTS_COUNCIL_ROOT"]) / "security-accepted.jsonl").exists()


def test_a_stored_attestation_answers_only_the_same_request(target):
    target.commit({"README.md": "# app\n\nMore.\n"})
    assert json.loads(target.prepare().stdout)["profile"] == "quick"
    again = target.prepare("--profile", "standard")
    assert again.returncode == 0
    assert json.loads(again.stdout)["profile"] == "standard"


def test_a_range_without_changes_is_refused(target):
    result = target.prepare("--range", "HEAD..HEAD")
    assert result.returncode == 2
    assert "changes no file" in result.stderr


def test_an_out_dir_others_can_write_is_refused(target):
    target.out.mkdir()
    target.out.chmod(0o777)
    result = target.prepare()
    assert result.returncode == 2
    assert "writable by no one else" in result.stderr


def test_a_medusa_report_the_agents_can_write_is_refused(target):
    target.out.mkdir(mode=0o700)
    report = target.out / "medusa.json"
    report.write_text(json.dumps({"security": 100, "findings": []}), encoding="utf-8")
    result = target.run("prepare", "--repo", str(target.repo), "--out", str(target.out), "--budget", "1", "--medusa", str(report))
    assert result.returncode == 2
    assert "lies in --out" in result.stderr


def test_an_out_dir_under_a_directory_others_can_change_is_refused(target):
    shared = target.repo.parent / "shared"
    shared.mkdir()
    shared.chmod(0o777)
    target.out = shared / "out"
    result = target.prepare()
    assert result.returncode == 2
    assert f"lies under {shared}, which another user can change" in result.stderr


@pytest.mark.parametrize(
    ("uid_map", "mapped"),
    [("0 0 4294967295\n", True), ("1000 1000 1\n", False), ("0 1000 1\n", True), ("1 100000 65536\n", False)],
)
def test_only_a_namespace_without_root_trusts_the_overflow_uid(uid_map, mapped):
    spec = importlib.util.spec_from_file_location("audit_scope", AUDIT.with_name("scope.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.maps_root(uid_map) is mapped


def test_a_tag_on_a_merged_side_commit_never_moves_the_start(target):
    target.commit({"app.py": "print(2)\n"})
    target.git("checkout", "-q", "-b", "side", "v1.0.0")
    target.commit({"lib.py": "x = 1\n"})
    target.git("tag", "v99.0.0")
    target.git("checkout", "-q", "main")
    target.git("merge", "-q", "--no-ff", "-m", "merge", "side")
    plan = json.loads(target.prepare().stdout)
    assert plan["range"] == "v1.0.0..HEAD"
    assert plan["files"] == ["app.py", "lib.py"]


@pytest.mark.parametrize("name", ["requirements.txt", "skills/x/SKILL.md", "AGENTS.md", "docs/CMakeLists.txt"])
def test_build_inputs_and_agent_instructions_are_never_docs(target, name):
    target.commit({name: "pinned==1\n"})
    result = target.prepare()
    assert result.returncode == 0
    assert "verdict" not in json.loads(result.stdout)


def test_a_deleted_file_is_never_docs(target):
    target.git("rm", "-q", "app.py")
    target.commit({"README.md": "# app\n\nMore.\n"})
    assert "verdict" not in json.loads(target.prepare().stdout)


@needs_node
def test_an_archived_blocked_attempt_blocks(target):
    target.commit({"app.py": f"print(1)\n{SEEDED}\n"})
    result = audited(target, [record("confirmed", "audit:echo", "low")], [*ledger(["app.py"]), archived("blocked")])
    assert result.returncode == 1, result.stderr
    document = json.loads(result.stdout)
    assert (document["verdict"], document["coverage"]) == ("blocked", {"covered": 1, "deferred": 1})


@needs_node
def test_an_archived_candidate_without_a_record_leaves_the_audit_unfinished(target):
    target.commit({"app.py": f"print(1)\n{SEEDED}\n"})
    result = audited(target, [record("confirmed", "audit:echo", "low")], [*ledger(["app.py"]), archived("candidate", ["audit:archived"])])
    assert result.returncode == 2
    assert "audit:archived" in result.stderr


@needs_node
def test_a_blocked_audit_records_no_acceptance(target):
    target.commit({"app.py": f"print(1)\n{SEEDED}\n"})
    result = audited(target, [rejected_high(), record("needs_validation", "audit:token")], ledger(["app.py"]), findings=[HIGH])
    assert result.returncode == 1, result.stderr
    assert json.loads(result.stdout)["accepted"] == []
    assert not (Path(target.env["AGENTS_COUNCIL_ROOT"]) / "security-accepted.jsonl").exists()


@needs_node
def test_a_planted_pass_attestation_is_refused_on_reuse(target):
    target.commit({"app.py": f"print(1)\n{SEEDED}\n"})
    result = audited(target, [record("needs_validation", "audit:token")], ledger(["app.py"]))
    assert result.returncode == 1, result.stderr
    stored = target.out / f"attestation-{json.loads(result.stdout)['tree']}.json"
    stored.write_text(json.dumps(json.loads(stored.read_text(encoding="utf-8")) | {"verdict": "pass"}), encoding="utf-8")
    again = target.prepare()
    assert again.returncode == 2
    assert "disagrees with what its run supports" in again.stderr


def test_a_planted_docs_only_attestation_is_refused_on_reuse(target):
    target.commit({"app.py": "print(2)\n"})
    plan = json.loads(target.prepare().stdout)
    planted = {key: plan[key] for key in ("tree", "range", "upstream", "profile", "budget")} | {"verdict": "skipped: docs-only"}
    (target.out / f"attestation-{plan['tree']}.json").write_text(json.dumps(planted), encoding="utf-8")
    again = target.prepare()
    assert again.returncode == 2
    assert "disagrees with what its run supports" in again.stderr
