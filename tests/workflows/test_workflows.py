import re
from pathlib import Path

import pytest
import yaml

WORKFLOWS = Path(__file__).resolve().parents[2] / ".github" / "workflows"
FILES = ["quality.yml", "release.yml"]
PINNED = re.compile(r"^[\w.-]+/[\w.-]+(?:/[\w./-]+)?@[0-9a-f]{40}$")
USES_LINE = re.compile(r"^\s*(?:-\s+)?uses:\s*(\S+)(.*)$")
VERSION_COMMENT = re.compile(r"^ # v\d+(?:\.\d+)*$")
PIP = re.compile(r"\bpip3?\s+install\b|-m\s+pip\b")
FLAKE_BUILD = 'nix build "github:infinito-nexus/quality/${QUALITY_REF}#default"'


def load(name: str) -> dict:
    return yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))


def triggers(workflow: dict) -> dict:
    return workflow[True]


def script_of(job: dict) -> str:
    return "\n".join(step.get("run", "") for step in job.get("steps", []))


def parsed_uses(workflow: dict) -> list:
    found = []
    for job in workflow["jobs"].values():
        found += [job["uses"]] if "uses" in job else []
        found += [step["uses"] for step in job.get("steps", []) if "uses" in step]
    return found


def ancestors(jobs: dict, name: str) -> set:
    needs = jobs[name].get("needs", [])
    direct = {needs} if isinstance(needs, str) else set(needs)
    return direct.union(*(ancestors(jobs, parent) for parent in direct))


def grants_id_token(permissions) -> bool:
    if isinstance(permissions, str):
        return permissions == "write-all"
    return (permissions or {}).get("id-token") == "write"


def step_index(job: dict, predicate) -> int:
    matches = [index for index, step in enumerate(job["steps"]) if predicate(step)]
    assert len(matches) == 1, matches
    return matches[0]


def test_quality_is_reusable_with_typed_inputs():
    inputs = triggers(load("quality.yml"))["workflow_call"]["inputs"]
    assert {"quality-ref", "base-ref", "db-cache-key"} <= inputs.keys()
    assert inputs["quality-ref"]["required"] is True
    assert all(spec.get("type") in {"string", "boolean", "number"} for spec in inputs.values())


def test_quality_checks_out_full_history():
    steps = load("quality.yml")["jobs"]["check"]["steps"]
    checkouts = [step for step in steps if step.get("uses", "").startswith("actions/checkout@")]
    assert checkouts
    assert all(step.get("with", {}).get("fetch-depth") == 0 for step in checkouts)


def test_quality_builds_the_tool_from_its_own_flake():
    job = load("quality.yml")["jobs"]["check"]
    install = job["steps"][step_index(job, lambda step: FLAKE_BUILD in step.get("run", ""))]
    assert install["env"]["QUALITY_REF"] == "${{ inputs.quality-ref }}"
    assert "^[0-9a-f]{40}$" in install["run"]
    every_job = [each for name in FILES for each in load(name)["jobs"].values()]
    assert not any(PIP.search(script_of(each)) for each in every_job)


def test_quality_fetches_the_database_before_an_offline_scan():
    job = load("quality.yml")["jobs"]["check"]
    restore = step_index(job, lambda step: step.get("uses", "").startswith("actions/cache/restore@"))
    update = step_index(job, lambda step: " db update " in step.get("run", ""))
    save = step_index(job, lambda step: step.get("uses", "").startswith("actions/cache/save@"))
    scan = step_index(job, lambda step: " check --base " in step.get("run", ""))
    assert restore < update < save < scan
    assert job["steps"][restore]["with"]["key"] == job["steps"][save]["with"]["key"]
    assert job["steps"][scan]["run"].startswith("sudo unshare --net -- ")
    assert "continue-on-error" not in job["steps"][scan]


def test_quality_gates_and_scans_the_whole_range():
    job = load("quality.yml")["jobs"]["check"]
    base = job["steps"][step_index(job, lambda step: step.get("id") == "base")]
    assert 'test "$(git rev-parse --is-shallow-repository)" = false' in base["run"]
    scan = job["steps"][step_index(job, lambda step: " check --base " in step.get("run", ""))]
    assert scan["env"]["BASE"] == "${{ steps.base.outputs.sha }}"
    assert 'check --base "$BASE" --db ' in scan["run"]


@pytest.mark.parametrize("name", FILES)
def test_every_action_is_pinned_to_a_commit_with_its_version(name: str):
    lines = (WORKFLOWS / name).read_text(encoding="utf-8").splitlines()
    pins = [match.groups() for match in map(USES_LINE.match, lines) if match]
    assert pins
    assert len(pins) == len(parsed_uses(load(name)))
    assert [ref for ref, _ in pins if not PINNED.match(ref)] == []
    assert [ref for ref, comment in pins if not VERSION_COMMENT.match(comment)] == []


@pytest.mark.parametrize("name", FILES)
def test_top_level_permissions_are_read_only(name: str):
    assert load(name)["permissions"] == {"contents": "read"}


def test_quality_jobs_add_no_permissions():
    assert all("permissions" not in job for job in load("quality.yml")["jobs"].values())


@pytest.mark.parametrize(("name", "holders"), [("quality.yml", set()), ("release.yml", {"publish"})], ids=FILES)
def test_id_token_only_in_the_publish_job(name: str, holders: set):
    workflow = load(name)
    assert not grants_id_token(workflow["permissions"])
    jobs = workflow["jobs"]
    assert {job_name for job_name, job in jobs.items() if grants_id_token(job.get("permissions"))} == holders
    assert all(jobs[holder]["permissions"] == {"id-token": "write"} for holder in holders)


def test_publish_uses_trusted_publishing_behind_an_environment():
    publish = load("release.yml")["jobs"]["publish"]
    assert publish["environment"]["name"]
    assert [step for step in publish["steps"] if step.get("uses", "").startswith("pypa/gh-action-pypi-publish@")]
    assert not any("password" in step.get("with", {}) for step in publish["steps"])


def test_tag_signature_is_verified_before_anything_ships():
    workflow = load("release.yml")
    assert triggers(workflow) == {"push": {"tags": ["v[0-9]+.[0-9]+.[0-9]+"]}}
    jobs = workflow["jobs"]
    assert [name for name, job in jobs.items() if "git tag -v" in script_of(job)] == ["verify"]
    assert all("verify" in ancestors(jobs, shipping) for shipping in ("build", "publish", "image", "release"))
    verify = jobs["verify"]
    assert verify["steps"][-1]["env"]["SIGNERS"].endswith(":.github/release-signers.asc")
    assert not any(step.get("continue-on-error") for step in verify["steps"])
    assert "||" not in script_of(verify)


def test_image_is_gated_and_built_from_the_flake_for_both_architectures():
    jobs = load("release.yml")["jobs"]
    image = jobs["image"]
    assert "vars.QUALITY_IMAGE_RELEASE" in image.get("if", "")
    assert "nix build .#image" in script_of(image)
    assert {entry["arch"] for entry in image["strategy"]["matrix"]["include"]} == {"amd64", "arm64"}
    assert "--digestfile" in script_of(image)
    assert jobs["image-index"]["outputs"]["digest"] == "${{ steps.index.outputs.digest }}"
    assert jobs["release"]["steps"][-1]["env"]["DIGEST"] == "${{ needs.image-index.outputs.digest }}"
