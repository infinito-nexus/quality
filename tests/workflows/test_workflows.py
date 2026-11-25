import re
from pathlib import Path

import pytest
import yaml

WORKFLOWS = Path(__file__).resolve().parents[2] / ".github" / "workflows"
FILES = ["ort.yml", "quality.yml", "release.yml", "tests.yml", "tool.yml", "update.yml"]
ORT_PIN = WORKFLOWS.parent / "ort" / "image"
ORT_IMAGE = re.compile(r"^ghcr\.io/oss-review-toolkit/ort:\d+\.\d+\.\d+@sha256:[0-9a-f]{64}\n$")
ORT_COMMANDS = (" analyze ", " evaluate ", " report ")
PIN_CHECK = 'image="$(python3 .github/ort/pin.py check .github/ort/image)"'
PIN_UPDATE = "python3 .github/ort/pin.py update .github/ort/image"
ORT_EXCLUDES = "yq -o=json 'explode(.)' rules/legal.yml | python3 .github/ort/excludes.py > \"$RUNNER_TEMP/ort-project/.ort.yml\""
SUITE = "nix develop --command make test-unit test-integration test-service"
PINNED = re.compile(r"^[\w.-]+/[\w.-]+(?:/[\w./-]+)?@[0-9a-f]{40}$")
USES_LINE = re.compile(r"^\s*(?:-\s+)?uses:\s*(\S+)(.*)$")
VERSION_COMMENT = re.compile(r"^ # v\d+(?:\.\d+)*$")
PIP = re.compile(r"\bpip3?\s+install\b|-m\s+pip\b")
FLAKE_BUILD = 'nix build "github:infinito-nexus/quality/${QUALITY_REF}#default"'
FLAKE_RUN = 'nix shell "github:infinito-nexus/quality/${QUALITY_REF}#${TOOL}" --command "$TOOL" "${args[@]}"'
OWN_COMMIT = "${{ job.workflow_sha }}"


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
    assert inputs["quality-ref"]["required"] is False
    assert inputs["quality-ref"]["default"] == ""
    assert all(spec.get("type") in {"string", "boolean", "number"} for spec in inputs.values())


def test_quality_checks_out_full_history():
    steps = load("quality.yml")["jobs"]["check"]["steps"]
    checkouts = [step for step in steps if step.get("uses", "").startswith("actions/checkout@")]
    assert checkouts
    assert all(step.get("with", {}).get("fetch-depth") == 0 for step in checkouts)


def test_quality_builds_the_tool_from_its_own_flake():
    job = load("quality.yml")["jobs"]["check"]
    install = job["steps"][step_index(job, lambda step: FLAKE_BUILD in step.get("run", ""))]
    assert install["env"]["QUALITY_REF"] == "${{ inputs.quality-ref || job.workflow_sha }}"
    assert "^[0-9a-f]{40}$" in install["run"]
    assert install["run"].rstrip().endswith('echo "ref=${QUALITY_REF}" >> "$GITHUB_OUTPUT"')
    every_job = [each for name in FILES for each in load(name)["jobs"].values()]
    assert not any(PIP.search(script_of(each)) for each in every_job)


def test_quality_keys_the_database_cache_by_the_resolved_ref():
    caches = [step["with"] for step in load("quality.yml")["jobs"]["check"]["steps"] if step.get("uses", "").startswith("actions/cache/")]
    keys = [settings[key] for settings in caches for key in ("key", "restore-keys") if key in settings]
    assert len(keys) == 3
    assert all("${{ steps.quality.outputs.ref }}" in key and "inputs.quality-ref" not in key for key in keys)


def test_tool_runs_the_named_package_of_its_own_flake():
    workflow = load("tool.yml")
    inputs = triggers(workflow)["workflow_call"]["inputs"]
    assert {name: (spec["required"], spec["type"]) for name, spec in inputs.items()} == {"tool": (True, "string"), "args": (True, "string")}
    assert all("permissions" not in job for job in workflow["jobs"].values())
    job = workflow["jobs"]["run"]
    run = job["steps"][step_index(job, lambda step: FLAKE_RUN in step.get("run", ""))]
    assert run["env"] == {"QUALITY_REF": OWN_COMMIT, "TOOL": "${{ inputs.tool }}", "ARGS": "${{ inputs.args }}"}
    assert '[[ ! "$QUALITY_REF" =~ ^[0-9a-f]{40}$ ]]' in run["run"]
    assert '[[ ! "$TOOL" =~ ^[a-z][a-z0-9-]*$ ]]' in run["run"]
    assert run["run"].rstrip().endswith(FLAKE_RUN)
    assert "${{" not in run["run"]


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


@pytest.mark.parametrize(
    ("name", "holders"),
    [("ort.yml", set()), ("quality.yml", set()), ("release.yml", {"publish"}), ("tests.yml", set()), ("tool.yml", set()), ("update.yml", set())],
    ids=FILES,
)
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


def test_pull_requests_and_main_run_the_suite():
    workflow = load("tests.yml")
    assert {"pull_request", "push"} <= triggers(workflow).keys()
    assert all(SUITE in script_of(job) and "permissions" not in job for job in workflow["jobs"].values())


def test_flake_lock_update_tests_the_new_pins_before_its_pull_request():
    workflow = load("update.yml")
    assert {"schedule", "workflow_dispatch"} <= triggers(workflow).keys()
    job = workflow["jobs"]["flake-lock"]
    inputs = step_index(job, lambda step: step.get("run", "").endswith("python3 .github/update/inputs.py flake.nix"))
    update = step_index(job, lambda step: step.get("run") == "nix flake update")
    pin = step_index(job, lambda step: step.get("run") == PIN_UPDATE)
    suite = step_index(job, lambda step: step.get("run") == SUITE)
    handed = step_index(job, lambda step: step.get("uses", "").startswith("actions/upload-artifact@"))
    assert inputs < update < pin < suite < handed == len(job["steps"]) - 1
    assert "--inputs-from ." in job["steps"][inputs]["run"]
    assert job["steps"][handed]["with"]["path"].split() == ["flake.nix", "flake.lock", ".github/ort/image"]
    assert job["steps"][handed]["with"]["include-hidden-files"] is True
    assert "permissions" not in job
    assert list(workflow["jobs"]) == ["flake-lock", "pull-request"]


def test_the_update_pull_request_job_runs_no_tool_its_token_could_leak_to():
    job = load("update.yml")["jobs"]["pull-request"]
    assert job["needs"] == "flake-lock"
    assert job["permissions"] == {"contents": "write", "pull-requests": "write"}
    uses = [step["uses"].split("@")[0] for step in job["steps"] if "uses" in step]
    assert uses == ["actions/checkout", "actions/download-artifact", "peter-evans/create-pull-request"]
    assert script_of(job).split() == [
        "cp", "--", '"$RUNNER_TEMP/flake-lock/flake.nix"', '"$RUNNER_TEMP/flake-lock/flake.lock"', ".",
        "cp", "--", '"$RUNNER_TEMP/flake-lock/.github/ort/image"', ".github/ort/image",
    ]
    assert job["steps"][-1]["with"]["add-paths"] == "flake.lock,flake.nix,.github/ort/image"


def test_ort_runs_only_on_pushes_to_the_default_branch():
    assert triggers(load("ort.yml")) == {"push": {"branches": ["main"]}}


def test_ort_runs_a_digest_pinned_image_and_uploads_its_report():
    job = load("ort.yml")["jobs"]["dependency-tree"]
    assert "permissions" not in job
    assert ORT_IMAGE.match(ORT_PIN.read_text(encoding="utf-8"))
    assert "ORT_IMAGE" not in job["env"]
    read = step_index(job, lambda step: PIN_CHECK in step.get("run", ""))
    assert read == 1 and '>> "$GITHUB_ENV"' in job["steps"][read]["run"]
    assert job["steps"][0]["uses"].startswith("actions/checkout@")
    runs = [step["run"] for step in job["steps"][read + 1 :] if "docker run " in step.get("run", "")]
    assert runs and all('"$ORT_IMAGE" ' in run for run in runs)
    assert not any("docker run " in step.get("run", "") for step in job["steps"][:read])
    assert [command for command in ORT_COMMANDS if not any(f'"$ORT_IMAGE"{command}' in run for run in runs)] == []
    report = step_index(job, lambda step: '"$ORT_IMAGE" report ' in step.get("run", ""))
    upload = step_index(job, lambda step: step.get("uses", "").startswith("actions/upload-artifact@"))
    assert report < upload
    assert job["steps"][upload]["with"]["path"] == "${{ runner.temp }}/ort"
    assert job["steps"][upload]["with"]["if-no-files-found"] == "error"
    assert "!cancelled()" in job["steps"][upload]["if"]


def test_ort_analyzes_a_writable_copy_and_mounts_the_checkout_read_only():
    job = load("ort.yml")["jobs"]["dependency-tree"]
    copy = step_index(job, lambda step: step.get("run", "").startswith('cp -a -- "$GITHUB_WORKSPACE/." "$RUNNER_TEMP/ort-project"'))
    analyze = step_index(job, lambda step: '"$ORT_IMAGE" analyze ' in step.get("run", ""))
    assert copy < analyze
    assert '--volume "$RUNNER_TEMP/ort-project:/project" ' in job["steps"][analyze]["run"]
    mounts = [step["run"] for step in job["steps"] if "docker run " in step.get("run", "") and "$GITHUB_WORKSPACE" in step["run"]]
    assert mounts and all('--volume "$GITHUB_WORKSPACE:/project:ro" ' in run for run in mounts)


def test_ort_excludes_the_exempt_paths_of_rules_legal_in_the_analyzed_copy():
    job = load("ort.yml")["jobs"]["dependency-tree"]
    copy = step_index(job, lambda step: ORT_EXCLUDES in step.get("run", ""))
    analyze = step_index(job, lambda step: '"$ORT_IMAGE" analyze ' in step.get("run", ""))
    assert copy < analyze
    lines = job["steps"][copy]["run"].splitlines()
    assert lines.index(ORT_EXCLUDES) == 1 and lines[0].startswith("cp -a -- ")
    assert "--repository-configuration-file" not in job["steps"][analyze]["run"]
