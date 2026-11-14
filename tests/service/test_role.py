import json
import os
import shutil
import subprocess

import pytest

from tests.service.support import ROLE

CORE_TASKS = ROLE / "tasks" / "00_core.yml"
MODE_REFUSAL = "deploys in compose mode only"
DEMO_REFUSAL = "would name core's demo data"
CORE_MODULE = "stack_host_template"


def deploy(tmp_path, mode):
    """
    Args:
        tmp_path: Scratch directory for the playbook, stubs of core's once-flag include and stack_host_template module,
            and Ansible's own files.
        mode: DEPLOYMENT_MODE of the run.

    Returns:
        The completed ansible-playbook run of tasks/00_core.yml, stopped by the demo-data assert.
    """
    playbook = shutil.which("ansible-playbook")
    if playbook is None:
        pytest.skip("ansible-playbook is not on PATH")
    stub = tmp_path / "utils" / "once" / "flag.yml"
    stub.parent.mkdir(parents=True)
    stub.write_text("- ansible.builtin.meta: noop\n", encoding="utf-8")
    module = tmp_path / "library" / f"{CORE_MODULE}.py"
    module.parent.mkdir()
    module.write_text(f"raise SystemExit('{CORE_MODULE} stands in for core\\'s module and never runs')\n", encoding="utf-8")
    play = [{"hosts": "localhost", "gather_facts": False, "vars": {"IS_COMPOSE_MODE": "{{ DEPLOYMENT_MODE == 'compose' }}"}}]
    play[0]["tasks"] = [{"ansible.builtin.import_tasks": str(CORE_TASKS)}]
    (tmp_path / "play.yml").write_text(json.dumps(play), encoding="utf-8")
    (tmp_path / "ansible.cfg").write_text("", encoding="utf-8")
    extra = {"DEPLOYMENT_MODE": mode, "ENVIRONMENT": "production", "application_id": "web-app-cst-quality-check"}
    extra["QUALITY_CHECK_CONTROLLER_DEMO_FIELDS"] = ["contact.email"]
    environment = {**os.environ, "ANSIBLE_CONFIG": str(tmp_path / "ansible.cfg"), "ANSIBLE_LOCAL_TEMP": str(tmp_path / "local")}
    environment.update(ANSIBLE_NOCOLOR="1", ANSIBLE_RETRY_FILES_ENABLED="0")
    argv = [playbook, "-i", "localhost,", "-c", "local", "-e", json.dumps(extra), str(tmp_path / "play.yml")]
    return subprocess.run(argv, cwd=tmp_path, env=environment, capture_output=True, text=True, timeout=300, check=False)


def test_deploy_refuses_swarm(tmp_path):
    refused = deploy(tmp_path / "swarm", "swarm")
    output = refused.stdout + refused.stderr
    assert refused.returncode != 0, output
    assert f"{MODE_REFUSAL}, not in swarm mode" in output
    assert DEMO_REFUSAL not in output


def test_deploy_passes_compose_to_the_next_assert(tmp_path):
    passed = deploy(tmp_path / "compose", "compose")
    output = passed.stdout + passed.stderr
    assert MODE_REFUSAL not in output, output
    assert DEMO_REFUSAL in output
