import json
from pathlib import Path

import jinja2
import yaml

ROOT = Path(__file__).resolve().parents[3]
COMPOSE = ROOT / "ansible" / "roles" / "web-app-cst-quality-check" / "templates" / "compose.yml.j2"
INCLUDES = {
    "roles/sys-svc-compose/templates/base.yml.j2": "services:",
    "roles/sys-svc-container/templates/base.yml.j2": "base: included",
    "roles/sys-svc-container/templates/deploy.yml.j2": "deploy: included",
}
OPENS = {"compose_networks": "networks:"}


class Named(jinja2.ChainableUndefined):
    def __str__(self):
        return self._undefined_name


def lookup(name, *args, **_kwargs):
    if name in OPENS:
        return OPENS[name]
    return f"{name}: {json.dumps([str(arg) for arg in args])}"


def services() -> dict:
    """
    Returns:
        The template's services, rendered with each include and lookup as a
        key that names it and each undefined variable as its name.
    """
    environment = jinja2.Environment(loader=jinja2.DictLoader(INCLUDES), undefined=Named)
    environment.filters["bool"] = bool
    rendered = environment.from_string(COMPOSE.read_text(encoding="utf-8")).render(lookup=lookup)
    return yaml.safe_load(rendered)["services"]


def test_scan_anchor_holds_nothing():
    assert services()["scan"] == {
        "deploy": "included",
        "container_image": ["application_id", "scan"],
        "compose_only": ["container_name", "QUALITY_CHECK_SCAN"],
        "command": ["sleep", "infinity"],
        "compose_restart": [],
        "template": ["roles/sys-svc-container/templates/logging.yml.j2"],
        "network_mode": "none",
        "read_only": True,
        "user": "QUALITY_CHECK_STEP_UID:QUALITY_CHECK_STEP_UID",
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "mem_limit": "16m",
        "pids_limit": 4,
    }
