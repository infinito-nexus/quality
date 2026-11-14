from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
COMPOSE = ROOT / "ansible" / "roles" / "web-app-cst-quality-check" / "templates" / "compose.yml.j2"
REQUIRED = (
    'command: ["sleep", "infinity"]',
    "restart: unless-stopped",
    "network_mode: none",
    "read_only: true",
    'user: "{{ QUALITY_CHECK_STEP_UID }}:{{ QUALITY_CHECK_STEP_UID }}"',
    "- ALL",
    "- no-new-privileges:true",
)
FORBIDDEN = ("env_file", "environment", "volumes", "base.yml.j2", "networks", "ports")


def anchor_block() -> list:
    lines = COMPOSE.read_text(encoding="utf-8").splitlines()
    start = lines.index("  scan:")
    end = next(index for index in range(start + 1, len(lines)) if not lines[index].strip())
    return [line.strip() for line in lines[start + 1 : end]]


def test_scan_anchor_holds_nothing():
    block = anchor_block()
    assert block[0] == "{{ lookup('container_image', application_id, 'scan') }}"
    assert [line for line in REQUIRED if line not in block] == []
    assert [line for line in block if any(word in line for word in FORBIDDEN)] == []
