import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
ROLE = "web-app-cst-quality-check"


def test_verify_deploy_keeps_database_updates():
    script = ROOT / "service" / "verify" / "extra_vars.py"
    output = subprocess.run([sys.executable, "-I", str(script), ROLE, str(ROOT)], capture_output=True, text=True, check=True)
    services = json.loads(output.stdout)["applications"][ROLE]["services"]
    assert all("database" not in service for service in services.values())
