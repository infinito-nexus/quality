"""
Args:
    argv[1]: role name, web-app-cst-quality-check.
    argv[2]: checkout of this repository the role builds its images from.

Output:
    One JSON object on stdout for INFINITO_INVENTORY_EXTRA_VARS: the role source, the local image tag for every
    image, so the registry probe misses and the role builds from the checkout, and no vulnerability database,
    because `quality db update` arrives with phase C of requirement 001.
"""

import json
import sys

IMAGES = ("quality-check", "scan", "proxy")

role, repo = sys.argv[1], sys.argv[2]
services = {name: {"version": "local"} for name in IMAGES}
services["quality-check"]["database"] = {"update_hours": None, "max_age_hours": 168}
application = {"source": {"url": repo, "path": f"ansible/roles/{role}"}, "services": services}
print(json.dumps({"applications": {role: application}}))
