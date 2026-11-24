import re
import subprocess

import pytest
import yaml

from tests.service.support import ROLE, ROOT

DOCKERFILE = ROOT / "service" / "nix" / "Dockerfile"
ARG = "INFINITO_CACHE_PACKAGE_URL"
CACHE = "http://10.0.0.5:8081"
KEY = "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="


def nix_words(url: str) -> list:
    """
    Args:
        url: Value of the build argument, empty when the build has no package cache.

    Returns:
        The words the closure stage's conditional Nix options expand to under sh.
    """
    expression = re.search(r"\$\{" + ARG + r":\+.*\}", DOCKERFILE.read_text(encoding="utf-8")).group(0)
    script = f'{ARG}="$1"; set -- {expression}; for word do printf "%s\\n" "$word"; done'
    return subprocess.run(["sh", "-c", script, "sh", url], capture_output=True, text=True, check=True).stdout.splitlines()


@pytest.mark.parametrize(
    ("url", "words"),
    [
        (CACHE, ["--option", "extra-substituters", f"{CACHE}/repository/raw-nixos-cache", "--option", "trusted-public-keys", KEY]),
        ("", []),
    ],
    ids=["package-cache", "upstream"],
)
def test_the_closure_stage_fetches_through_the_package_cache_only_when_one_is_named(url, words):
    assert f"ARG {ARG}" in DOCKERFILE.read_text(encoding="utf-8")
    assert nix_words(url) == words


def test_both_image_builds_hand_dev_nix_package_cache_to_the_closure_stage():
    variables = yaml.safe_load((ROLE / "vars" / "main.yml").read_text(encoding="utf-8"))
    assert variables["QUALITY_CHECK_PACKAGE_CACHE"] == "{{ lookup('config', 'dev-nix', 'services.nix.package_cache') }}"
    tasks = yaml.safe_load((ROLE / "tasks" / "02_build_context.yml").read_text(encoding="utf-8"))
    builds = [task["ansible.builtin.command"]["argv"] for task in tasks if "ansible.builtin.command" in task]
    assert [f"--build-arg={ARG}={{{{ QUALITY_CHECK_PACKAGE_CACHE }}}}" in argv for argv in builds] == [True]
    template = (ROLE / "templates" / "compose.yml.j2").read_text(encoding="utf-8")
    assert f'{ARG}: "{{{{ QUALITY_CHECK_PACKAGE_CACHE }}}}"' in template
    service = yaml.safe_load((ROOT / "service" / "compose.yml").read_text(encoding="utf-8"))
    assert {name: spec["build"]["args"][ARG] for name, spec in service["services"].items() if "nix" in spec.get("build", {}).get("dockerfile", "")} == {
        "scan": f"${{{ARG}:-}}",
        "proxy": f"${{{ARG}:-}}",
    }
