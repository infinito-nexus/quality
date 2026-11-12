import json

import pytest

from tests.distribution.support import (
    FLAKE,
    PIN_SOURCE,
    ROOT,
    SYSTEM,
    SYSTEMS,
    built,
    flake_ref,
    image_contents,
    needs_nix,
    nix,
    nix_eval,
    nix_json,
    pin_violations,
    repository_texts,
    tool_names,
    tools,
)

IMAGE_LIMIT = 1 << 30
NOBODY = "65534:65534"
NOTICES = "share/doc/quality/NOTICES"
PACKAGES = ("default", "image", "tools", "scan", "proxy")


def planted(tool: str, separator: str, version: str) -> str:
    """
    Args:
        tool: Tool spelling.
        separator: What joins it to the version.
        version: Version text.

    Returns:
        The pin, built at run time.
    """
    return f"{tool}{separator}{version}"


def jscpd_input(name: str, version: str) -> str:
    return f'inputs.{name} = {{ url = "https://example.org/{planted("jscpd-linux-x64-gnu", "-", version)}.tgz"; }};\n'


def test_single_pin_source():
    assert pin_violations(repository_texts(ROOT), tool_names()) == []


@pytest.mark.parametrize(
    "name, before, pin, after",
    [
        ("Makefile", "\tpip install ", ("ruff", "==", "0.6.0"), "\n"),
        ("requirements.txt", "", ("semgrep", ">=", "1.2"), "\n"),
        ("Dockerfile", "FROM ghcr.io/aquasecurity/", ("trivy", ":", "0.50.0"), "\n"),
        ("package.json", '{"', ("jscpd", '": "^', "4.0.5"), '"}\n'),
        ("pyproject.toml", "", ("ruff", ' = "', "0.6.0"), '"\n'),
        ("x.sh", "npx ", ("jscpd", "@", "4.0.5"), "\n"),
        ("x.sh", "curl -O https://example.org/", ("ripgrep", "-", "14.1.0"), ".tgz\n"),
        ("Dockerfile", "ENV ", ("TRIVY", "_VERSION=", "0.50.0"), "\n"),
        ("Dockerfile", "ARG ", ("RUFF", "_VERSION=", "0.6.0"), "\n"),
        ("Makefile", "", ("GITLEAKS", "_VERSION := ", "8.18.0"), "\n"),
        ("Makefile", "", ("SHELLCHECK", "_VERSION ?= ", "0.10.0"), "\n"),
        ("ci.yml", "  ", ("TRIVY", "_VERSION: ", "0.50.0"), "\n"),
        ("x.sh", "", ("hadolint", "_version='", "2.12.0"), "'\n"),
    ],
)
def test_single_pin_source_finds_a_pin_in_any_file(name, before, pin, after):
    text = f"{before}{planted(*pin)}{after}"
    violations = pin_violations({name: text}, tool_names())
    assert any(planted(*pin) in line for line in violations), violations


@pytest.mark.parametrize(
    "text, expected",
    [
        ("jscpd = mkDerivation { " + planted("version", ' = "', "5.4.2") + '"; };\n', "hand pin"),
        ("src = fetchurl { url = x; };\n", "hand pin 'fetchurl'"),
        (jscpd_input("a", "5.4.2") + jscpd_input("b", "5.4.3"), "jscpd inputs name ['5.4.2', '5.4.3']"),
    ],
)
def test_single_pin_source_finds_hand_pins_in_the_flake(text, expected):
    violations = pin_violations({FLAKE: text}, tool_names())
    assert any(expected in line for line in violations), violations


@pytest.mark.parametrize(
    "text",
    [
        "osv-scanner 2.7 confirms each lockfile\n",
        "db_repository: ghcr.io/aquasecurity/trivy-db:2\n",
        "ruff 0.10 s, ast-grep 0.25 s\n",
        jscpd_input("jscpd-x86_64-linux", "5.4.2") + jscpd_input("jscpd-aarch64-linux", "5.4.2"),
    ],
)
def test_single_pin_source_passes_prose_and_locked_inputs(text):
    assert pin_violations({FLAKE: text}, tool_names()) == []


def test_every_flake_input_is_locked():
    lock = json.loads((ROOT / PIN_SOURCE).read_text(encoding="utf-8"))
    for name in lock["nodes"]["root"]["inputs"].values():
        assert lock["nodes"][name]["locked"]["narHash"].startswith("sha256-"), name


@needs_nix
def test_every_package_evaluates_for_both_platforms():
    expression = "packages: builtins.mapAttrs (_: system: builtins.mapAttrs (_: package: package.drvPath) system) packages"
    result = nix("eval", "--json", f"{flake_ref(ROOT)}#packages", "--apply", expression)
    assert result.returncode == 0, result.stderr
    paths = json.loads(result.stdout)
    assert sorted(paths) == sorted(SYSTEMS)
    for system in SYSTEMS:
        assert sorted(paths[system]) == sorted(PACKAGES), system


@needs_nix
@pytest.mark.parametrize("system", SYSTEMS)
def test_pins_name_git_and_every_tool(system):
    pins = nix_json(ROOT, f"packages.{system}.default.passthru.pins")
    assert sorted(pins) == sorted(["git", *tools()])
    for name, pin in pins.items():
        assert pin["path"].startswith("/nix/store/") and pin["path"].endswith(f"/bin/{name}"), name
        assert pin["version"] and pin["licences"], name


@needs_nix
def test_notices_name_every_bundled_tool_with_its_licence():
    pins = nix_json(ROOT, f"packages.{SYSTEM}.default.passthru.pins")
    lines = nix_eval(ROOT, f"packages.{SYSTEM}.default.passthru.noticesText").splitlines()
    assert lines[0].endswith(": MIT")
    for pin in pins.values():
        expected = f"{pin['package']} {pin['version']}: {', '.join(pin['licences'])}"
        assert expected in lines, expected
    assert not any("medusa" in line.lower() for line in lines)


@needs_nix
@pytest.mark.parametrize("version, fails", [("8.0.0", True), ("7.9", False)])
def test_proxy_version(version, fails):
    changed = f'previous.squid.overrideAttrs (_: {{ version = "{version}"; __intentionallyOverridingVersion = true; }})'
    expression = (
        f'let flake = builtins.getFlake "{flake_ref(ROOT)}"; '
        f'pkgs = import flake.inputs.nixpkgs {{ system = "{SYSTEM}"; }}; '
        f"changed = pkgs.extend (_: previous: {{ squid = {changed}; }}); "
        "in (flake.lib.proxyFor changed).drvPath"
    )
    result = nix("eval", "--impure", "--raw", "--expr", expression)
    if fails:
        assert result.returncode != 0
        assert '"7"' in result.stderr, result.stderr
    else:
        assert result.returncode == 0, result.stderr


@needs_nix
def test_proxy_package_is_the_guarded_one():
    expression = (
        f'let flake = builtins.getFlake "{flake_ref(ROOT)}"; '
        f'pkgs = import flake.inputs.nixpkgs {{ system = "{SYSTEM}"; }}; '
        f"in (flake.lib.proxyFor pkgs).drvPath == flake.packages.{SYSTEM}.proxy.drvPath"
    )
    result = nix("eval", "--impure", "--json", "--expr", expression)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) is True


@pytest.fixture(scope="module")
def image():
    tarball = built("image")
    return (tarball, *image_contents(tarball))


@needs_nix
def test_image_is_at_most_1_gib_compressed(image):
    tarball, _members, _config = image
    assert tarball.stat().st_size <= IMAGE_LIMIT


@needs_nix
def test_image_runs_as_nobody(image):
    _tarball, _members, config = image
    assert config["config"]["User"] == NOBODY


@needs_nix
def test_image_holds_the_notices_and_no_medusa(image):
    _tarball, members, _config = image
    assert NOTICES in members
    assert [name for name in members if "medusa" in name.lower()] == []
    notices = (built("default") / NOTICES).read_text(encoding="utf-8")
    assert notices == nix_eval(ROOT, f"packages.{SYSTEM}.default.passthru.noticesText")
