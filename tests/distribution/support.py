import json
import os
import platform
import re
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

from tests.integration.support import ROOT, git, tools

NIX = shutil.which("nix")
SYSTEM = f"{platform.machine()}-linux"
SYSTEMS = ("x86_64-linux", "aarch64-linux")
NIX_FEATURES = ("--extra-experimental-features", "nix-command flakes")
needs_nix = pytest.mark.skipif(NIX is None, reason="needs nix")

TOOL_ALIASES = {"rg": ("ripgrep",)}
SEPARATOR = r'(?:_VERSION\s*(?:[:?]?=|:)\s*["\']?|\s*[=~!<>]=\s*|@|:|-|_|/v?|"?\s*[:=]\s*"[\^~>=<v]*)'
VERSION = r"v?(?P<version>\d+\.\d+(?:\.\d+)*)"
HAND_PINS = re.compile(
    r"\b(?:fetchurl|fetchzip|fetchgit|fetchFromGitHub|fetchTarball|fetchPypi)\b"
    r'|\b(?:version|hash|sha256|sha512|rev)\s*=\s*"'
)
INPUT_URL = re.compile(r'inputs\.(?P<name>[\w-]+)(?:\.url|\s*=\s*\{[^}]*?\burl)\s*=\s*"(?P<url>[^"]+)"')
PIN_SOURCE = "flake.lock"
FLAKE = "flake.nix"
IMAGE_MANIFEST = "manifest.json"


def flake_ref(root: Path) -> str:
    return f"path:{root}"


def nix(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([NIX, *NIX_FEATURES, *args], capture_output=True, text=True, check=False)


def nix_eval(root: Path, attribute: str) -> str:
    result = nix("eval", "--raw", f"{flake_ref(root)}#{attribute}")
    assert result.returncode == 0, result.stderr
    return result.stdout


def nix_json(root: Path, attribute: str):
    result = nix("eval", "--json", f"{flake_ref(root)}#{attribute}")
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def built(attribute: str) -> Path:
    """
    Args:
        attribute: Package attribute of this system, such as `image`.

    Returns:
        The output of this repository's flake, built already by
        `nix build .#default .#image`.
    """
    if NIX is None:
        pytest.skip("needs nix")
    result = nix("path-info", f"{flake_ref(ROOT)}#packages.{SYSTEM}.{attribute}")
    if result.returncode != 0:
        pytest.fail(f"the {attribute} output of this tree is not built, run `nix build .#default .#image`: {result.stderr.strip()}")
    return Path(result.stdout.strip())


def repository_files(root: Path) -> list:
    listing = git(root, "ls-files", "-z", "-c", "-o", "--exclude-standard").stdout
    return sorted({name for name in listing.split("\0") if name and not (root / name).is_symlink()})


def copy_of(root: Path, destination: Path) -> Path:
    for name in repository_files(root):
        source = root / name
        if source.is_file():
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
    return destination


def repository_texts(root: Path) -> dict:
    texts = {}
    for name in repository_files(root):
        path = root / name
        if name != PIN_SOURCE and path.is_file():
            try:
                texts[name] = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
    return texts


def tool_names() -> dict:
    return {name: (name, *TOOL_ALIASES.get(name, ())) for name in tools()}


def pin_pattern(names: dict) -> re.Pattern:
    spellings = {spelling: tool for tool, aliases in names.items() for spelling in aliases}
    alternatives = "|".join(re.escape(spelling) for spelling in sorted(spellings, key=len, reverse=True))
    return re.compile(rf"(?<![\w-])(?P<tool>{alternatives})[\w.-]*?{SEPARATOR}{VERSION}(?!\w)", re.IGNORECASE)


def canonical(names: dict, spelling: str) -> str:
    return next(tool for tool, aliases in names.items() if spelling.lower() in aliases)


def input_pins(flake: str, pattern: re.Pattern, names: dict) -> tuple:
    """
    Args:
        flake: Text of flake.nix.
        pattern: Pin pattern of the tools.
        names: Tool name to its spellings.

    Returns:
        flake.nix without its input URLs, and the versions those URLs name
        per tool.
    """
    versions = {}
    for declared in INPUT_URL.finditer(flake):
        for pin in pattern.finditer(declared.group("url")):
            versions.setdefault(canonical(names, pin.group("tool")), set()).add(pin.group("version"))
    return INPUT_URL.sub("", flake), versions


def pin_violations(texts: dict, names: dict) -> list:
    """
    Args:
        texts: Repository file name to its text, flake.lock left out.
        names: Tool name to its spellings.

    Returns:
        One line per tool version written outside flake.lock and the flake
        inputs it locks, per hand-written version or hash in flake.nix, and
        per tool whose inputs name more than one version.
    """
    pattern = pin_pattern(names)
    violations = []
    for name, text in sorted(texts.items()):
        if name == FLAKE:
            text, versions = input_pins(text, pattern, names)
            violations += [f"{FLAKE}: {tool} inputs name {sorted(found)}" for tool, found in versions.items() if len(found) > 1]
            violations += [f"{FLAKE}: hand pin {hit.group(0)!r}" for hit in HAND_PINS.finditer(text)]
        violations += [f"{name}: {hit.group(0)!r}" for hit in pattern.finditer(text)]
    return violations


def image_contents(tarball: Path) -> tuple:
    """
    Args:
        tarball: The gzipped docker archive `packages.image` builds.

    Returns:
        Every entry name of the archive and of each of its layers, those of
        the customisation layer without their leading `./`, and the image
        config its manifest.json names.

    Raises:
        ValueError: The manifest names more or fewer than one image.
    """
    names = []
    blobs = {}
    with tarfile.open(tarball, "r|gz") as archive:
        for member in archive:
            names.append(member.name)
            if member.name.endswith("layer.tar"):
                with tarfile.open(fileobj=archive.extractfile(member), mode="r|") as layer:
                    names += [entry.name.removeprefix("./") for entry in layer]
            elif member.isfile() and "/" not in member.name and member.name.endswith(".json"):
                blobs[member.name] = archive.extractfile(member).read()
    (entry,) = json.loads(blobs[IMAGE_MANIFEST])
    return names, json.loads(blobs[entry["Config"]])


def clean_env() -> dict:
    return {"PATH": os.environ["PATH"]}
