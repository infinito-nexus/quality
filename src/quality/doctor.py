import json
import os
import re
import shutil
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from quality import QualityError, __version__, db, printable
from quality.environment import tool_environment, validated_path
from quality.process import run
from quality.ruledata import RuleData, load, locate

PINS = Path(__file__).with_name("pins.json")
GIT = "git"
VERSION_SHAPE = re.compile(r"\d+(?:\.\d+)+")
NO_VERSION = "no version"
PIN_KEYS = ("version", "path")


@dataclass(frozen=True)
class Context:
    """
    Args:
        pins: Tool name to its pinned package, version, executable path and
            licences, None without a readable manifest.
        path_value: Validated PATH, empty when the caller has none.
        scratch: Directory every version call runs in, also its HOME.
        gaps: Gap lines, extended by every check.
    """

    pins: dict | None
    path_value: str
    scratch: Path
    gaps: list


def read_pins(path: Path, gaps: list) -> dict | None:
    """
    Args:
        path: The pin manifest the flake writes into the package.
        gaps: Gap lines, extended when the manifest is missing, unreadable
            or no JSON object.

    Returns:
        The manifest, or None.
    """
    try:
        pins = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        gaps.append(f"no pinned versions: {path} is missing, so this is no flake build (`nix build .#default`)")
        return None
    except (OSError, ValueError):
        gaps.append(f"no pinned versions: {path} is unreadable")
        return None
    if not isinstance(pins, dict):
        gaps.append(f"no pinned versions: {path} holds no JSON object")
        return None
    return pins


def pin_of(name: str, context: Context) -> dict | None:
    """
    Args:
        name: Executable name.
        context: The running diagnosis, its gaps extended when the manifest
            lacks the tool or its pin lacks a version or a path.

    Returns:
        The pin of the tool, or None.
    """
    if context.pins is None:
        return None
    pin = context.pins.get(name)
    if pin is None:
        context.gaps.append(f"{name}: no pinned version")
        return None
    if not isinstance(pin, dict) or not all(isinstance(pin.get(key), str) and pin.get(key) for key in PIN_KEYS):
        context.gaps.append(f"{name}: malformed pin, needs a version and a path")
        return None
    return pin


def reported_version(output: str, pinned: str) -> str:
    """
    Args:
        output: What `<tool> --version` printed.
        pinned: The pinned version, or an empty string without a pin.

    Returns:
        The pinned version when the output names it as a whole version,
        else the first version-shaped token, else NO_VERSION.
    """
    if pinned and re.search(rf"(?<![\d.]){re.escape(pinned)}(?!\.?\d)", output):
        return pinned
    found = VERSION_SHAPE.search(output)
    if found is None:
        return NO_VERSION
    return found.group(0)


def probe(name: str, timeout: float, context: Context) -> tuple:
    """
    Args:
        name: Executable name.
        timeout: Seconds the version call may take.
        context: The running diagnosis.

    Returns:
        The resolved executable and what `--version` printed.

    Raises:
        QualityError: The tool is missing, fails or times out.
    """
    found = shutil.which(name, path=context.path_value)
    if found is None:
        raise QualityError("missing tool")
    env = tool_environment(context.path_value, context.scratch, None)
    result = run([found, "--version"], str(context.scratch), env, timeout)
    if result.code != 0:
        raise QualityError(f"`{name} --version` exited {result.code}")
    return found, (result.stdout + result.stderr).decode("utf-8", errors="replace")


def tool_line(name: str, timeout: float, context: Context) -> str:
    pin = pin_of(name, context)
    try:
        found, output = probe(name, timeout, context)
    except QualityError as error:
        context.gaps.append(f"{name}: {error}")
        return f"{name}: {error}"
    if pin is None:
        return f"{name} {reported_version(output, '')} {found}"
    version = reported_version(output, pin["version"])
    if version != pin["version"]:
        context.gaps.append(f"{name}: pinned {pin['version']}, but `{name} --version` reports {version}")
    if os.path.realpath(found) != os.path.realpath(pin["path"]):
        context.gaps.append(f"{name}: resolves to {found}, not to the pinned {pin['path']}")
    return f"{name} {version} {found}"


def database_line(option: str | None, environ: dict, data: RuleData, gaps: list) -> str:
    try:
        root = db.location(option, environ)
        bundle = db.open_bundle(root, data.limit("db_max_age_days"), datetime.now(timezone.utc))
    except QualityError as error:
        gaps.append(f"vulnerability database: {error}")
        return "vulnerability database: unusable"
    bundle.handle.close()
    return bundle.note()


def diagnose(rules: str | None, option: str | None, environ: dict, pins_path: Path) -> tuple:
    """
    Args:
        rules: The --rules value, or None for the packaged rule data.
        option: The --db value, or None for the default bundle location.
        environ: The caller's environment.
        pins_path: The pin manifest to compare against.

    Returns:
        The report lines and the gap lines: git and every tool of tools.yml
        with the version it reports and where it resolves, then the
        database state.
    """
    data = load(locate(rules))
    gaps = []
    pins = read_pins(pins_path, gaps)
    try:
        path_value = validated_path(environ)
    except QualityError as error:
        gaps.append(str(error))
        path_value = ""
    timeouts = {GIT: data.limit("git_timeout")}
    timeouts.update({name: data.tool(name)["timeout"] for name in data.tools})
    lines = [f"quality {__version__}"]
    scratch = Path(tempfile.mkdtemp(prefix="quality-")).resolve()
    try:
        context = Context(pins, path_value, scratch, gaps)
        lines += [tool_line(name, timeouts[name], context) for name in sorted(timeouts)]
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    lines.append(database_line(option, environ, data, gaps))
    return lines, gaps


def doctor(rules: str | None, option: str | None) -> int:
    """
    Args:
        rules: The --rules value, or None for the packaged rule data.
        option: The --db value, or None for the default bundle location.

    Returns:
        0 when git and every tool resolve to their pinned versions and the
        database opens, 2 naming each gap otherwise.
    """
    lines, gaps = diagnose(rules, option, dict(os.environ), PINS)
    print("\n".join(printable(line) for line in lines))
    for gap in gaps:
        print(f"quality: gap: {printable(gap)}", file=sys.stderr)
    return 2 if gaps else 0
