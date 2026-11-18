import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from quality import QualityError
from quality.db import open_bundle
from tests.integration.repository.support import VULNERABLE, findings_of
from tests.integration.support import RULES, TEST_DB, VULNERABLE_PIN, git_env, rule_for, rules_with_enforcers

BINARY_VARIABLE = "QUALITY_E2E_BINARY"
IMAGE_VARIABLE = "QUALITY_E2E_IMAGE"
RUNTIME_VARIABLE = "QUALITY_E2E_RUNTIME"
REPOSITORIES = {"skills": "QUALITY_E2E_SKILLS", "package-manager": "QUALITY_E2E_PACKAGE_MANAGER"}
MODES = ("staged", "base", "all")
DEEP_MODES = ("base", "all")
PROBE = "quality_e2e_probe.py"
PROBE_TEXT = "import os\n"
LOADED = re.compile(r"^Loaded image(?: ID)?: (\S+)$", re.MULTILINE)
CHECK_SECONDS = 900
STEP_USER = "65534"
UMASK = 0o022


def built(variable: str) -> str:
    if variable not in os.environ:
        pytest.skip(f"{variable} names no output of the flake: make test-e2e builds packages.default and packages.image and sets it")
    path = os.environ[variable]
    assert Path(path).exists(), f"{variable} names {path}, which does not exist"
    return path


@pytest.fixture(scope="module")
def binary():
    return built(BINARY_VARIABLE)


@pytest.fixture(scope="module")
def image():
    archive = built(IMAGE_VARIABLE)
    if shutil.which("docker") is None:
        pytest.fail("docker is not on PATH, so the image cannot run")
    if subprocess.run(["docker", "info"], capture_output=True, check=False).returncode != 0:
        pytest.fail("the docker daemon does not answer, so the image cannot run")
    result = subprocess.run(["docker", "load", "--input", archive], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    loaded = LOADED.search(result.stdout)
    assert loaded, f"docker load named no image: {result.stdout}"
    return loaded.group(1)


@pytest.fixture(scope="module")
def runtime():
    if not os.environ.get(RUNTIME_VARIABLE):
        pytest.fail(f"{RUNTIME_VARIABLE} is required: the docker runtime the image runs under, core's SANDBOX_RUNTIME on a sandbox host")
    return os.environ[RUNTIME_VARIABLE]


@pytest.fixture(scope="module")
def bundle():
    limit = yaml.safe_load((RULES / "limits.yml").read_text(encoding="utf-8"))["db_max_age_days"]
    try:
        opened = open_bundle(TEST_DB, limit, datetime.now(timezone.utc))
    except QualityError as error:
        pytest.fail(f"needs the shared test bundle, which make test-integration fetches: {error}")
    opened.handle.close()
    return opened


def source(name: str) -> str:
    variable = REPOSITORIES[name]
    if variable not in os.environ:
        pytest.fail(f"{variable} is required: path or URL of the {name} repository that make test-e2e clones")
    return os.environ[variable]


def git(cwd: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=cwd, env=git_env(), capture_output=True, text=True, umask=UMASK, check=False)
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def prepared(name: str, mode: str, directory: Path) -> tuple:
    """
    Args:
        name: Key of REPOSITORIES.
        mode: staged, base or all.
        directory: Empty directory for the clone.

    Returns:
        (clone, the mode's command line flags), the probe staged for --staged and committed otherwise;
        the clone is shallow except for --base, which needs the merge base.
    """
    directory.mkdir()
    clone = directory / name
    depth = () if mode == "base" else ("--depth", "1")
    git(directory, "clone", "--quiet", "--no-local", *depth, "--", source(name), str(clone))
    base = git(clone, "rev-parse", "HEAD")
    (clone / PROBE).write_text(PROBE_TEXT, encoding="utf-8")
    git(clone, "add", "--", PROBE)
    if mode != "staged":
        git(clone, "commit", "--quiet", "--no-verify", "--message", "quality e2e probe")
    flags = {"staged": ("--staged",), "base": ("--base", base), "all": ("--all",)}
    return clone, flags[mode]


def host_quality(binary: str, cwd: Path, *args: str) -> subprocess.CompletedProcess:
    """
    Args:
        binary: The host binary of the flake.
        cwd: Directory quality runs in; its sibling home becomes HOME, cache and TMPDIR.
        args: Arguments of quality.

    Returns:
        The finished process, its output as text.
    """
    home = cwd.parent / "home"
    home.mkdir()
    env = {"HOME": str(home), "XDG_CACHE_HOME": str(home / "cache"), "TMPDIR": str(home)}
    return subprocess.run([binary, *args], cwd=cwd, env=env, capture_output=True, text=True, timeout=CHECK_SECONDS, check=False)


def image_quality(image: str, runtime: str, mounts: list, *args: str) -> subprocess.CompletedProcess:
    """
    Args:
        image: The loaded image of the flake.
        runtime: Docker runtime the container runs under.
        mounts: docker run volume options.
        args: Arguments of the image's quality entrypoint.

    Returns:
        The finished docker run, its output as text.
    """
    sandbox = ["--rm", "--network", "none", "--read-only", "--tmpfs", "/tmp", "--user", STEP_USER, f"--runtime={runtime}"]  # nocheck: security.temp-path -- the image's own /tmp as a fresh tmpfs, the read-only root has no other writable place
    argv = ["docker", "run", *sandbox, *mounts, image, *args]
    return subprocess.run(argv, capture_output=True, text=True, timeout=CHECK_SECONDS, check=False)


def host_run(binary: str, clone: Path, flags: tuple, database: Path) -> subprocess.CompletedProcess:
    return host_quality(binary, clone, "check", *flags, "--json", "--db", str(database))


def image_run(image: str, runtime: str, clone: Path, flags: tuple, database: Path) -> subprocess.CompletedProcess:
    mounts = ["-v", f"{clone}:/src:ro", "-v", f"{database}:/db:ro"]
    return image_quality(image, runtime, mounts, "check", *flags, "--json", "--db", "/db")


def outcome(result: subprocess.CompletedProcess, side: str) -> dict:
    assert result.returncode in (0, 1, 2), f"{side}: exit {result.returncode}: {result.stderr}"
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        raise AssertionError(f"{side}: exit {result.returncode} without a JSON report: {result.stderr}") from None


@pytest.fixture(scope="module")
def sides(binary, runtime, image, bundle):
    return binary, image, bundle, runtime


def test_doctor_host_and_image_agree(tmp_path, sides):
    binary, image, bundle, runtime = sides
    work = tmp_path / "work"
    work.mkdir()
    host = host_quality(binary, work, "doctor", "--db", str(bundle.root))
    contained = image_quality(image, runtime, ["-v", f"{bundle.root}:/db:ro"], "doctor", "--db", "/db")
    assert host.returncode == 0, host.stderr
    assert (contained.returncode, contained.stdout, contained.stderr) == (host.returncode, host.stdout, host.stderr)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("name", sorted(REPOSITORIES))
def test_host_and_image_agree(tmp_path, sides, name, mode):
    binary, image, bundle, runtime = sides
    clone, flags = prepared(name, mode, tmp_path / "work")
    host = host_run(binary, clone, flags, bundle.root)
    contained = image_run(image, runtime, clone, flags, bundle.root)
    host_report, image_report = outcome(host, "host"), outcome(contained, "image")
    assert image_report["findings"] == host_report["findings"]
    assert image_report == host_report
    assert contained.returncode == host.returncode
    probe_rule = rule_for("F401")
    assert (PROBE, probe_rule) in {(item["path"], item["rule"]) for item in host_report["findings"]}
    if mode in DEEP_MODES:
        assert bundle.note() in host_report["notes"]


def commit_file(repository: Path, name: str, text: str) -> None:
    (repository / name).write_text(text, encoding="utf-8")
    git(repository, "add", "--", name)
    git(repository, "commit", "--quiet", "--no-verify", "--message", name)


def vulnerable_repository(directory: Path) -> tuple:
    """
    Args:
        directory: Path for a new repository.

    Returns:
        (the repository, the commit before the one that adds a vulnerable requirements.txt).
    """
    directory.mkdir()
    git(directory, "init", "--quiet")
    commit_file(directory, "seed.py", "x = 1\n")
    base = git(directory, "rev-parse", "HEAD")
    commit_file(directory, "requirements.txt", VULNERABLE_PIN)
    return directory, base


@pytest.mark.parametrize(
    ("enforcer", "tool", "line"),
    [("manifest", "trivy", 1), ("lockfile", "osv-scanner", None)],
    ids=["trivy", "osv-scanner"],
)
def test_vuln_offline_image(tmp_path, sides, enforcer, tool, line):
    _binary, image, bundle, runtime = sides
    repository, base = vulnerable_repository(tmp_path / "repository")
    rules = rules_with_enforcers(tmp_path / "rules", VULNERABLE, {enforcer})
    mounts = ["-v", f"{repository}:/src:ro", "-v", f"{bundle.root}:/db:ro", "-v", f"{rules}:/rules:ro"]
    result = image_quality(image, runtime, mounts, "check", "--base", base, "--json", "--verbose", "--db", "/db", "--rules", "/rules")
    assert result.returncode == 1, result.stderr
    assert findings_of(result, VULNERABLE) == [("requirements.txt", line)]
    other = {"trivy": "osv-scanner", "osv-scanner": "trivy"}[tool]
    assert f"tool {tool}:" in result.stderr and f"tool {other}:" not in result.stderr
