import os
from pathlib import Path

from quality import QualityError, db


def validated_path(environ: dict) -> str:
    """
    Args:
        environ: The caller's environment.

    Returns:
        PATH with absolute entries only, so it never resolves a tool relative to the target.

    Raises:
        QualityError: PATH is not set.
    """
    raw = environ.get("PATH")
    if raw is None:
        raise QualityError("environment is missing key 'PATH'")
    return os.pathsep.join(entry for entry in raw.split(os.pathsep) if os.path.isabs(entry))


def tool_environment(path_value: str, home: Path, bundle: db.Bundle | None) -> dict:
    """
    Args:
        path_value: Validated PATH.
        home: Scratch directory every tool gets as HOME and cache.
        bundle: Vulnerability database of the deep tier, or None.

    Returns:
        The only environment tools see: Semgrep without metrics and version
        check, osv-scanner on the bundle, no proxy, so no tool reaches the network.
    """
    env = {
        "PATH": path_value,
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home),
        "XDG_CACHE_HOME": str(home),
        "LC_ALL": "C.UTF-8",
        "PYTHONSAFEPATH": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "RUFF_NO_CACHE": "true",
        "SEMGREP_ENABLE_VERSION_CHECK": "0",
        "SEMGREP_SEND_METRICS": "off",
        "EIO_BACKEND": "posix",
    }
    if bundle is not None:
        env["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"] = str(bundle.osv_cache())
    return env


def enclosing_roots(cwd: str) -> list:
    """
    Args:
        cwd: Directory the check runs in.

    Returns:
        That directory and the nearest ancestor holding `.git`, found without
        git, because git itself must be vetted before it runs.
    """
    start = Path(cwd).resolve()
    marked = [path for path in (start, *start.parents) if (path / ".git").exists()]
    return [start, *marked[:1]]
