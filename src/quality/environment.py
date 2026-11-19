import os
import shutil
from pathlib import Path

from quality import QualityError, db
from quality.adapters import refuse_inside
from quality.repo import Repo, hardened_env


def validated_path(environ: dict) -> str:
    """
    Args:
        environ: The caller's environment.

    Returns:
        PATH with absolute entries only.

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
        check, osv-scanner on the bundle, no proxy.
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
        git.
    """
    start = Path(cwd).resolve()
    marked = [path for path in (start, *start.parents) if (path / ".git").exists()]
    return [start, *marked[:1]]


def trusted_worktree(cwd: str) -> Path | None:
    """
    Args:
        cwd: Directory the check runs in.

    Returns:
        That directory when it holds `.git` itself, as git's one
        `safe.directory`; None otherwise and for a directory named `*`.
    """
    start = Path(cwd).resolve()
    if start.name == "*" or not (start / ".git").exists():
        return None
    return start


def open_repository(cwd: str, timeout: float, path_value: str, inherited: dict) -> Repo:
    """
    Args:
        cwd: Directory inside the work tree.
        timeout: Seconds each git command may take.
        path_value: Validated PATH git is resolved from.
        inherited: Environment whose git location variables pass to git.

    Returns:
        The repository, read by a git that lives outside it.

    Raises:
        QualityError: git is missing or resolves inside the target, or cwd is
            no git work tree.
    """
    git = shutil.which("git", path=path_value)
    if git is None:
        raise QualityError("missing tool: git")
    refuse_inside(git, "git", enclosing_roots(cwd))
    env = hardened_env(path_value, inherited, trusted_worktree(cwd))
    repo = Repo.open(cwd, env, timeout, git)
    refuse_inside(git, "git", [Path(repo.root).resolve()])
    return repo
