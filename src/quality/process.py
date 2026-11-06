import os
import signal
import subprocess
from dataclasses import dataclass

from quality import QualityError


@dataclass(frozen=True, repr=False)
class Completed:
    code: int
    stdout: bytes
    stderr: bytes


def kill_group(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        return


def abandon(proc: subprocess.Popen) -> None:
    kill_group(proc)
    # Exception: an escaped grandchild may hold the pipes open, so closing them
    # replaces a second communicate() that could block past the timeout.
    for stream in (proc.stdin, proc.stdout, proc.stderr):
        if stream is not None:
            stream.close()
    proc.wait()


def run(argv: list, cwd: str, env: dict, timeout: float, stdin: bytes | None = None) -> Completed:
    """
    Args:
        argv: Program and arguments, never passed through a shell.
        cwd: Working directory.
        env: Complete environment.
        timeout: Seconds before the whole process group is killed.
        stdin: Bytes fed to the process, or None for an empty stdin.

    Returns:
        The exit code and both captured streams.

    Raises:
        QualityError: The process could not start, timed out or died from a signal.
    """
    name = os.path.basename(argv[0])
    stdin_mode = subprocess.DEVNULL if stdin is None else subprocess.PIPE
    try:
        proc = subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            stdin=stdin_mode,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as error:
        raise QualityError(f"{name} could not start: {error.strerror}") from None
    try:
        stdout, stderr = proc.communicate(stdin, timeout=timeout)
    except subprocess.TimeoutExpired:
        abandon(proc)
        raise QualityError(f"{name} exceeded its timeout of {timeout} s and was killed") from None
    if proc.returncode < 0:
        raise QualityError(f"{name} was killed by signal {-proc.returncode}")
    return Completed(proc.returncode, stdout, stderr)
