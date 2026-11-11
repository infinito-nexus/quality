import csv
import os
import shutil
import sys
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path

from quality import QualityError, printable
from quality.adapters import (
    actionlint,
    gitleaks,
    hadolint,
    lizard,
    rg,
    ruff,
    shellcheck,
)
from quality.adapters.base import Bound
from quality.adapters.builtin import run_builtin
from quality.process import run
from quality.ruledata import BUILTIN, RuleData, require

REGISTRY = {
    "actionlint": actionlint,
    "gitleaks": gitleaks,
    "hadolint": hadolint,
    "lizard": lizard,
    "rg": rg,
    "ruff": ruff,
    "shellcheck": shellcheck,
}
PARSE_FAILURES = (ValueError, LookupError, TypeError, csv.Error)


@dataclass(frozen=True)
class Invocation:
    argv: list
    cwd: Path


def refuse_inside(found: str, tool: str, roots: list) -> None:
    """
    Args:
        found: Executable as shutil.which returned it.
        tool: Name for the error.
        roots: Directories of the target the executable must not live in.

    Raises:
        QualityError: The executable or its symlink target lies inside a root.
    """
    for candidate in (Path(found).absolute(), Path(found).resolve()):
        if any(candidate.is_relative_to(root) for root in roots):
            raise QualityError(f"tool {tool} resolves inside the target repository")


@dataclass(frozen=True, eq=False)
class Runtime:
    path_value: str
    env: dict
    empty_file: Path
    repo_root: Path
    verbose: bool

    def resolve(self, tool: str) -> str:
        """
        Args:
            tool: Tool name from tools.yml.

        Returns:
            Absolute path of the executable.

        Raises:
            QualityError: The tool is missing or lives inside the target.
        """
        found = shutil.which(tool, path=self.path_value)
        if found is None:
            raise QualityError(f"missing tool: {tool}")
        refuse_inside(found, tool, [self.repo_root])
        return found

    def log(self, text: str) -> None:
        if self.verbose:
            print(f"quality: {printable(text)}", file=sys.stderr)


def chunked(files: list, budget: int) -> list:
    """
    Args:
        files: Paths for one tool.
        budget: Bytes one command line may hold for paths.

    Returns:
        Lists of paths in the original order.
    """
    chunks = []
    current = []
    used = 0
    for path in files:
        size = len(os.fsencode(path)) + 1
        if current and used + size > budget:
            chunks.append(current)
            current = []
            used = 0
        current.append(path)
        used += size
    if current:
        chunks.append(current)
    return chunks


def bind_files(bindings: list, kinds: dict, predicate) -> list:
    bound = []
    for binding in bindings:
        if predicate(binding.rule):
            files = [
                path
                for path, path_kinds in kinds.items()
                if binding.binds(path_kinds) and not binding.rule.excludes(path)
            ]
            if files:
                bound.append(Bound(binding, files))
    return bound


class Collector:
    def __init__(self, data: RuleData, runtime: Runtime):
        self.data = data
        self.runtime = runtime

    def collect(self, snapshot, paths: list, predicate) -> list:
        """
        Args:
            snapshot: Snapshot holding the files.
            paths: Files to check.
            predicate: Selects the rules of this run.

        Returns:
            All findings, unfiltered.
        """
        kinds = {path: snapshot.kinds_of(path) for path in paths}
        hits = []
        for tool, bindings in self.data.bindings().items():
            bound = bind_files(bindings, kinds, predicate)
            if bound:
                hits += self.run_tool(tool, bound, snapshot)
        return hits

    def run_tool(self, tool: str, bound: list, snapshot) -> list:
        if tool == BUILTIN:
            return [hit for item in bound for hit in run_builtin(item, snapshot)]
        if tool not in REGISTRY:
            raise QualityError(f"tool {tool} is allow-listed without an adapter")
        binary = self.runtime.resolve(tool)
        settings = self.data.tool(tool)
        hits = []
        commands = REGISTRY[tool].commands(bound, settings, self.config_file(tool, settings))
        for command in commands:
            for files in chunked(command.files, self.data.limit("argv_max_bytes")):
                hits += self.run_chunk(tool, binary, replace(command, files=files), snapshot)
        return hits

    def config_file(self, tool: str, settings: dict) -> Path:
        """
        Args:
            tool: Tool name from tools.yml.
            settings: Its entry there.

        Returns:
            The file the tool reads instead of discovering one in the target:
            its `config` text from tools.yml, or the empty file without one.
        """
        text = settings.get("config")
        if text is None:
            return self.runtime.empty_file
        path = self.runtime.empty_file.with_name(f"{tool}.config")
        path.write_text(text, encoding="utf-8")
        return path

    def run_chunk(self, tool: str, binary: str, command, snapshot) -> list:
        """
        Args:
            tool: Tool name from tools.yml.
            binary: Its resolved executable.
            command: One chunk of the adapter's command.
            snapshot: Snapshot holding the files.

        Returns:
            The chunk's findings. An adapter with `operands` stages the files
            in a work directory, removed afterwards, and the tool runs there.
        """
        adapter = REGISTRY[tool]
        if not hasattr(adapter, "operands"):
            argv = [binary, *command.prefix, *command.files]
            return self.execute(tool, Invocation(argv, snapshot.root), command, snapshot)
        with tempfile.TemporaryDirectory(dir=snapshot.root.parent) as work:
            operands = adapter.operands(command, snapshot, Path(work))
            argv = [binary, *command.prefix, *operands]
            return self.execute(tool, Invocation(argv, Path(work)), command, snapshot)

    def execute(self, tool: str, invocation, command, snapshot) -> list:
        """
        Args:
            tool: Tool name from tools.yml.
            invocation: Arguments and working directory.
            command: The chunk the arguments carry.
            snapshot: Snapshot holding the files.

        Returns:
            The findings. An adapter with `unread` also names the files the
            tool skipped, which the snapshot then reports as unchecked. An
            adapter with `rescan` names files its first run could not read,
            which run once more with `rescan` set.
        """
        settings = self.data.tool(tool)
        result = run(
            invocation.argv,
            str(invocation.cwd),
            self.runtime.env,
            require(settings, "timeout", f"tools.yml {tool}"),
        )
        self.runtime.log(f"tool {tool}: exit {result.code}, files: {' '.join(command.files)}")
        check_result(tool, result, settings)
        adapter = REGISTRY[tool]
        command = replace(command, log=result.stderr)
        try:
            hits = adapter.parse(result.stdout, command, snapshot)
        except PARSE_FAILURES:
            raise QualityError(f"{tool} produced output its adapter does not document") from None
        if hasattr(adapter, "unread"):
            snapshot.unread.update(adapter.unread(command, snapshot))
        first = hasattr(adapter, "rescan") and not command.rescan
        again = adapter.rescan(command, snapshot) if first else []
        if again:
            follow = replace(command, files=again, log=b"", rescan=True)
            hits += self.run_chunk(tool, invocation.argv[0], follow, snapshot)
        return hits


def check_result(tool: str, result, settings: dict) -> None:
    documented = require(settings, "exit_codes", f"tools.yml {tool}")
    if result.code not in documented:
        raise QualityError(f"{tool} exited with undocumented code {result.code}")
    if settings.get("stderr_fails") and result.stderr:
        raise QualityError(f"{tool} reported an error while exiting {result.code}")
