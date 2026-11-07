import csv
import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

from quality import QualityError, printable
from quality.adapters import actionlint, lizard, rg, ruff, shellcheck
from quality.adapters.base import Bound
from quality.adapters.builtin import run_builtin
from quality.process import run
from quality.ruledata import BUILTIN, RuleData, require

REGISTRY = {
    "actionlint": actionlint,
    "lizard": lizard,
    "rg": rg,
    "ruff": ruff,
    "shellcheck": shellcheck,
}
PARSE_FAILURES = (ValueError, LookupError, TypeError, csv.Error)


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
                if path_kinds & binding.kinds and not binding.rule.excludes(path)
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
        hits = []
        commands = REGISTRY[tool].commands(bound, self.data.tool(tool), self.runtime.empty_file)
        for command in commands:
            for files in chunked(command.files, self.data.limit("argv_max_bytes")):
                argv = [binary, *command.prefix, *files]
                hits += self.run_chunk(tool, argv, command, snapshot)
        return hits

    def run_chunk(self, tool: str, argv: list, command, snapshot) -> list:
        settings = self.data.tool(tool)
        result = run(
            argv,
            str(snapshot.root),
            self.runtime.env,
            require(settings, "timeout", f"tools.yml {tool}"),
        )
        files = " ".join(argv[1 + len(command.prefix) :])
        self.runtime.log(f"tool {tool}: exit {result.code}, files: {files}")
        check_result(tool, result, settings)
        try:
            return REGISTRY[tool].parse(result.stdout, command, snapshot)
        except PARSE_FAILURES:
            raise QualityError(f"{tool} produced output its adapter does not document") from None


def check_result(tool: str, result, settings: dict) -> None:
    documented = require(settings, "exit_codes", f"tools.yml {tool}")
    if result.code not in documented:
        raise QualityError(f"{tool} exited with undocumented code {result.code}")
    if settings.get("stderr_fails") and result.stderr:
        raise QualityError(f"{tool} reported an error while exiting {result.code}")
