#!/usr/bin/env kvb-quality-python
"""
Args:
    --repo: A directory inside the git work tree to review.
    --base REF | --staged | --range A..B | --all: exactly one mode, as
        `quality check` takes it; --range reviews the commits from the merge
        base of A and B up to B.
    --path: A file relative to the repository root; repeatable; limits every
        lens to those files.
    --db: The vulnerability database; the deep tier runs only with it.
    --measure: Run the performance lens on the command given after `--`.
    --json: Required; the output is JSON only.

Exit codes:
    0 no finding, 1 findings, 2 usage or tool error.
"""

import json
import sys

from reviewer import document, options, qualitylens, target, tools

from quality import QualityError, printable
from quality.report import EXIT_ERROR
from quality.ruledata import load, locate


def review(request: options.Request) -> list:
    """
    Args:
        request: The parsed command line.

    Returns:
        The result of every lens.

    Raises:
        QualityError: The rule data is unreadable, --repo is no work tree,
            or a ref resolves to no commit.
    """
    rules = locate(None)
    data = load(rules)
    change = target.resolve(request, data.limit("git_timeout"))
    return [
        *qualitylens.quality_results(request, change, data, rules),
        tools.security_result(request, change),
        tools.performance_result(request, change),
        *document.judgements(),
    ]


def main(argv: list) -> int:
    """
    Args:
        argv: Arguments without the program name.

    Returns:
        The exit code; usage errors exit 2 while parsing.
    """
    request = options.parse(argv)
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", errors="backslashreplace")
    try:
        results = review(request)
    except QualityError as error:
        print(f"review: error: {printable(str(error))}", file=sys.stderr)
        return EXIT_ERROR
    except Exception as error:
        print(f"review: internal error: {type(error).__name__}", file=sys.stderr)
        return EXIT_ERROR
    for result in results:
        if result.error is not None:
            print(f"review: {result.lens}: {printable(result.error)}", file=sys.stderr)
    print(json.dumps(document.assemble(results), indent=2))
    return document.exit_code(results)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
