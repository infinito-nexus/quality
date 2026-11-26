#!/usr/bin/env kvb-quality-python
"""
Args:
    --fix: fix confidence in percent, 0 to 100.
    --break: break risk in percent, 0 to 100.
    --efficiency: tokens in percent above 0, from measure.py of kvb-quality-performance
        or the skill-token count; `-` when not measured or not relevant, `new` when
        the change has no base. Both count as 100 in the score.
    --speed: velocity in percent above 0, from measure.py of kvb-quality-performance;
        `-` or `new` as for --efficiency.
    --security: security in percent, 0 to 100, from security.py of kvb-quality-security;
        `~<n>` for a value from a review by hand.
    --critical: count of critical security findings.
    --legal: legal in percent, 0 to 100, `legal` of `quality check --json`;
        `~<n>` when it includes review findings or unchecked dependencies.
    --legal-blockers: count of legal blockers, `legal_blockers` of `quality check --json`.
    --architecture: architecture in percent, 0 to 100, `architecture` of
        `quality check --json`.
    --note <metric>=<text>: a note on one metric key of ../labels.json, at most one
        per metric, one line of text; repeatable.
    --message-block: print the block and append one row to the score journal of
        journal.py; a failed append prints one stderr line and keeps the exit code.
    --commit-table <repo>: print `📁 Worktree:`, `🌿 Branch:` and `📊 Diff stat:` of
        that repository's staged change above the block.
    --commit <sha>: with --commit-table, the diff stat of that commit instead of
        the staged one and a `🔖 Commit:` line; appends one row with the full sha
        and the commit time to the score journal unless it holds one for that
        remote and sha, so the hub counts the commit once.
    --value <n:n|?>: a `💰 Value:` line after security, the cost:value quotient of
        the skill-token count, `?` when unknown. It changes neither score nor gate.

Output:
    Labels and emojis: from ../labels.json.
    The block: `Metrics:`, one `<emoji> <Label>: <value>` line per metric, legal
    and architecture before the score, a note's marker (¹, ², ...) after its
    value; with notes a `---` line and one `<marker> <text>` line per note; then
    a blank line and `🚦 Gate: <verdict>`.
    Values: `<n> %`, `~<n> %` for an estimate, `–` for `-`, `new` for `new`.
    Score: fix * (100 - break) / 100 * 100 / tokens * 100 / velocity * security / 100
        * legal / 100 * architecture / 100, capped to 0..100, rounded half up.
    Verdict: `✅ <rule met>`, `⚠️ ask: <causes>` or `⛔ do not commit: <causes>`.

Exit codes:
    0 gate passed, 1 fix under 90 or break over 5, 2 usage error, a malformed
    labels.json or a --commit-table repository git cannot read, one stderr line
    and nothing on stdout (4 still wins with a critical finding or a legal
    blocker), 3 tokens or velocity over 100 or new, or security, legal or
    architecture under 100: ask the operator before the commit, 4 a critical
    security finding or a legal blocker: do not commit.
"""

from __future__ import annotations

import argparse
import math
import re
import sys
import time
from pathlib import Path
from typing import NamedTuple

sys.path.insert(0, str(Path(__file__).resolve().parent))

from journal import (
    LABEL_ERRORS,
    LABELS,
    append,
    entry,
    git,
    git_read,
    journal_path,
    known,
    load_labels,
    origin,
)

DASH = "-"
NEW = "new"
UNKNOWN = "?"
FIX_MIN = 90
BREAK_MAX = 5
COST_MAX = 100
SAFE = 100
ESTIMATE = "~"
HEAD = "Metrics:"
RULE = "---"
METRICS = ("fix", "break", "tokens", "velocity", "security", "score")
SCORED_EXTRAS = ("legal", "architecture")
EXTRAS = ("value", "gate", *SCORED_EXTRAS)
NOTED = (*METRICS, *SCORED_EXTRAS)
SUPERSCRIPT = str.maketrans("0123456789", "⁰¹²³⁴⁵⁶⁷⁸⁹")
WORKTREE = "📁 Worktree"
BRANCH = "🌿 Branch"
DIFFSTAT = "📊 Diff stat"
COMMIT = "🔖 Commit"
QUOTIENT = re.compile(r"\d+(?:\.\d+)?:\d+(?:\.\d+)?")
SHORTSTAT = re.compile(
    r"(\d+) files? changed(?:, (\d+) insertions?\(\+\))?(?:, (\d+) deletions?\(-\))?"
)


class Scored(NamedTuple):
    """Attributes:
        args: the parsed arguments.
        total: score() of them.
        measured: per key of the block the value as it shows.
        metrics: the metrics of labels.json in block order.
        extras: the extras of labels.json.
        verdict: gate() of them: emoji, verdict text and exit code.
    """

    args: argparse.Namespace
    total: int
    measured: dict
    metrics: dict
    extras: dict
    verdict: tuple[str, str, int]


def percent(text: str) -> float:
    """
    Args:
        text: a command-line value meant as a percentage.

    Returns:
        The value as a float within 0..100; argparse.ArgumentTypeError otherwise.
    """
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a number") from None
    if not 0 <= value <= 100:
        raise argparse.ArgumentTypeError(f"{text!r} is outside 0..100")
    return value


def cost(text: str) -> float | str:
    if text in (DASH, NEW):
        return text
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is neither a number, {DASH!r} nor {NEW!r}") from None
    if not math.isfinite(value) or value <= 0:
        raise argparse.ArgumentTypeError(f"{text!r} must be a positive number")
    return value


def estimate(text: str) -> tuple[float, str]:
    mark = ESTIMATE if text.startswith(ESTIMATE) else ""
    return percent(text.removeprefix(ESTIMATE)), mark


def worth(text: str) -> str:
    if text == UNKNOWN or QUOTIENT.fullmatch(text):
        return text
    raise argparse.ArgumentTypeError(f"{text!r} is neither n:n nor {UNKNOWN!r}")


def count(text: str) -> int:
    if not text.isdigit():
        raise argparse.ArgumentTypeError(f"{text!r} is not a count")
    return int(text)


def note(text: str) -> tuple[str, str]:
    key, sep, body = text.partition("=")
    if not sep or key not in NOTED or not body.strip() or not body.isprintable():
        raise argparse.ArgumentTypeError(f"{text!r} is not <metric>=<one line of text>, metric one of {', '.join(NOTED)}")
    return key, body.strip()


def number(value: float) -> str:
    return f"{value:g}"


def shown(value: float | str) -> str:
    if value == DASH:
        return "–"
    if value == NEW:
        return NEW
    return f"{number(value)} %"


def factor(value: float | str) -> float:
    return 100 / value if isinstance(value, float) else 1.0


def score(args: argparse.Namespace) -> int:
    raw = (
        args.fix * (100 - args.risk) / 100 * factor(args.efficiency) * factor(args.speed)
        * args.security[0] / 100 * args.legal[0] / 100 * args.architecture / 100
    )
    return math.floor(min(max(raw, 0.0), 100.0) + 0.5)


def over(name: str, value: float | str) -> str | None:
    if value == NEW:
        return f"{name} {NEW}"
    if isinstance(value, float) and value > COST_MAX:
        return f"{name} {number(value)} % > {COST_MAX}"
    return None


def below(name: str, value: float, mark: str) -> str | None:
    return f"{name} {mark}{number(value)} % < {SAFE}" if value < SAFE else None


def labels() -> tuple[dict, dict]:
    """
    Returns:
        (metrics, extras) of labels.json; ValueError when its metrics are not
        exactly METRICS, it lacks one of EXTRAS or an entry has no string emoji
        and label.
    """
    found = load_labels(LABELS)
    metrics, extras = found["metrics"], found["extras"]
    named = [*metrics.values(), *(extras[key] for key in EXTRAS)]
    if set(metrics) != set(METRICS) or not all(isinstance(item["emoji"], str) and isinstance(item["label"], str) for item in named):
        raise ValueError(f"needs a string emoji and label for {', '.join(METRICS)} and {', '.join(EXTRAS)}")
    return metrics, extras


def word(items: dict, key: str) -> str:
    return items[key]["label"].lower()


def counted(amount: int, noun: str) -> str:
    return f"{amount} {noun}{'' if amount == 1 else 's'}"


def blockers(args: argparse.Namespace, metrics: dict, extras: dict) -> list[str]:
    found = []
    if args.critical > 0:
        found.append(counted(args.critical, f"critical {word(metrics, 'security')} finding"))
    if args.legal_blockers > 0:
        found.append(counted(args.legal_blockers, f"{word(extras, 'legal')} blocker"))
    return found


def failures(args: argparse.Namespace, metrics: dict) -> list[str]:
    failed = []
    if args.fix < FIX_MIN:
        failed.append(f"{word(metrics, 'fix')} {number(args.fix)} % < {FIX_MIN}")
    if args.risk > BREAK_MAX:
        failed.append(f"{word(metrics, 'break')} {number(args.risk)} % > {BREAK_MAX}")
    return failed


def asks(args: argparse.Namespace, metrics: dict, extras: dict) -> list[str]:
    causes = (
        over(word(metrics, "tokens"), args.efficiency),
        over(word(metrics, "velocity"), args.speed),
        below(word(metrics, "security"), *args.security),
        below(word(extras, "legal"), *args.legal),
        below(word(extras, "architecture"), args.architecture, ""),
    )
    return [text for text in causes if text]


def gate(args: argparse.Namespace, metrics: dict, extras: dict) -> tuple[str, str, int]:
    stopped = blockers(args, metrics, extras)
    if stopped:
        return "⛔", f"do not commit: {', '.join(stopped)}", 4
    failed = failures(args, metrics)
    causes = [*failed, *asks(args, metrics, extras)]
    if causes:
        return "⚠️", f"ask: {', '.join(causes)}", 1 if failed else 3
    rule = f"{word(metrics, 'security')}, {word(extras, 'legal')} and {word(extras, 'architecture')} {SAFE} %"
    return "✅", f"{FIX_MIN}/{BREAK_MAX}, {word(metrics, 'tokens')} and {word(metrics, 'velocity')} <= {COST_MAX}, {rule}", 0


def diffstat(shortstat: str) -> str:
    match = SHORTSTAT.search(shortstat)
    files, added, removed = (int(group) if group else 0 for group in match.groups()) if match else (0, 0, 0)
    return f"{files} file{'' if files == 1 else 's'} +{added}/-{removed}"


def branch_name(repo: str) -> str:
    branch = git(repo, "branch", "--show-current")
    return branch if branch else f"detached at {git(repo, 'rev-parse', '--short', 'HEAD')}"


def commit_lines(repo: str, commit: str | None) -> list[str]:
    branch = branch_name(repo)
    if commit is None:
        lines = [f"{BRANCH}: {branch}", f"{DIFFSTAT}: {diffstat(git(repo, 'diff', '--cached', '--shortstat'))}"]
    else:
        stat = git(repo, "show", "--shortstat", "--format=", commit)
        lines = [f"{BRANCH}: {branch}", f"{DIFFSTAT}: {diffstat(stat)}", f"{COMMIT}: {git(repo, 'rev-parse', '--short', commit)}"]
    return [f"{WORKTREE}: {git(repo, 'rev-parse', '--show-toplevel')}", *lines]


def label(item: dict) -> str:
    return f"{item['emoji']} {item['label']}"


def order(scored: Scored) -> list[str]:
    keys = []
    for key in scored.metrics:
        keys.extend(name for name in SCORED_EXTRAS if scored.extras[name].get("before") == key)
        keys.append(key)
    keys.extend(name for name in SCORED_EXTRAS if name not in keys)
    if scored.args.value:
        keys.insert(keys.index("security") + 1, "value")
    return keys


def block(scored: Scored) -> str:
    notes = dict(scored.args.note)
    lines, footer = [HEAD], []
    for key in order(scored):
        item = scored.metrics.get(key) or scored.extras[key]
        line = f"{label(item)}: {scored.measured[key]}"
        if key in notes:
            mark = str(len(footer) + 1).translate(SUPERSCRIPT)
            line = f"{line} {mark}"
            footer.append(f"{mark} {notes[key]}")
        lines.append(line)
    if footer:
        lines.extend((RULE, *footer))
    emoji, verdict, _ = scored.verdict
    return "\n".join((*lines, "", f"{label(scored.extras['gate'])}: {emoji} {verdict}"))


def displayed(args: argparse.Namespace, total: int) -> dict:
    security, guess = args.security
    legal, legal_guess = args.legal
    return {
        "fix": f"{number(args.fix)} %", "break": f"{number(args.risk)} %", "tokens": shown(args.efficiency),
        "velocity": shown(args.speed), "security": f"{guess}{number(security)} %", "value": args.value,
        "legal": f"{legal_guess}{number(legal)} %", "architecture": f"{number(args.architecture)} %", "score": str(total),
    }


def parse() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Score a change and print its block.")
    parser.add_argument("--fix", type=percent, required=True)
    parser.add_argument("--break", dest="risk", type=percent, required=True)
    parser.add_argument("--efficiency", type=cost, required=True)
    parser.add_argument("--speed", type=cost, required=True)
    parser.add_argument("--security", type=estimate, required=True)
    parser.add_argument("--critical", type=count, required=True)
    parser.add_argument("--legal", type=estimate, required=True)
    parser.add_argument("--legal-blockers", type=count, required=True)
    parser.add_argument("--architecture", type=percent, required=True)
    parser.add_argument("--note", type=note, action="append", default=[])
    layout = parser.add_mutually_exclusive_group()
    layout.add_argument("--commit-table", metavar="REPO")
    layout.add_argument("--message-block", action="store_true")
    parser.add_argument("--commit", metavar="SHA")
    parser.add_argument("--value", type=worth)
    args = parser.parse_args()
    if args.commit and not args.commit_table:
        parser.error("--commit needs --commit-table")
    keys = [key for key, _ in args.note]
    if len(set(keys)) != len(keys):
        parser.error("--note: at most one note per metric")
    return args


def blocked(args: argparse.Namespace) -> bool:
    return args.critical > 0 or args.legal_blockers > 0


def commit_table(scored: Scored) -> int:
    args, code = scored.args, scored.verdict[2]
    try:
        lead = commit_lines(args.commit_table, args.commit)
    except LookupError as error:
        print(f"score: {error}", file=sys.stderr)
        return 4 if code == 4 else 2
    text = block(scored)
    print("\n".join((*lead, text)), flush=True)
    if args.commit:
        committed(args.commit_table, args.commit, values_of(args, scored.total), text)
    return code


def main() -> int:
    args = parse()
    total = score(args)
    try:
        metrics, extras = labels()
    except LABEL_ERRORS as error:
        print(f"score: labels {LABELS}: {error!r}", file=sys.stderr)
        return 4 if blocked(args) else 2
    scored = Scored(args, total, displayed(args, total), metrics, extras, gate(args, metrics, extras))
    if args.commit_table:
        return commit_table(scored)
    text = block(scored)
    print(text, flush=True)
    if args.message_block:
        journal(args, total, text)
    return scored.verdict[2]


def plain(value: float | str) -> float | int | None:
    if not isinstance(value, float):
        return None
    return int(value) if value.is_integer() else value


def values_of(args: argparse.Namespace, total: int) -> dict:
    return {
        "fix": plain(args.fix), "break": plain(args.risk), "tokens": plain(args.efficiency),
        "velocity": plain(args.speed), "security": plain(args.security[0]), "score": total,
    }


def journal(args: argparse.Namespace, total: int, text: str) -> None:
    try:
        path = journal_path()
    except OSError as error:
        print(f"score: journal: {error}", file=sys.stderr)
        return
    try:
        here = Path.cwd()
        branch = git_read(here, "branch", "--show-current") or None
        append(path, [entry(int(time.time()), origin(here), branch, None, (values_of(args, total), text))])
    except (OSError, ValueError) as error:
        print(f"score: journal {path}: {getattr(error, 'strerror', None) or error}", file=sys.stderr)


def committed(repo: str, commit: str, values: dict, text: str) -> None:
    """Args:
        repo: the --commit-table repository.
        commit: the --commit revision.
        values: values_of() the block.
        text: the block the commit carries.

    Returns:
        Appends one row with the full sha and the commit time unless the
        journal holds one for its remote and sha; a failure prints one
        stderr line.
    """
    path = journal_path()
    try:
        sha = git(repo, "rev-parse", "--verify", f"{commit}^{{commit}}")
        place = origin(Path(repo))
        if (place[0], sha) not in known(path):
            when = int(git(repo, "show", "-s", "--format=%ct", sha))
            branch = git_read(Path(repo), "branch", "--show-current") or None
            append(path, [entry(when, place, branch, sha, (values, text))])
    except (OSError, ValueError, LookupError) as error:
        print(f"score: journal {path}: {getattr(error, 'strerror', None) or error}", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
