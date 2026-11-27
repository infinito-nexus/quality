#!/usr/bin/env kvb-quality-python
"""
Args:
    prepare --repo DIR --out DIR --budget N --medusa FILE [--range A..B] [--profile NAME]:
        verifies the vendored upstream against lock.json, resolves the range
        (newest vX.Y.Z tag reachable from HEAD to HEAD by default), then
        prints the stored attestation of the range end's tree, writes a
        `skipped: docs-only` attestation, or writes the audit plan
        <out>/plan-<tree>.json with the MEDUSA seeds of the changed files.
        FILE is the `security.py --json` report of the range.
    attest --repo DIR --plan FILE --run DIR --invocations N --tokens N --minutes N:
        validates <run>/findings.json and <run>/coverage-ledger.json with the
        upstream validators, records every rejected MEDUSA seed as a
        `security.py accept` row and writes <out>/attestation-<tree>.json.

Output:
    The plan or attestation as JSON on stdout.

Exit codes:
    0 plan written, pass or skipped; 1 blocked; 2 usage, lock, range,
    budget or validation error.
"""

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

SKILL = Path(__file__).resolve().parents[1]
UPSTREAM = SKILL / "upstream"
LOCK = SKILL / "lock.json"
ACCEPT = SKILL.parent / "kvb-quality-security" / "scripts" / "security.py"
PROFILES = ("quick", "standard", "deep")
TAGS = "v[0-9]*.[0-9]*.[0-9]*"
DOCS = frozenset({".md", ".txt", ".rst", ".png", ".jpg", ".jpeg", ".gif", ".webp"})
VERDICTS = ("confirmed", "needs_validation", "rejected")
SEVERITIES = ("critical", "high", "medium", "low", "informational")
BLOCKING = frozenset({"critical", "high"})
SKIPPED = "skipped: docs-only"
SEED = "medusa:{rule}:{sha1}"
REASON_CHARS = 200


class Usage(Exception):
    pass


def git(root: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise Usage(f"git {' '.join(args)} exited {result.returncode}: {result.stderr.strip()}")
    return result.stdout


def verified_upstream() -> dict:
    """
    Returns:
        lock.json, once every vendored file matches its sha256 and the
        upstream directory holds no other file.
    """
    lock = json.loads(LOCK.read_text(encoding="utf-8"))
    digests = {item["name"]: item["sha256"] for item in lock["files"]}
    present = sorted(path.name for path in UPSTREAM.iterdir())
    if present != sorted(digests):
        raise Usage(f"{UPSTREAM} holds {present}, lock.json names {sorted(digests)}")
    for name, digest in digests.items():
        if hashlib.sha256((UPSTREAM / name).read_bytes()).hexdigest() != digest:
            raise Usage(f"{UPSTREAM / name} differs from lock.json")
    return lock


def toplevel(repo: str) -> Path:
    return Path(git(Path(repo), "rev-parse", "--show-toplevel").strip())


def output_dir(root: Path, out: str) -> Path:
    """
    Args:
        root: The target's work tree.
        out: The --out value.

    Returns:
        The created directory; a path inside the tree must be ignored by git.
    """
    folder = Path(out).resolve()
    if folder.is_relative_to(root):
        ignored = subprocess.run(["git", "check-ignore", "-q", "--", str(folder)], cwd=root, check=False)
        if ignored.returncode != 0:
            raise Usage(f"--out {folder} lies in the tracked tree: use /tmp or a git-ignored directory")
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def resolved_range(root: Path, option: str | None) -> tuple[str, str]:
    if option is None:
        described = subprocess.run(
            ["git", "describe", "--tags", "--abbrev=0", "--match", TAGS, "HEAD"],
            cwd=root, capture_output=True, text=True, check=False,
        )
        if described.returncode != 0:
            raise Usage("no vX.Y.Z tag is reachable from HEAD: pass --range <a>..<b>")
        start, end = described.stdout.strip(), "HEAD"
    else:
        start, separator, end = option.partition("..")
        if not separator or not start or not end:
            raise Usage(f"--range wants <a>..<b>, got {option!r}")
    for ref in (start, end):
        git(root, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")
    return start, end


def changed(root: Path, start: str, end: str) -> list[str]:
    listed = git(root, "diff", "--name-only", "--diff-filter=d", "-z", start, end)
    return sorted(name for name in listed.split("\0") if name)


def seeds(report: Path, files: list[str]) -> list[dict]:
    """
    Args:
        report: The `security.py --json` report of the range.
        files: The range's changed files.

    Returns:
        One candidate per MEDUSA finding in a changed file, with the
        fingerprint the audit must keep for it.
    """
    try:
        findings = json.loads(report.read_text(encoding="utf-8"))["findings"]
        kept = [item for item in findings if item["path"] in files]
        return [
            {
                "fingerprint": SEED.format(rule=item["rule"], sha1=item["sha1"]),
                **{key: item[key] for key in ("rule", "path", "line", "sha1", "severity")},
            }
            for item in kept
        ]
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise Usage(f"--medusa {report} is no security.py --json report ({type(error).__name__})") from None


def attestation(plan: dict, verdict: str, run: dict) -> dict:
    return {
        "tree": plan["tree"],
        "range": plan["range"],
        "upstream": plan["upstream"],
        "profile": plan["profile"],
        "budget": plan["budget"],
        **run,
        "verdict": verdict,
    }


def empty_run() -> dict:
    return {
        "invocations": 0,
        "verdicts": dict.fromkeys(VERDICTS, 0),
        "severities": dict.fromkeys(SEVERITIES, 0),
        "accepted": [],
        "tokens": 0,
        "minutes": 0,
    }


def emitted(document: dict) -> int:
    print(json.dumps(document, indent=2, sort_keys=True))
    return 1 if document["verdict"] == "blocked" else 0


def written(folder: Path, document: dict) -> int:
    (folder / f"attestation-{document['tree']}.json").write_text(json.dumps(document, indent=2, sort_keys=True), encoding="utf-8")
    return emitted(document)


def prepare(args: argparse.Namespace) -> int:
    lock = verified_upstream()
    root = toplevel(args.repo)
    folder = output_dir(root, args.out)
    start, end = resolved_range(root, args.range)
    tree = git(root, "rev-parse", f"{end}^{{tree}}").strip()
    stored = folder / f"attestation-{tree}.json"
    if stored.is_file():
        return emitted(json.loads(stored.read_text(encoding="utf-8")))
    files = changed(root, start, end)
    plan = {
        "tree": tree,
        "range": f"{start}..{end}",
        "upstream": lock["commit"],
        "profile": args.profile,
        "budget": args.budget,
        "out": str(folder),
        "files": files,
        "seeds": seeds(Path(args.medusa), files),
        "skill": str(UPSTREAM / "SKILL.md"),
    }
    if all(Path(name).suffix.lower() in DOCS for name in files):
        return written(folder, attestation(plan, SKIPPED, empty_run()))
    (folder / f"plan-{tree}.json").write_text(json.dumps(plan, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(plan, indent=2, sort_keys=True))
    return 0


def validated(run: Path, files: list[str]) -> list:
    """
    Args:
        run: The audit's output directory.
        files: The plan's changed files.

    Returns:
        The findings, once both upstream validators pass and the coverage
        ledger reviewed every changed file: the validators accept an empty
        ledger, which would attest an audit that read nothing.
    """
    node = shutil.which("node")
    if node is None:
        raise Usage("missing tool: node, which runs the upstream validators")
    for validator, name in (("validate-findings.cjs", "findings.json"), ("validate-coverage-ledger.cjs", "coverage-ledger.json")):
        result = subprocess.run([node, str(UPSTREAM / validator), str(run / name)], capture_output=True, text=True, check=False)
        if result.returncode != 0:
            raise Usage(f"{validator} refused {run / name}: {result.stderr.strip()[:REASON_CHARS]}")
    ledger = json.loads((run / "coverage-ledger.json").read_text(encoding="utf-8"))
    reviewed = {path for unit in ledger for path in unit["reviewed_paths"]}
    unread = [name for name in files if name not in reviewed]
    if unread:
        raise Usage(f"the coverage ledger reviewed none of {', '.join(unread[:5])}{' ...' if len(unread) > 5 else ''}")
    return json.loads((run / "findings.json").read_text(encoding="utf-8"))


def counted(findings: list) -> tuple[dict, dict]:
    verdicts = dict.fromkeys(VERDICTS, 0)
    severities = dict.fromkeys(SEVERITIES, 0)
    for item in findings:
        verdicts[item["verdict"]] += 1
        if item["verdict"] == "confirmed":
            severities[item["severity"]["overall_severity"]] += 1
    return verdicts, severities


def accepted(root: Path, plan: dict, findings: list) -> list[dict]:
    """
    Args:
        root: The target's work tree.
        plan: The audit plan holding the MEDUSA seeds.
        findings: The validated findings.

    Returns:
        The seeds a rejected verdict refuted, each recorded by
        `security.py accept` with the verdict's reason.
    """
    by_print = {seed["fingerprint"]: seed for seed in plan["seeds"]}
    rows = []
    for item in findings:
        seed = by_print.get(item["fingerprint"])
        if item["verdict"] != "rejected" or seed is None:
            continue
        reason = " ".join(item["reason"].split())[:REASON_CHARS]
        flags = ["--rule", seed["rule"], "--path", seed["path"], "--sha1", seed["sha1"], "--reason", f"audit: {reason}"]
        if seed["line"] is not None:
            flags += ["--line", str(seed["line"])]
        result = subprocess.run([sys.executable, str(ACCEPT), "accept", "--repo", str(root), *flags], capture_output=True, text=True, check=False)
        if result.returncode != 0:
            raise Usage(f"security.py accept refused {seed['fingerprint']}: {result.stderr.strip()[:REASON_CHARS]}")
        rows.append({key: seed[key] for key in ("rule", "path", "line", "sha1")})
    return rows


def attest(args: argparse.Namespace) -> int:
    verified_upstream()
    plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))
    if args.invocations > plan["budget"]:
        raise Usage(f"{args.invocations} agent invocations exceed the budget of {plan['budget']}")
    root = toplevel(args.repo)
    findings = validated(Path(args.run), plan["files"])
    verdicts, severities = counted(findings)
    rows = accepted(root, plan, findings)
    blocked = verdicts["needs_validation"] or any(severities[name] for name in BLOCKING)
    run = {
        "invocations": args.invocations,
        "verdicts": verdicts,
        "severities": severities,
        "accepted": rows,
        "tokens": args.tokens,
        "minutes": args.minutes,
    }
    return written(Path(plan["out"]), attestation(plan, "blocked" if blocked else "pass", run))


def count(text: str) -> int:
    if not text.isdecimal():
        raise argparse.ArgumentTypeError(f"want a whole number, got {text!r}")
    return int(text)


def options(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="audit.py")
    commands = parser.add_subparsers(dest="command", required=True)
    first = commands.add_parser("prepare")
    for flag in ("--repo", "--out", "--medusa"):
        first.add_argument(flag, required=True)
    first.add_argument("--budget", type=count, required=True)
    first.add_argument("--range")
    first.add_argument("--profile", choices=PROFILES, default="quick")  # nocheck: clean.default-value -- requirement 011 decision 7 makes quick the profile unless --profile names another
    second = commands.add_parser("attest")
    for flag in ("--repo", "--plan", "--run"):
        second.add_argument(flag, required=True)
    for flag in ("--invocations", "--tokens", "--minutes"):
        second.add_argument(flag, type=count, required=True)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = options(argv)
    try:
        return prepare(args) if args.command == "prepare" else attest(args)
    except Usage as error:
        print(f"audit.py: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
