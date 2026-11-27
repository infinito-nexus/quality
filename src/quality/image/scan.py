import json
import os
import re
import shutil
import tarfile
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from quality import QualityError, db, printable, ruledata
from quality.adapters.trivy import offline_flags
from quality.environment import tool_environment, validated_path
from quality.image import engines
from quality.process import run

DOCKER = "docker"
TRIVY = "trivy"
OSV = "osv-scanner"
DOCKER_VARIABLES = ("DOCKER_HOST",)
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
MISSING_IMAGE = b"No such image"
NOT_LOCAL = "not local"
LINE_CHARS = 200
ERROR_WORDS = re.compile(r"error|fatal|could not|unable|failed|no such", re.IGNORECASE)


@dataclass(frozen=True)
class Source:
    """
    Args:
        ref: The reference, archive or directory as the caller named it.
        trivy_input: What trivy reads: the archive or the OCI layout directory.
        archive: The tar osv-scanner reads.
        reason: Why it stays unscanned, or "".
    """

    ref: str
    trivy_input: Path | None
    archive: Path | None
    reason: str


@dataclass(frozen=True)
class Context:
    scratch: Path
    env: dict
    data: ruledata.RuleData
    bundle: db.Bundle
    programs: dict


def first_line(stderr: bytes) -> str:
    """
    Args:
        stderr: A tool's error output.

    Returns:
        Its first line naming an error, else its last line: osv-scanner and
        trivy print progress lines before the error.
    """
    lines = [line.strip() for line in stderr.decode("utf-8", "replace").splitlines() if line.strip()]
    if not lines:
        return "no error output"
    named = [line for line in lines if ERROR_WORDS.search(line)]
    return printable((named or lines[-1:])[0][:LINE_CHARS])


def executable(name: str, path_value: str) -> str:
    found = shutil.which(name, path=path_value)
    if found is None:
        raise QualityError(f"missing tool: {name}")
    return found


@dataclass
class Exporter:
    """
    Args:
        docker: The docker client.
        env: Its environment.
        timeout: Seconds one inspect or save may take.
        scratch: Directory the archives go to.
        saved: Image id to its archive and the reason it failed, filled as
            references are exported, so one id is saved once.
    """

    docker: str
    env: dict
    timeout: float
    scratch: Path
    saved: dict

    def source(self, ref: str) -> Source:
        inspected = self.docker_run("image", "inspect", "--format", "{{.Id}}", "--", ref)
        if inspected.code != 0:
            local = MISSING_IMAGE not in inspected.stderr
            return Source(ref, None, None, f"docker: {first_line(inspected.stderr)}" if local else NOT_LOCAL)
        image_id = inspected.stdout.decode("ascii", "replace").strip()
        if not IMAGE_ID.fullmatch(image_id):
            return Source(ref, None, None, "docker: no image id")
        if image_id not in self.saved:
            self.saved[image_id] = self.save(ref, image_id)
        archive, reason = self.saved[image_id]
        return Source(ref, archive, archive, reason)

    def save(self, ref: str, image_id: str) -> tuple:
        archive = self.scratch / f"{image_id.removeprefix('sha256:')}.tar"
        saved = self.docker_run("save", "--output", str(archive), "--", ref)
        if saved.code != 0:
            return None, f"docker: {first_line(saved.stderr)}"
        return archive, ""

    def docker_run(self, *args: str):
        return run([self.docker, *args], str(self.scratch), self.env, self.timeout)


def packed(layout: Path, archive: Path) -> Path:
    with tarfile.open(archive, "w") as bundle:
        for item in sorted(layout.iterdir()):
            bundle.add(item, arcname=item.name)
    return archive


def explicit(target: str) -> bool:
    return Path(target).is_absolute() or target.startswith((os.curdir + os.sep, os.pardir + os.sep))


def sources(targets: list, context: Context, path_value: str) -> list:
    """
    Args:
        targets: References, `docker save` archives and OCI layout directories.
        context: The scan's scratch and settings.
        path_value: PATH docker is resolved from, only when a reference is given.

    Returns:
        One Source per distinct target. A reference is exported from the local
        daemon, never pulled; a directory is packed into a tar for osv-scanner.
        Only an absolute or ./-relative target is a path; a bare target that
        exists on disk is refused, since a planted file named like a reference
        would otherwise replace the daemon image.
    """
    found = []
    exporter = None
    for index, target in enumerate(dict.fromkeys(targets)):
        path = Path(target)
        if explicit(target) and path.is_dir():
            found.append(Source(target, path.resolve(), packed(path, context.scratch / f"layout-{index}.tar"), ""))
        elif explicit(target) and path.is_file():
            found.append(Source(target, path.resolve(), path.resolve(), ""))
        elif explicit(target) or os.path.lexists(target):
            raise QualityError(
                f"{printable(target)}: an archive or layout is an existing ./ or absolute path, a reference names no file here"
            )
        else:
            if exporter is None:
                exporter = Exporter(
                    executable(DOCKER, path_value),
                    docker_env(context.env),
                    context.data.limit("image_export_timeout"),
                    context.scratch,
                    {},
                )
            found.append(exporter.source(target))
    return found


def docker_env(env: dict) -> dict:
    return env | {name: os.environ[name] for name in DOCKER_VARIABLES if name in os.environ}


def engine_argv(name: str, source: Source, context: Context) -> list:
    if name == TRIVY:
        return [context.programs[TRIVY], "image", "--input", str(source.trivy_input), *offline_flags(context.bundle)]
    empty = context.scratch / "osv-scanner.toml"
    empty.touch()
    return [
        context.programs[OSV],
        "scan",
        "image",
        "--archive",
        "--offline",
        "--offline-vulnerabilities",
        "--format",
        "json",
        "--config",
        str(empty),
        "--",
        str(source.archive),
    ]


def engine_rows(name: str, source: Source, context: Context) -> tuple:
    """
    Args:
        name: trivy or osv-scanner.
        source: A scannable image.
        context: The scan's scratch and settings.

    Returns:
        The engine's (package, installed, id, severity, fixed, engine) rows and
        "", or no rows and why the engine gave no report.
    """
    settings = context.data.tool(name)
    result = run(engine_argv(name, source, context), str(context.scratch), context.env, settings["timeout"])
    if result.code not in settings["exit_codes"]:
        return [], f"{name}: {first_line(result.stderr)}"
    parse = engines.trivy_rows if name == TRIVY else engines.osv_rows
    try:
        return [(*row, name) for row in parse(result.stdout)], ""
    except (ValueError, KeyError, TypeError, AttributeError):
        return [], f"{name}: unreadable report"


def merged(rows: list) -> dict:
    """
    Args:
        rows: (package, installed, id, severity, fixed, engine) rows of one image.

    Returns:
        (package, installed) to its engines and its ids, each with the gravest
        severity and the highest fixed-in version any engine reported.
    """
    packages = {}
    for package, installed, identifier, severity, fixed, engine in rows:
        entry = packages.setdefault((package, installed), {"engines": set(), "vulnerabilities": {}})
        entry["engines"].add(engine)
        known = entry["vulnerabilities"].setdefault(identifier, {"severity": engines.UNKNOWN, "fixed": ""})
        known["severity"] = engines.graver(known["severity"], severity)
        known["fixed"] = engines.highest([known["fixed"], fixed])
    return packages


def finding(rule, ref: str, key: tuple, entry: dict) -> dict:
    """
    Args:
        rule: security.vulnerable-image.
        ref: The image as the caller named it.
        key: (package, installed).
        entry: Its engines and vulnerabilities, see merged().

    Returns:
        The finding in `quality check --json`'s schema plus package,
        installed, fixed, vulnerabilities, engines and message.
    """
    package, installed = key
    fixed = engines.highest([item["fixed"] for item in entry["vulnerabilities"].values()])
    ids = sorted(entry["vulnerabilities"])
    state = f"fixed in {fixed}" if fixed else "no fix"
    return {
        "rule": rule.id,
        "path": ref,
        "line": None,
        "severity": rule.severity,
        "summary": rule.summary,
        "value": None,
        "commit": None,
        "lens": rule.lens,
        "package": package,
        "installed": installed,
        "fixed": fixed,
        "vulnerabilities": {name: entry["vulnerabilities"][name] for name in ids},
        "engines": sorted(entry["engines"]),
        "message": f"{package} {installed} ({state}): {', '.join(ids)}",
    }


def scanned(found: list, context: Context) -> tuple:
    rule = context.data.runner_rule(ruledata.IMAGE_SCAN)
    findings, unscanned, cache = [], [], {}
    for source in found:
        if source.reason:
            unscanned.append({"path": source.ref, "reason": source.reason})
            continue
        if source.archive not in cache:
            cache[source.archive] = [engine_rows(name, source, context) for name in (TRIVY, OSV)]
        reports = cache[source.archive]
        rows = [row for engine_report, _ in reports for row in engine_report]
        findings += [finding(rule, source.ref, key, entry) for key, entry in sorted(merged(rows).items())]
        unscanned += [{"path": source.ref, "reason": reason} for _, reason in reports if reason]
    return findings, unscanned


def rendered(document: dict, as_json: bool) -> str:
    if as_json:
        return json.dumps(document, indent=2, sort_keys=True)
    lines = [f"{item['path']}: {item['rule']} [{item['severity']}] {item['message']}" for item in document["findings"]]
    lines += [f"unscanned: {item['path']}: {item['reason']}" for item in document["unscanned"]]
    lines += document["notes"]
    lines.append(f"quality: {len(document['findings'])} finding(s), {len(document['unscanned'])} unscanned image(s)")
    return "\n".join(printable(line) for line in lines)


def scan(targets: list, rules_option: str | None, db_option: str | None, as_json: bool) -> int:
    """
    Args:
        targets: References of local images, `docker save` archives and OCI
            layout directories.
        rules_option: The --rules value, or None.
        db_option: The --db value, or None.
        as_json: Print JSON instead of text.

    Returns:
        0 when every image scanned clean, 1 with findings or unscanned images.
    """
    data = ruledata.load(ruledata.locate(rules_option))
    bundle = db.open_bundle(db.location(db_option, os.environ), data.limit("db_max_age_days"), datetime.now(timezone.utc))
    path_value = validated_path(os.environ)
    programs = {name: executable(name, path_value) for name in (TRIVY, OSV)}
    scratch = Path(tempfile.mkdtemp(prefix="quality-image-")).resolve()
    try:
        home = scratch / "home"
        home.mkdir()
        context = Context(scratch, tool_environment(path_value, home, bundle), data, bundle, programs)
        findings, unscanned = scanned(sources(targets, context, path_value), context)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    print(rendered({"findings": findings, "unscanned": unscanned, "notes": [bundle.note()]}, as_json))
    return 1 if findings or unscanned else 0
