import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from tests.integration.hard.support import SECRET_LINE, SECRET_RULE
from tests.integration.support import NO_BUNDLE_CACHE, SRC, TEST_CACHE, TEST_DB

ROOT = Path(__file__).resolve().parents[3]
REVIEW = ROOT / "skills" / "kvb-quality-review" / "scripts" / "review.py"
UNUSED_RULE = "coding.unused-import"
LENGTH_RULE = "clean.function-length"
UNUSED = "import os\n"
CLEAN = "x = 1\n"
LONG = "def long():\n" + "".join(f"    value_{index} = {index}\n" for index in range(60)) + "    return value_0\n"
LEDGER = "security-accepted.jsonl"
JUDGED = {"kvb-quality-break-risk", "kvb-quality-confidence"}
DEEP = "quality-deep"


def review(target, scratch: Path, *argv: str, deep: bool = False) -> subprocess.CompletedProcess:
    """
    Args:
        target: The fixture repository.
        scratch: The test's own directory; its council/ holds the shared
            accepted-findings ledger of the run.
        argv: Arguments after --repo.
        deep: True reads the shared test bundle's cache, False one without.

    Returns:
        The finished review.py run.
    """
    env = {
        "PATH": os.environ["PATH"],
        "TMPDIR": tempfile.gettempdir(),
        "PYTHONPATH": str(SRC),
        "HOME": str(scratch / "home"),
        "XDG_STATE_HOME": str(scratch / "state"),
        "XDG_CACHE_HOME": str(TEST_CACHE if deep else NO_BUNDLE_CACHE),
        "AGENTS_COUNCIL_ROOT": str(scratch / "council"),
    }
    return subprocess.run(
        [sys.executable, "-B", str(REVIEW), "--repo", str(target.path), *argv],
        cwd=target.path,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


def parsed(result: subprocess.CompletedProcess) -> dict:
    assert result.returncode in (0, 1), result.stderr
    return json.loads(result.stdout)


def rows(document: dict, lens: str) -> list:
    return [(item["rule"], item["path"]) for item in document["findings"] if item["lens"] == lens]


def skipped(document: dict) -> set:
    return {item["lens"] for item in document["skipped"]}


def accept(scratch: Path, rule: str, path: str, fingerprinted: str) -> None:
    """
    Args:
        scratch: The test's own directory holding council/.
        rule: Rule of the accepted finding.
        path: Its path.
        fingerprinted: Its stripped line, or the whole file for a finding
            without a line.
    """
    council = scratch / "council"
    council.mkdir(exist_ok=True)
    row = {"rule": rule, "path": path, "sha1": hashlib.sha1(fingerprinted.encode()).hexdigest(), "reason": "fixture"}
    with (council / LEDGER).open("a", encoding="utf-8") as ledger:
        ledger.write(json.dumps(row) + "\n")


def test_staged_reports_an_unused_import_with_its_blob_then_nothing_after_the_fix(target, tmp_path):
    target.write("seed.py", CLEAN)
    target.commit()
    target.write("a.py", UNUSED)
    target.stage()
    result = review(target, tmp_path, "--staged", "--json")
    document = parsed(result)
    assert result.returncode == 1, result.stderr
    blob = target.git("rev-parse", ":a.py").stdout.strip()
    assert [(item["lens"], item["rule"], item["tier"], item["path"], item["blob"]) for item in document["findings"]] == [
        ("quality", UNUSED_RULE, "fast", "a.py", blob)
    ]
    target.write("a.py", CLEAN)
    target.stage()
    fixed = review(target, tmp_path, "--staged", "--json")
    assert fixed.returncode == 0, fixed.stderr
    assert parsed(fixed)["findings"] == []


def test_judgements_and_unmeasured_scores_stay_null_and_every_lens_that_ran_names_its_version(target, tmp_path):
    target.write("seed.py", CLEAN)
    target.commit()
    target.write("a.py", CLEAN)
    target.stage()
    document = parsed(review(target, tmp_path, "--staged", "--json"))
    scores = document["scores"]
    assert [scores[name] for name in ("break_risk", "confidence", "efficiency", "speed")] == [None] * 4
    assert (scores["legal"], scores["architecture"]) == (100, 100)
    assert JUDGED | {DEEP, "performance"} <= skipped(document)
    assert {"quality", "legal", "architecture"} <= set(document["ran"])
    assert set(document["lenses"]) == set(document["ran"])
    assert all(isinstance(version, str) and version for version in document["lenses"].values())
    assert not set(document["ran"]) & skipped(document)


def test_path_limits_every_lens_and_its_score(target, tmp_path):
    target.write("seed.py", CLEAN)
    target.commit()
    target.write("a.py", UNUSED)
    target.write("b.py", UNUSED + "\n\n" + LONG)
    target.stage()
    every = parsed(review(target, tmp_path, "--staged", "--json"))
    assert {item["path"] for item in every["findings"]} == {"a.py", "b.py"}
    assert every["scores"]["architecture"] == 90
    limited = parsed(review(target, tmp_path, "--staged", "--path", "a.py", "--json"))
    assert limited["findings"]
    assert {item["path"] for item in limited["findings"]} == {"a.py"}
    assert limited["scores"]["architecture"] == 100


def test_waived_and_accepted_findings_are_absent(target, tmp_path):
    target.write("seed.py", CLEAN)
    target.write("pkg/__init__.py", "")
    target.commit()
    target.write("a.py", UNUSED)
    target.write("pkg/b.py", UNUSED)
    target.write("c.py", UNUSED)
    target.write("long.py", LONG)
    target.write(".qualityignore.yml", f"- rule: {UNUSED_RULE}\n  paths: [a.py]\n  reason: fixture\n")
    target.write("pkg/.nocheck", f"# nocheck: {UNUSED_RULE} -- fixture\n")
    target.stage()
    before = parsed(review(target, tmp_path, "--staged", "--json"))
    assert rows(before, "quality") == [(UNUSED_RULE, "c.py")]
    assert rows(before, "architecture") == [(LENGTH_RULE, "long.py")]
    assert before["scores"]["architecture"] == 90
    accept(tmp_path, LENGTH_RULE, "long.py", LONG.splitlines()[0].strip())
    after = parsed(review(target, tmp_path, "--staged", "--json"))
    assert rows(after, "quality") == [(UNUSED_RULE, "c.py")]
    assert rows(after, "architecture") == []
    assert after["scores"]["architecture"] == 100


def test_a_security_finding_in_the_accepted_findings_ledger_is_absent(target, tmp_path):
    target.write("seed.py", CLEAN)
    target.commit()
    target.write("leak.py", SECRET_LINE)
    target.stage()
    before = parsed(review(target, tmp_path, "--staged", "--json"))
    if "security" not in before["ran"]:
        pytest.skip(f"the security lens did not run: {before['skipped']}")
    found = [item for item in before["findings"] if item["lens"] == "security"]
    if not found:
        pytest.skip("MEDUSA reports nothing on the fixture secret")
    for item in found:
        accept(tmp_path, item["rule"], item["path"], SECRET_LINE if item["line"] is None else SECRET_LINE.strip())
    after = parsed(review(target, tmp_path, "--staged", "--json"))
    assert rows(after, "security") == []
    assert (SECRET_RULE, "leak.py") in rows(after, "quality")


def test_range_reports_a_secret_added_and_removed_inside_it_with_that_commit(target, tmp_path):
    target.write("a.py", CLEAN)
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    target.write("a.py", SECRET_LINE)
    added = target.commit()
    target.write("a.py", CLEAN)
    removed = target.commit()
    target.write("later.py", CLEAN)
    target.commit()
    result = review(target, tmp_path, "--range", f"main..{removed}", "--json")
    document = parsed(result)
    assert result.returncode == 1, result.stderr
    assert [(item["lens"], item["rule"], item["path"], item["line"], item["commit"]) for item in document["findings"]] == [
        ("quality", SECRET_RULE, "a.py", 1, added)
    ]
    assert document["findings"][0]["blob"] == target.git("rev-parse", f"{added}:a.py").stdout.strip()
    assert {"security", DEEP} <= skipped(document)


def test_all_reports_findings_without_a_ratchet_score(target, tmp_path):
    target.write("legacy.py", UNUSED)
    target.commit()
    result = review(target, tmp_path, "--all", "--json")
    document = parsed(result)
    assert result.returncode == 1, result.stderr
    assert rows(document, "quality") == [(UNUSED_RULE, "legacy.py")]
    assert (document["scores"]["legal"], document["scores"]["architecture"]) == (None, None)
    assert "security" in skipped(document)


@pytest.mark.deep
def test_the_deep_tier_runs_only_with_a_database(target, tmp_path):
    target.write("seed.py", CLEAN)
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    target.write("a.py", CLEAN)
    target.commit()
    without = parsed(review(target, tmp_path, "--base", "main", "--json"))
    assert DEEP in skipped(without)
    assert DEEP not in without["ran"]
    result = review(target, tmp_path, "--base", "main", "--db", str(TEST_DB), "--json", deep=True)
    document = parsed(result)
    assert DEEP in document["ran"], result.stderr
    assert DEEP not in skipped(document)
    assert document["lenses"][DEEP]
