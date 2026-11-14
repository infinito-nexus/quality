import os

import pytest

from tests.integration.repository.support import (
    DOWNLOAD,
    PARTIAL_SCAN,
    PIPE,
    feature_check,
    findings_of,
)
from tests.integration.support import branchy, report

STATIC = "security.static-analysis"
CALL = "new Function(location.hash)();\n"


@pytest.mark.deep
def test_semgrep_reports_a_script_it_cannot_parse(target):
    target.write("seed.py", "x = 1\n")
    target.write("old.js", "$(( 2 +\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    target.write("app.js", f"{CALL}$(( 1 +\n")
    target.write("old.js", f"{CALL}$(( 2 +\n")
    target.commit()
    for flags in (("--base", "main"), ("--all",)):
        result = target.check(*flags, "--json")
        assert result.returncode == 1, result.stderr
        assert findings_of(result, STATIC) == [("app.js", None), ("old.js", None)]


STATIC_BLOCK = "class A {\n  static {\n    run(\n      new Function(\n        location.hash\n      )\n    );\n  }\n}\n"


@pytest.mark.deep
def test_semgrep_reads_extensionless_scripts_and_shell_needs_no_parser(target):
    result = feature_check(
        target,
        {
            "bin/app": f"#!/usr/bin/env node\n{CALL}",
            "bin/web": f"#!/usr/bin/env node\n{STATIC_BLOCK}",
            "web/app.js": STATIC_BLOCK,
            "install.sh": f'#!/bin/bash\necho start\ncase "$1" in (go) {PIPE};; esac\n',
            "bin/run": f'#!/bin/bash\n: "${{1:?$({PIPE})|b}}"\n',
        },
    )
    assert result.returncode == 1, result.stderr
    assert ("bin/app", 2) in findings_of(result, STATIC)
    assert findings_of(result, PARTIAL_SCAN) == [("bin/web", None), ("web/app.js", None)]
    assert findings_of(result, DOWNLOAD) == [("bin/run", 2), ("install.sh", 3)]
    whole = target.check("--all", "--json")
    assert findings_of(whole, PARTIAL_SCAN) == []
    assert findings_of(whole, DOWNLOAD) == [("bin/run", 2), ("install.sh", 3)]
    unparsed = [note for note in report(whole)["notes"] if note.startswith("parse incomplete: ")]
    assert unparsed == ["parse incomplete: bin/web", "parse incomplete: web/app.js"]


@pytest.mark.deep
def test_an_old_partial_parse_counts_once_its_file_changes(target):
    target.write("web/app.js", STATIC_BLOCK)
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "unrelated")
    target.write("seed.py", "x = 2\n")
    target.commit()
    assert findings_of(target.check("--base", "main", "--json"), PARTIAL_SCAN) == []
    target.git("checkout", "-q", "-b", "feature", "main")
    target.write("web/app.js", f"// changed\n{STATIC_BLOCK}")
    target.commit()
    assert findings_of(target.check("--base", "main", "--json"), PARTIAL_SCAN) == [("web/app.js", None)]


NOCHECK_GAP = f"nocheck: {PARTIAL_SCAN} -- semgrep reads no part of this"


def gap_entry(path: str) -> str:
    return f"- rule: {PARTIAL_SCAN}\n  paths: [{path}]\n  reason: semgrep reads no static block\n"


@pytest.mark.deep
def test_only_a_base_side_entry_naming_the_file_waives_a_partial_scan(target):
    target.write(".qualityignore.yml", gap_entry("web/run.js"))
    nochecked = STATIC_BLOCK.replace("static {", f"static {{ // {NOCHECK_GAP}")
    result = feature_check(target, {"web/run.js": STATIC_BLOCK, "web/app.js": nochecked})
    assert result.returncode == 1, result.stderr
    assert findings_of(result, PARTIAL_SCAN) == [("web/app.js", None)]
    assert report(result)["nocheck"] == []
    assert [item["rule"] for item in report(result)["ignored"]] == [PARTIAL_SCAN]
    whole = report(target.check("--all", "--json"))
    assert [item["rule"] for item in whole["ignored"]] == [PARTIAL_SCAN]
    assert "parse incomplete: web/run.js" not in whole["notes"]


@pytest.mark.deep
def test_a_pull_request_cannot_waive_its_own_partial_scan(target):
    result = feature_check(target, {"web/app.js": STATIC_BLOCK, ".qualityignore.yml": gap_entry("web/app.js")})
    assert result.returncode == 1, result.stderr
    assert findings_of(result, PARTIAL_SCAN) == [("web/app.js", None)]
    assert report(result)["ignored"] == []


@pytest.mark.deep
def test_a_partial_scan_entry_for_a_file_read_whole_is_stale_under_base_and_all(target):
    result = feature_check(target, {"web/clean.js": "run(1);\n", ".qualityignore.yml": gap_entry("web/clean.js")})
    assert result.returncode == 2
    assert "stale .qualityignore.yml entry" in result.stderr
    whole = target.check("--all")
    assert whole.returncode == 2
    assert "stale .qualityignore.yml entry" in whole.stderr
    target.write("web/clean.js", "run(2);\n")
    target.stage()
    assert target.check("--staged").returncode == 0


@pytest.mark.deep
def test_a_renamed_waived_file_needs_its_new_name_on_the_base_side(target):
    target.write("web/app.js", STATIC_BLOCK)
    target.write(".qualityignore.yml", gap_entry("web/app.js"))
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    target.git("mv", "web/app.js", "web/main.js")
    target.write(".qualityignore.yml", gap_entry("web/main.js"))
    target.commit()
    result = target.check("--base", "main", "--json")
    assert result.returncode == 1, result.stderr
    assert findings_of(result, PARTIAL_SCAN) == [("web/main.js", None)]


@pytest.mark.deep
def test_nochecks_around_an_unread_region_waive_nothing(target):
    body = "    run(\n      new Function(\n        location.hash\n      )\n    );\n"
    result = feature_check(
        target,
        {
            "web/app.js": f"class A {{\n  static {{ // {NOCHECK_GAP}\n{body}  }}\n}} // {NOCHECK_GAP}\n",
            "bin/boot": f"#!/bin/bash\n: ${{1:?$(\n  {PIPE}\n)|b}}  # {NOCHECK_GAP}\n",
        },
    )
    assert result.returncode == 1, result.stderr
    assert findings_of(result, PARTIAL_SCAN) == [("web/app.js", None)]
    assert findings_of(result, DOWNLOAD) == [("bin/boot", 3)]


CLONES = "clean.clones"


@pytest.mark.deep
def test_clone_of_an_untouched_file_is_new(target):
    target.write("a.py", branchy("original", 12))
    target.write("c.py", branchy("old_copy", 12))
    target.commit()
    target.git("checkout", "-q", "-b", "unrelated")
    target.write("seed.py", "x = 1\n")
    target.commit()
    assert findings_of(target.check("--base", "main", "--json"), CLONES) == []
    target.git("checkout", "-q", "-b", "feature", "main")
    target.write("b.py", branchy("copied", 12))
    target.commit()
    found = findings_of(target.check("--base", "main", "--json"), CLONES)
    assert "b.py" in {path for path, _line in found}


@pytest.mark.deep
def test_an_untouched_name_jscpd_cannot_read_never_breaks_an_unrelated_change(target):
    hostile = os.fsdecode(b"caf\xe9.py")
    target.write("seed.py", "x = 1\n")
    target.write(hostile, "z = 3\n")
    target.commit()
    target.git("checkout", "-q", "-b", "unrelated")
    target.write("other.py", "y = 2\n")
    target.commit()
    result = target.check("--base", "main", "--json")
    assert result.returncode == 0, result.stderr
    assert f"unchecked: {hostile}: jscpd cannot read a name that is not UTF-8" in report(result)["notes"]
