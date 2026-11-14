import json
import os
import subprocess

import pytest

from tests.integration.support import branchy, report

CLONES = "clean.clones"


def findings(result) -> list:
    return [(item["rule"], item["path"], item["value"]) for item in report(result)["findings"]]


def lines_of(text: str, count: int) -> str:
    return "".join(f"{text}{index}\n" for index in range(count))


def test_size_limits(target, mode):
    target.write("seed.py", "x = 1\n")
    target.start_feature(mode)
    target.write("run.sh", "#!/bin/bash\n" + lines_of("echo ", 500))
    target.write("tests/long.sh", "#!/bin/bash\n" + lines_of("printf ", 500))
    target.write("data.json", "[\n" + "".join(f"{index},\n" for index in range(500)) + "0]\n")
    target.write("yarn.lock", lines_of("x", 501))
    target.write("package-lock.json", "{\n" + lines_of('  "x', 501).replace("\n", '": 0,\n') + '  "y": 0\n}\n')
    target.write("locales/de.js", lines_of("export const a = ", 501))
    target.write("generated/api.ts", lines_of("export const a = ", 501))
    target.advance(mode)
    result = target.judge(mode, "--json")
    assert result.returncode == 1, result.stderr
    assert findings(result) == [("clean.file-lines", "run.sh", 501)]


def test_folder_limit(target, mode):
    for index in range(11):
        target.write(f"pkg/m{index}.txt", "x\n")
    for index in range(20):
        target.write(f"wide/m{index}.txt", "x\n")
    target.start_feature(mode)
    target.write("pkg/m11.txt", "x\n")
    target.write("wide/m0.txt", "y\n")
    target.advance(mode)
    assert findings(target.judge(mode, "--json")) == []
    target.write("pkg/m12.txt", "x\n")
    target.advance(mode)
    result = target.judge(mode, "--json")
    assert result.returncode == 1, result.stderr
    assert findings(result) == [("clean.folder-items", "pkg", 13)]


def test_folder_limit_counts_a_new_folder_in_its_parent(target, mode):
    for index in range(12):
        target.write(f"pkg/m{index}.txt", "x\n")
    target.start_feature(mode)
    target.write("pkg/sub/deep/a.txt", "x\n")
    target.advance(mode)
    assert findings(target.judge(mode, "--json")) == [("clean.folder-items", "pkg", 13)]


def test_folder_limit_counts_symlinks(target, mode):
    for index in range(12):
        target.write(f"pkg/m{index}.txt", "x\n")
    target.start_feature(mode)
    (target.path / "pkg" / "link").symlink_to("m0.txt")
    target.advance(mode)
    assert findings(target.judge(mode, "--json")) == [("clean.folder-items", "pkg", 13)]


def test_structure_under_all(target):
    for index in range(13):
        target.write(f"pkg/m{index}.txt", "x\n")
    target.write("report_a.txt", "x\n")
    target.write("report_b.txt", "x\n")
    target.commit()
    result = target.check("--all", "--json")
    assert sorted(findings(result)) == [
        ("clean.folder-items", "pkg", 13),
        ("clean.prefix-groups", ".", 2),
    ]


def test_prefix_groups(target, mode):
    target.write("old_a.txt", "x\n")
    target.write("old_b.txt", "x\n")
    target.start_feature(mode)
    target.write("report_a.txt", "x\n")
    target.write("report-b.txt", "x\n")
    target.write("ok/__init__.py", "")
    target.write("ok/__main__.py", "")
    target.write("ok/2026_a.md", "x\n")
    target.write("ok/2026_b.md", "x\n")
    target.write("ok/test_a.txt", "x\n")
    target.write("ok/test_b.txt", "x\n")
    target.write("ok/-a.txt", "x\n")
    target.write("ok/-b.txt", "x\n")
    target.write("ok/web-app-a/x.txt", "x\n")
    target.write("ok/web-app-b/x.txt", "x\n")
    target.advance(mode)
    result = target.judge(mode, "--json")
    assert result.returncode == 1, result.stderr
    assert findings(result) == [("clean.prefix-groups", ".", 2)]
    target.write("old_c.txt", "x\n")
    target.advance(mode)
    assert sorted(findings(target.judge(mode, "--json"))) == [
        ("clean.prefix-groups", ".", 2),
        ("clean.prefix-groups", ".", 3),
    ]


def workflow(*steps: tuple) -> str:
    body = "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
    for name, script in steps:
        indented = "".join(f"          {line}\n" for line in script)
        body += f"      - name: {name}\n        run: |\n{indented}"
    return body


ELEVEN = [*(f"echo {index}" for index in range(10)), "echo a \\", "  b", "# note", ""]
TWELVE = [f"echo {index}" for index in range(12)]


def test_inline_script_limit(target, mode):
    target.write("seed.py", "x = 1\n")
    target.start_feature(mode)
    target.write(".github/workflows/w.yml", workflow(("short", ELEVEN)))
    target.advance(mode)
    assert findings(target.judge(mode, "--json")) == []
    target.write(".github/workflows/w.yml", workflow(("short", ELEVEN), ("long", TWELVE)))
    target.advance(mode)
    result = target.judge(mode, "--json")
    assert result.returncode == 1, result.stderr
    long_run = 7 + len(ELEVEN) + 2
    assert [(item["rule"], item["line"], item["value"]) for item in report(result)["findings"]] == [
        ("clean.inline-script", long_run, 12)
    ]


def test_inline_script_nocheck(target):
    target.write("seed.py", "x = 1\n")
    target.commit()
    text = workflow(("long", TWELVE)).replace(
        "run: |", "run: |  # nocheck: clean.inline-script -- vendored step"
    )
    target.write(".github/workflows/w.yml", text)
    target.stage()
    document = report(target.check("--staged", "--json"))
    assert document["findings"] == []
    assert [item["rule"] for item in document["nocheck"]] == ["clean.inline-script"]


def test_inline_script_aliases_counted_once(target):
    target.write("seed.py", "x = 1\n")
    target.commit()
    script = "".join(f"          echo {index}\n" for index in range(12))
    text = (
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps: &steps\n"
        f"      - name: long\n        run: |\n{script}"
        "  b:\n    runs-on: ubuntu-latest\n    steps: *steps\n"
    )
    target.write(".github/workflows/w.yml", text)
    target.stage()
    assert [item["rule"] for item in report(target.check("--staged", "--json"))["findings"]] == [
        "clean.inline-script"
    ]


def function_of_length(name: str, nloc: int) -> str:
    body = "".join(f"    total += {index}\n" for index in range(nloc - 3))
    return f"def {name}():\n    total = 0\n{body}    return total\n"


def test_function_limits(target, mode):
    target.write("seed.py", "x = 1\n")
    target.start_feature(mode)
    source = "\n\n".join(
        [
            branchy("ccn_ok", 9),
            branchy("ccn_over", 10),
            function_of_length("length_ok", 50),
            function_of_length("length_over", 51),
            "def params_ok(a, b, c, d, e):\n    return a + b + c + d + e\n",
            "def params_over(a, b, c, d, e, f):\n    return a + b + c + d + e + f\n",
        ]
    )
    target.write("limits.py", source)
    target.advance(mode)
    result = target.judge(mode, "--json")
    assert result.returncode == 1, result.stderr
    metric = [item for item in report(result)["findings"] if item["rule"] != CLONES]
    assert sorted((item["rule"], item["value"]) for item in metric) == [
        ("clean.complexity", 11),
        ("clean.function-length", 51),
        ("clean.parameters", 6),
    ]


def sum_function(name: str, parameters: str, terms: int) -> str:
    """
    Args:
        name: Function name.
        parameters: Parameter list text.
        terms: Number of added literals.

    Returns:
        A function of 8 + 2 * terms jscpd tokens with one parameter, one fewer without.
    """
    total = " + ".join(str(term) for term in range(1, terms + 1))
    return f"def {name}({parameters}):\n    return a + {total}\n"


@pytest.mark.deep
def test_clone_limit(target, tmp_path):
    fifty = sum_function("first", "a", 21)
    forty_nine = sum_function("second", "", 21)
    target.write("seed.py", "x = 0\n")
    target.start_feature("base")
    target.write("one.py", f"{fifty}\n\nx = 0\n\n\n{forty_nine}")
    target.write("two.py", f"y = 1\n\n\n{fifty}\n\nz = 2\n\n\n{forty_nine}")
    target.write(".jscpd.json", '{"ignore": ["**/*.py"]}\n')
    target.write("package.json", '{"jscpd": {"ignore": ["**/*.py"]}}\n')
    target.advance("base")
    expected = [("one.py", 1), ("two.py", 4)]
    for flags in (("--base", "main"), ("--all",)):
        found = report(target.check(*flags, "--json"))["findings"]
        assert sorted((i["path"], i["line"]) for i in found if i["rule"] == CLONES) == expected
    output = tmp_path / "raw"
    home = tmp_path / "home"
    home.mkdir()
    control = subprocess.run(
        ["jscpd", "--reporters", "json", "--output", str(output), "one.py", "two.py"],
        cwd=target.path,
        env={"PATH": os.environ["PATH"], "HOME": str(home)},
        capture_output=True,
        check=False,
    )
    assert control.returncode == 0
    raw = json.loads((output / "jscpd-report.json").read_text(encoding="utf-8"))
    assert raw["duplicates"] == []
