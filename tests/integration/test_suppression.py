from tests.integration.support import report, rule_for, rule_ids, rules_without_pending

F401 = rule_for("F401")
EVAL = "security.eval-exec"
DOCKERFILE = "coding.dockerfile"
IGNORE = ".qualityignore.yml"


def staged_finding(target, ignore_text: str | None):
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.write("a.py", "import os\n")
    if ignore_text is not None:
        target.write(IGNORE, ignore_text)
    target.stage()
    return target.check("--staged", "--json")


def test_ignore_disables_rule(target):
    result = staged_finding(target, None)
    assert result.returncode == 1
    assert rule_ids(result) == [F401]
    target.write(IGNORE, f"- rule: {F401}\n  reason: fixture\n")
    target.stage()
    result = target.check("--staged", "--json")
    assert result.returncode == 0
    assert report(result)["ignored"] == [{"rule": F401, "paths": [], "reason": "fixture"}]
    target.write(IGNORE, f"- rule: {F401}\n  paths: [other/]\n  reason: fixture\n")
    target.stage()
    result = target.check("--staged", "--json")
    assert result.returncode == 1
    assert rule_ids(result) == [F401]
    target.write(IGNORE, f"- rule: {F401}\n  paths: [a.py]\n  reason: fixture\n")
    target.stage()
    assert target.check("--staged").returncode == 0


def test_ignore_disables_rule_for_a_group(target):
    assert staged_finding(target, "- rule: coding\n  reason: fixture\n").returncode == 0


def test_ignore_reason_required(target):
    result = staged_finding(target, f"- rule: {F401}\n")
    assert result.returncode == 2
    assert "reason" in result.stderr


def test_ignore_hard_needs_paths(target):
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.write(IGNORE, f"- rule: {EVAL}\n  reason: fixture\n")
    target.stage()
    result = target.check("--staged")
    assert result.returncode == 2
    assert "hard" in result.stderr
    for pattern in ("'**'", "'src/**'", "'*'", "'*.py'", "'[a-z]*'", "'*/a.py'"):
        target.write(IGNORE, f"- rule: {EVAL}\n  paths: [{pattern}]\n  reason: fixture\n")
        target.stage()
        result = target.check("--staged")
        assert result.returncode == 2, pattern
        assert "hard" in result.stderr


def test_ignore_hard_read_from_base(target):
    target.write("a.py", "x = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    target.write("a.py", "X = eval(input())\n")
    target.write(IGNORE, f"- rule: {EVAL}\n  paths: [a.py]\n  reason: self exempted\n")
    target.commit()
    result = target.check("--base", "main", "--json")
    assert result.returncode == 1
    assert EVAL in rule_ids(result)
    assert report(result)["ignored"] == []
    target.git("checkout", "-q", "main")
    target.write(IGNORE, f"- rule: {EVAL}\n  paths: [a.py]\n  reason: reviewed on main\n")
    target.commit()
    target.git("checkout", "-q", "-b", "second")
    target.write("a.py", "X = eval(input())\n")
    target.commit()
    assert target.check("--base", "main").returncode == 0


def test_ignore_soft_read_from_head_under_base(target):
    target.write("a.py", "x = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    target.write("a.py", "import os\n")
    target.write(IGNORE, f"- rule: {F401}\n  paths: [a.py]\n  reason: fixture\n")
    target.commit()
    assert target.check("--base", "main").returncode == 0


def test_ignore_broken_on_base_keeps_hard_rules_and_allows_the_fix(target):
    target.write("a.py", "x = 1\n")
    target.write(IGNORE, "- rule: x\n  reason: [\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    target.write(IGNORE, "")
    target.commit()
    assert target.check("--base", "main").returncode == 0
    target.write("a.py", "X = eval(input())\n")
    target.commit()
    assert target.check("--base", "main").returncode == 1


def test_ignore_stale(target, tmp_path):
    target.write("a.py", "x = 1\n")
    target.commit()
    target.write("b.py", "y = 1\n")
    target.write(IGNORE, f"- rule: {F401}\n  paths: [nothing.py]\n  reason: stale\n")
    target.stage()
    assert target.check("--staged").returncode == 0
    reduced = rules_without_pending(tmp_path / "rules")
    result = target.check("--all", "--rules", str(reduced))
    assert result.returncode == 2
    assert "stale" in result.stderr
    assert F401 in result.stderr
    target.write(IGNORE, f"- rule: {F401}\n  paths: [a.py]\n  reason: used\n")
    target.write("a.py", "import os\n")
    target.stage()
    assert target.check("--all", "--rules", str(reduced)).returncode == 0


def test_ignore_audit_line(target):
    target.write("a.py", "x = 1\n")
    target.write(
        IGNORE,
        "- rule: coding.one\n  reason: first\n- rule: coding.two\n  reason: second\n",
    )
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    target.write("a.py", "x = 2\n")
    target.commit()
    silent = target.check("--base", "main")
    assert "audit:" not in silent.stdout
    target.write(
        IGNORE,
        "- rule: coding.one\n  reason: changed\n- rule: coding.three\n  reason: third\n",
    )
    target.commit()
    result = target.check("--base", "main")
    audit = [line for line in result.stdout.splitlines() if line.startswith("audit:")]
    assert len(audit) == 3
    assert sum("removed rule=coding.two" in line for line in audit) == 1
    assert sum("added rule=coding.three" in line for line in audit) == 1
    assert sum("changed rule=coding.one" in line for line in audit) == 1
    notes = report(target.check("--base", "main", "--json"))["notes"]
    assert sum(note.startswith("audit:") for note in notes) == 3


def test_nocheck_needs_reason(target):
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.write("a.py", f"import os  # nocheck: {F401}\n")
    target.stage()
    assert target.check("--staged").returncode == 1
    target.write("a.py", f"import os  # nocheck: {F401} -- \n")
    target.stage()
    assert target.check("--staged").returncode == 1
    target.write("a.py", f"import os  # nocheck: {F401} -- legacy interface\n")
    target.stage()
    result = target.check("--staged", "--json")
    assert result.returncode == 0
    assert report(result)["nocheck"] == [{"path": "a.py", "line": 1, "rule": F401}]


def test_nocheck_comment_only(target):
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.write("a.py", f'import os; x = "nocheck: {F401} -- reason"\n')
    target.stage()
    result = target.check("--staged", "--json")
    assert result.returncode == 1
    assert F401 in rule_ids(result)
    assert report(result)["nocheck"] == []


def test_nocheck_wrong_rule_does_not_suppress(target):
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.write("a.py", "import os  # nocheck: coding.other -- reason\n")
    target.stage()
    assert target.check("--staged").returncode == 1


def test_nocheck_does_not_suppress_a_hard_rule(target):
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.write("a.py", f"X = eval(input())  # nocheck: {EVAL} -- reason\n")
    target.stage()
    result = target.check("--staged", "--json")
    assert result.returncode == 1
    assert rule_ids(result) == [EVAL]


def test_nocheck_in_a_shell_comment(target):
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.write("s.sh", "#!/bin/bash\necho $1  # nocheck: coding.shell-lint -- fixture\n")
    target.stage()
    assert target.check("--staged").returncode == 0
    target.write("s.sh", '#!/bin/bash\necho $1 "# nocheck: coding.shell-lint -- fixture"\n')
    target.stage()
    assert target.check("--staged").returncode == 1


def test_nocheck_in_a_dockerfile_comment(target):
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.write("Dockerfile", f"FROM debian:13\nRUN echo $1  # nocheck: {DOCKERFILE} -- fixture\n")
    target.stage()
    result = target.check("--staged", "--json")
    assert result.returncode == 0, result.stderr
    assert report(result)["nocheck"] == [{"path": "Dockerfile", "line": 2, "rule": DOCKERFILE}]
    target.write("Dockerfile", "FROM debian:13\nRUN echo $1\n")
    target.stage()
    assert rule_ids(target.check("--staged", "--json")) == [DOCKERFILE]


def test_nocheck_applies_to_every_tool_line(target):
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.write("a.py", "import os  # nocheck: coding -- group\n")
    target.stage()
    assert target.check("--staged").returncode == 0
