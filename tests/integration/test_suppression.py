from tests.integration.support import report, rule_for, rule_ids, rules_without_pending

F401 = rule_for("F401")
EVAL = "security.eval-exec"
DOCKERFILE = "coding.dockerfile"
IGNORE = ".qualityignore.yml"
PARSE_GAP = "coding.parse-incomplete"
GAP_SOURCE = "export function run( {\n  go();\n}\n"
LINE_BREAK = "security.uncounted-line-break"
STRUCTURAL = "coding.structural"
LS = "\N{LINE SEPARATOR}"
PS = "\N{PARAGRAPH SEPARATOR}"
NEL = "\x85"
HIDDEN_JS = "// nocheck: coding.structural -- r{0}function f() {{{0}  debugger;{0}  try {{ x(); }} catch (e) {{}}{0}}}{0}\n"
HIDDEN_YAML = 'a: 1 # c{0}b: "{{{{ x | default(1) }}}}"\n'
HIDDEN_CS = '// c{0}class A {{ static void Main() {{ string x = null; System.Console.WriteLine(x ?? "hidden"); }} }}\n'
JAVA_ESCAPE = "\\u000a"
SEPARATED = {
    "ls.cs": HIDDEN_CS.format(LS),
    "ps.cs": HIDDEN_CS.format(PS),
    "nel.cs": HIDDEN_CS.format(NEL),
    "Escape.java": f"// c {JAVA_ESCAPE} class Escape {{ void m() {{ try {{ x(); }} catch (Exception e) {{}} }} }}\n",
    "ls.js": HIDDEN_JS.format(LS),
    "ps.js": HIDDEN_JS.format(PS),
    "ls.ts": HIDDEN_JS.format(LS),
    "ps.tsx": HIDDEN_JS.format(PS),
    "ls.yml": HIDDEN_YAML.format(LS),
    "nel.yml": HIDDEN_YAML.format(NEL),
    "ff.css": "/* nocheck: coding.structural -- r */\fa { }\n",
}
LEGAL = {
    "escaped.js": 'export const s = "a\\u2028b";\n',
    "nel.js": f'export const s = "a{NEL}b";\n',
    "ls.py": f's = "a{LS}b"\n',
    "nel.css": f'a::before {{ content: "{NEL}"; }}\n',
    "Even.java": f'class Even {{ String s = "\\{JAVA_ESCAPE}"; }}\n',
    "ls.rs": f"// c{LS}fn main() {{}}\n",
}
CR_ONLY = {
    "nocheck.js": "// nocheck: coding.structural -- r\rfunction f() {\r  debugger;\r  try { x(); } catch (e) {}\r}\r",
    "group.js": "// nocheck: clean -- r\r// narration\rconst p = process.env.PORT || 8080;\rfunction g(a = 5) { return a; }\r",
    "heredoc.php": "<?php // nocheck: coding -- r\r$x = <<<EOT\r?>\rEOT;\rvar_dump($x);\r",
}
REGION = [
    "// nocheck: coding.parse-incomplete -- grammar gap",
    "function run( {",
    "  debugger;",
    "  try { go(); } catch (e) {}",
    "  eval(input);",
    "}",
    "",
]


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


def test_ignore_parse_gap_read_from_base(target):
    target.write("a.py", "x = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    target.write("src/gap.js", GAP_SOURCE)
    target.write(IGNORE, f'- rule: {PARSE_GAP}\n  paths: ["src/"]\n  reason: self exempted\n')
    target.commit()
    result = target.check("--base", "main", "--json")
    assert result.returncode == 1
    assert PARSE_GAP in rule_ids(result)
    assert report(result)["ignored"] == []
    target.git("checkout", "-q", "main")
    target.write(IGNORE, f'- rule: {PARSE_GAP}\n  paths: ["src/"]\n  reason: reviewed on main\n')
    target.commit()
    target.git("checkout", "-q", "-b", "second")
    target.write("src/gap.js", GAP_SOURCE)
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
    assert rule_ids(result) == ["clean.unused-nocheck", EVAL]


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


def found_by_path(result) -> dict:
    found = {}
    for item in report(result)["findings"]:
        found.setdefault(item["path"], []).append((item["rule"], item["line"]))
    return {path: sorted(items) for path, items in found.items()}


def test_a_lone_carriage_return_fails_closed_under_any_nocheck(target, mode):
    target.write("seed.py", "x = 1\n")
    target.start_feature(mode)
    for name, text in CR_ONLY.items():
        target.write(name, text)
    target.advance(mode)
    result = target.judge(mode, "--json")
    assert result.returncode == 1
    assert {path: (LINE_BREAK, 1) in items for path, items in found_by_path(result).items()} == dict.fromkeys(
        CR_ONLY, True
    )


def test_a_separator_line_break_fails_closed_under_any_nocheck(target, mode):
    target.write("seed.py", "x = 1\n")
    target.start_feature(mode)
    for name, text in {**SEPARATED, **LEGAL}.items():
        target.write(name, text)
    target.advance(mode)
    result = target.judge(mode, "--json")
    assert result.returncode == 1
    found = found_by_path(result)
    assert {path: line for path, items in found.items() for rule, line in items if rule == LINE_BREAK} == dict.fromkeys(
        SEPARATED, 1
    )


def test_crlf_lines_count_as_lf_lines_and_a_lone_cr_is_a_finding(target):
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.write("lf.js", "\n".join(REGION))
    target.write("crlf.js", "\r\n".join(REGION))
    target.write("cr.js", "\r".join(REGION))
    target.stage()
    found = found_by_path(target.check("--staged", "--json"))
    assert found["crlf.js"] == found["lf.js"]
    assert LINE_BREAK not in [rule for rule, _ in found["lf.js"]]
    assert (LINE_BREAK, 1) in found["cr.js"]


def test_a_stray_carriage_return_moves_no_nocheck_onto_the_next_line(target):
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.write(
        "shift.js",
        "const a = 1; // x\ry\nfunction f() {\n  // nocheck: coding.structural -- r\n  debugger;\n}\n",
    )
    target.stage()
    result = target.check("--staged", "--json")
    assert result.returncode == 1
    found = found_by_path(result)["shift.js"]
    assert (STRUCTURAL, 4) in found
    assert ("clean.unused-nocheck", 3) in found
    assert (LINE_BREAK, 1) in found
    assert report(result)["nocheck"] == []
