import pytest

from tests.integration.support import findings_of_rule, report

PARSE_ERRORS = {
    "bad.json": ('{"a": }\n', [1]),
    "open.json": ('{"a": 1\n', [2]),
    "bad.yml": ("a: [1, 2\nb: 3\n", [2]),
    "alias.yml": ("a: *missing\n", [1]),
    "bad.py": ("def f(:\n    pass\n", [1, 1]),
}
GRAMMAR_GAPS = {
    "variance.ts": "interface I<in out T> {\n  f(x: T): T;\n}\n",
    "safe.rs": 'unsafe extern "C" {\n    pub safe fn sqrt(x: f64) -> f64;\n}\n',
    "range.css": "@media (width >= 600px) {\n  a {\n    color: red;\n  }\n}\n",
    "layer.css": "@import url(x.css) layer(base);\n",
    "bitint.c": "_BitInt(7) y;\n",
    "split.c": "int f(void)\n#ifdef A\n{\n#else\n{\n#endif\n  return 0;\n}\n",
    "open.js": "if (x) {\n  y();\n",
}


def test_only_full_parsers_report_syntax_errors(target):
    for name, (source, _) in PARSE_ERRORS.items():
        target.write(name, source)
    for name, source in GRAMMAR_GAPS.items():
        target.write(name, source)
    target.write("good.json", '{"a": [1, ""]}\n')
    target.write("vault.yml", "a: !vault |\n  x\n")
    target.write("good.ts", "const x: number = 1;\nconst s = `${x}`;\n")
    target.write("good.sh", "#!/bin/bash\ncat <<EOF\nEOF\nif true; then echo hi; fi\n")
    target.commit()
    result = target.check("--all", "--json")
    found = findings_of_rule(result, "coding.syntax-error")
    assert found == sorted((name, line) for name, (_, lines) in PARSE_ERRORS.items() for line in lines)
    assert report(result)["parse_incomplete"] == sorted({*GRAMMAR_GAPS, *PARSE_ERRORS} - {"alias.yml"})
    assert "parse incomplete: variance.ts" in target.check("--all").stdout.splitlines()


EVASIONS = {
    "app.js": "export function run( {\n  debugger;\n  eval(location.hash.slice(1));\n}\n",
    "io.c": "void f(char *b) { gets(b) }\n",
    "boot.lua": "function f(\n  loadstring(io.read())()\nend\n",
    "run.php": "<?php\nif ($x) {\n  eval($_GET['x']);\n",
}


def test_unreadable_changed_file_is_a_finding(target, mode):
    target.write("old.js", "export function old( {\n}\n")
    target.start_feature(mode)
    for name, source in EVASIONS.items():
        target.write(name, source)
    target.write("gap.ts", "interface I<in out T> { // nocheck: coding.parse-incomplete -- TypeScript 4.7 variance\n}\n")
    target.write("ok.js", "export const a = 1;\n")
    target.advance(mode)
    result = target.judge(mode, "--json")
    assert result.returncode == 1
    assert sorted({path for path, _ in findings_of_rule(result, "coding.parse-incomplete")}) == sorted(EVASIONS)
    assert ("gap.ts", 1) in [(item["path"], item["line"]) for item in report(result)["nocheck"]]
    target.commit()
    whole = target.check("--all", "--json")
    assert findings_of_rule(whole, "coding.parse-incomplete") == []
    assert report(whole)["parse_incomplete"] == sorted([*EVASIONS, "gap.ts", "old.js"])


def test_nocheck_waives_one_line_of_an_unreadable_region(target, mode):
    target.start_feature(mode)
    body = "".join(f"  step{n}();\n" for n in range(30))
    target.write(
        "hide.js",
        "export function run( { // nocheck: coding.parse-incomplete -- grammar gap\n"
        + body
        + "  debugger;\n  try { a(); } catch (e) {}\n}\n",
    )
    target.advance(mode)
    result = target.judge(mode, "--json")
    assert result.returncode == 1
    lines = [line for _, line in findings_of_rule(result, "coding.parse-incomplete")]
    assert 1 not in lines
    assert {32, 33} <= set(lines)
    assert [(item["path"], item["line"]) for item in report(result)["nocheck"]] == [("hide.js", 1)]


def test_missing_token_spans_its_top_level_item(target, mode):
    target.start_feature(mode)
    note = " // nocheck: coding.parse-incomplete -- grammar gap"
    target.write("item.js", "const a = 1;\nfunction f() {\n  return (4 + 5;" + note + "\n  g();\n}\nconst c = 6;\n")
    target.write("item.c", "int a = 1;\nint f(void) {\n  g();\n  return 1" + note + "\n}\nint c = 6;\n")
    target.write("plain.js", "const a = (1 + 2;\nconst b = 3;\nconst c = 4;\n")
    target.advance(mode)
    result = target.judge(mode, "--json")
    assert result.returncode == 1
    assert findings_of_rule(result, "coding.parse-incomplete") == [
        ("item.c", 5),
        ("item.js", 4),
        ("item.js", 5),
        ("plain.js", 1),
    ]


VALID = {
    "page.html": '<!doctype html>\n<html>\n<head>\n<script src="app.js"></script>\n</head>\n<body><p>x</p></body>\n</html>\n',
    "style.html": "<html>\n<head><style></style></head>\n<body><textarea></textarea></body>\n</html>\n",
    "raw.go": 'package main\n\nvar a = ``\nvar b = ""\n\nfunc main() {}\n',
    "str.lua": "local a = ''\nlocal b = [[]]\nprint(a, b)\n",
    "lib.rs": "pub fn f() -> &'static str {\n    let _a = \"\";\n    r\"\"\n}\n",
    "tag.php": "<?php\necho 1;\n?>\n<p>x</p>\n<?php echo 2; ?>\n",
    "page.php": "<!doctype html>\n<p>x</p>\n<?php echo 1; ?>\n<p>y</p>\n",
    "markup.php": '<!doctype html>\n<html lang="en"><head><meta charset="utf-8"><title>A</title></head></html>\n',
    "call.php": "<?php get_header(); ?>\n<main>\n<?php the_content(); ?>\n</main>\n<?php get_footer(); ?>\n",
    "layout.php": (
        '<!doctype html>\n<html lang="<?php echo esc_attr($lang); ?>">\n<body>\n<?php if ($user): ?>\n'
        '  <nav><a href="/">Home</a></nav>\n<?php else: ?>\n  <a href="/login">Login</a>\n<?php endif; ?>\n</body>\n'
    ),
    "loop.php": (
        "<?php while (have_posts()) : the_post(); ?>\n  <article id=\"post-<?php the_ID(); ?>\">\n"
        "    <td><?= $row['a'] ?></td>\n  </article>\n<?php endwhile; ?>\n"
    ),
    "script.php": (
        "<?php $v = 1; ?>\n<script>\nvar data = <?php echo wp_json_encode($v); ?>;\n"
        "var url = '<?php echo esc_url($v); ?>';\n</script>\n"
    ),
    "inline.php": (
        "<?php $c = get_theme_mod('color'); ?>\n<style>\n.a { color: <?php echo esc_attr($c); ?>; }\n"
        "/* header */\n.b { background: url('<?php echo esc_url($img); ?>'); }\n</style>\n"
    ),
    "eot.php": "<?php\n$a = <<<EOT\nx\nEOT?>\n<p>y</p>\n",
    "list.php": "<?php $a = 1; $b = 2; ?>\n<p><?= $a, $b ?></p>\n<?= $a, $b ?>\n",
    "switch.php": "<?php switch ($x): ?>\n<?php case 1: ?>\n<p>one</p>\n<?php endswitch; ?>\n",
    "tpl.js": "export const a = ``;\nconst b = 1\n;[b].forEach(String)\n",
    "jsx.tsx": "export const A = () => <div></div>;\n",
    "def.c": "#define FLAG\n#ifdef FLAG\nint x;\n#endif\nint main(void) { return 0; }\n",
    "doc.rb": "x = <<~EOS\nEOS\nputs x, ''\n",
    "empty.css": 'a::before { content: ""; }\n',
    "main.tf": 'locals {\n  a = ""\n  b = <<EOT\nEOT\n}\n',
    "s.nix": "{ a = \"\"; b = ''''; }\n",
    "Main.kt": 'fun main() {\n    println("")\n}\n',
    "Main.java": 'class Main {\n  String a = "";\n  String b = """\n    """;\n}\n',
}


def test_valid_code_parses_in_full(target):
    for name, source in VALID.items():
        target.write(name, source)
    target.commit()
    assert report(target.check("--all", "--json"))["parse_incomplete"] == []


HIDDEN_PHP = {
    "tag.php": ("<?php\n$x = '?>'; var_dump($x); // <?\n", 2),
    "dq.php": ('<?php $v = 1; ?>\n<script>\nvar y = "<?php $s = "?>"; var_dump($s); $t = "<?"; ?>";\n</script>\n', 3),
    "sq.php": ("<?php $v = 1; ?>\n<script>\nvar u = '<?php $s = '?>'; var_dump($s); $t = '<?'; ?>';\n</script>\n", 3),
    "dq_lines.php": ('<?php $v = 1; ?>\n<script>\nvar y = "<?php\n$s = "?>";\nvar_dump($s);\n$t = "<?";\n?>";\n</script>\n', 5),
    "sq_lines.php": ("<?php $v = 1; ?>\n<script>\nvar u = '<?php\n$s = '?>';\nvar_dump($s);\n$t = '<?';\n?>';\n</script>\n", 5),
    "block.php": ("<?php $v = 1; ?>\n<!-- /* -->\n<?php $s = '*/ ?>'; var_dump($s); $t = '<?'; ?>\n", 3),
    "heredoc.php": ("<?php\n$s = <<<EOT\n?>\nEOT;\nvar_dump($s);\n", 5),
    "comment.php": ("<?php // c ?><?php var_dump($x);\n", 1),
    "echo.php": ("<p><?= var_dump($x) ?></p>\n", 1),
    "glued.php": ("<p><?=var_dump($x)?></p>\n", 1),
}


def test_closing_tag_hidden_in_php_code_keeps_the_code(target, mode):
    target.start_feature(mode)
    for name, (source, _) in HIDDEN_PHP.items():
        target.write(name, source)
    target.advance(mode)
    found = findings_of_rule(target.judge(mode, "--json"), "coding.structural")
    assert found == sorted((name, line) for name, (_, line) in HIDDEN_PHP.items())


def test_edit_to_an_unreadable_legacy_file_is_judged_absolutely(target, mode):
    target.write("a.css", "svg .a { fill: url(#hatch); }\n.b { color: red; }\n")
    target.start_feature(mode)
    target.write("a.css", "svg .a { fill: url(#hatch); }\n.b { color: red; }\n.c { color: blue; }\n")
    target.advance(mode)
    result = target.judge(mode, "--json")
    assert result.returncode == 1
    assert findings_of_rule(result, "coding.parse-incomplete") == [("a.css", 1)]


def test_path_entry_waives_an_unreadable_region(target, mode):
    target.write(".qualityignore.yml", "- rule: coding.parse-incomplete\n  paths: [gap.js]\n  reason: grammar gap\n")
    target.start_feature(mode)
    target.write("gap.js", "export function run( {\n  a();\n  b();\n}\n")
    target.advance(mode)
    assert target.judge(mode).returncode == 0
    target.commit()
    whole = report(target.check("--all", "--json"))
    assert whole["findings"] == []
    assert whole["parse_incomplete"] == ["gap.js"]


UNUSED = {
    "fake.py": "# nocheck: clean.comment -- loop over every user and send the newsletter mail\nx = 1\n",
    "other.py": "x = 1  # nocheck: security.temp-path -- the loop retries three times\n",
}


def test_unused_nocheck_is_a_finding(target, mode):
    target.write("legacy.py", "# nocheck: clean.comment -- an old one\nx = 1\n")
    target.start_feature(mode)
    for name, source in UNUSED.items():
        target.write(name, source)
    target.write("legacy.py", "# nocheck: clean.comment -- an old one\nx = 2\n")
    target.write("used.py", "breakpoint()  # nocheck: coding.structural -- fixture\n")
    target.write("gap.ts", "interface I<in out T> { // nocheck: coding.parse-incomplete -- grammar gap\n}\n")
    target.advance(mode)
    result = target.judge(mode, "--json")
    assert result.returncode == 1
    assert findings_of_rule(result, "clean.unused-nocheck") == [("fake.py", 1), ("other.py", 1)]
    target.commit()
    whole = target.check("--all", "--json")
    assert findings_of_rule(whole, "clean.unused-nocheck") == [("fake.py", 1), ("legacy.py", 1), ("other.py", 1)]


NOT_RUN = {
    "dup.js": "export const a = 1; // nocheck: clean.clones -- each test spells out its own request\n",
    "kind.py": "x = 1  # nocheck: coding.shell-lint -- the loop retries three times\n",
    "group.js": "export const b = 1; // nocheck: clean -- each test spells out its own request\n",
    "group.ts": "export const c = 1; // nocheck: security -- vetted by the semgrep rule set\n",
}
DEEP_TIER_NOCHECKS = [("dup.js", 1), ("group.js", 1), ("group.ts", 1)]


@pytest.mark.deep
def test_nocheck_for_a_rule_that_did_not_run_is_not_judged(target, mode):
    target.start_feature(mode)
    for name, source in NOT_RUN.items():
        target.write(name, source)
    target.advance(mode)
    judged = [("kind.py", 1), *(DEEP_TIER_NOCHECKS if mode == "base" else [])]
    assert findings_of_rule(target.judge(mode, "--json"), "clean.unused-nocheck") == sorted(judged)


def test_old_nocheck_under_an_old_path_entry_stays_old(target, mode):
    target.write(".qualityignore.yml", "- rule: clean.default-value\n  paths: [a.py]\n  reason: legacy accessors\n")
    source = "def f(d):\n    return d.get('k', 1)  # nocheck: clean.default-value -- the key is optional\n"
    target.write("a.py", source)
    target.start_feature(mode)
    target.write("a.py", source + "\n\ndef g():\n    return 2\n")
    target.advance(mode)
    result = target.judge(mode, "--json")
    assert findings_of_rule(result, "clean.unused-nocheck") == []


def test_old_hard_rule_nocheck_stays_old(target, mode):
    source = "X = eval(input())  # nocheck: security.eval-exec -- an old one\n"
    target.write("a.py", source)
    target.start_feature(mode)
    target.write("a.py", source + "Y = 2\n")
    target.advance(mode)
    assert findings_of_rule(target.judge(mode, "--json"), "clean.unused-nocheck") == []
