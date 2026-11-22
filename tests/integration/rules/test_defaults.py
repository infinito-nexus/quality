import pytest

from quality.adapters.astgrep import reported_rows
from tests.integration.support import catalogue, findings_of_rule, report

DEFAULTS_FIXTURES = {
    "app.py": (
        "import os\n\n\ndef old(a=1):\n    return a\n"
        '\n\ndef new(a, b=2, *, c=None, d=False, e="", f=[], g=()):\n'
        "    return a, b, c, d, e, f, g\n"
        '\n\nport = os.environ.get("PORT", "8080")\n'
        'home = os.getenv("HOME", "")\n'
        'name = getattr(os, "name", "posix")\n'
        "# the operator picked three retries for the flaky host\n"
        'retries = os.getenv("RETRIES", default="3")\n'
        'label = os.environ.get("LABEL") or "none"\n'
        'parser.add_argument("--level", default="info")\n'
        'parser.add_argument("--flag", default=False)\n'
        'size = {}.get("size", 0)\n'
        "pick = lambda x=None, y=5: x\n"
    ),
    "run.sh": 'echo "${OLD:-1}"\n: "${NEW:=fallback}"\necho "${SET:?SET is required} ${BLANK:-} ${QUOTED:-""}"\n',
    "Makefile": "OLD ?= 1\nNEW ?= 2\nEMPTY ?=\nrun: ; echo $${PORT:-80} # port 80 is the fixed listen port\n",
    "lib.rs": (
        "fn main() {}\n"
        "fn port(v: Option<u16>) -> u16 { v.unwrap_or(8080) }\n"
        "fn name(v: Option<String>) -> String { v.unwrap_or_default() }\n"
        "fn flag(v: Option<bool>) -> bool { v.unwrap_or(false) }\n"
        "#[serde(default)]\n"
        "// v.unwrap_or(1) in a comment is no code\n"
    ),
    "schema.sql": (
        "CREATE TABLE t (id INT DEFAULT 0);\n"
        "CREATE TABLE u (n INT DEFAULT 5, note TEXT DEFAULT NULL, s TEXT DEFAULT '');\n"
        "INSERT INTO u DEFAULT VALUES; -- DEFAULT 7 in a comment\n"
    ),
    "main.tf": (
        'variable "old" {\n  default = 1\n}\n'
        'variable "port" {\n  default = 8080\n}\n'
        'variable "tags" {\n  default = {}\n}\n'
        "locals {\n  default = 3\n}\n"
    ),
    "web.ts": (
        "export function connect(host: string, port = 8080, tls = false) {\n"
        '  const { retries = 3, name = "" } = options;\n'
        "  const timeout = options.timeout ?? 30;\n"
        '  const label = options.label || "anon";\n'
        "  const flag = options.flag || other;\n"
        "  const empty = options.empty ?? null;\n"
        "  return [host, port, tls, retries, name, timeout, label, flag, empty];\n"
        "}\n"
        "const handler = (event, limit = 10) => limit;\n"
    ),
    "site.yml": (
        'port: "{{ app_port | default(8080) }}"\n'
        "user: \"{{ app_user | default('') }}\"\n"
        "home: \"{{ lookup('env', 'HOME') | default('') }}\"\n"
        'list: "{{ items | default([]) }}"\n'
        'cmd: "echo ${PORT:-80} ${EMPTY:-}"\n'
    ),
    "Store.java": (
        "class Store {\n"
        '  int port(java.util.Map<String, Integer> m) { return m.getOrDefault("port", 8080); }\n'
        '  Integer none(java.util.Map<String, Integer> m) { return m.getOrDefault("x", null); }\n'
        "}\n"
    ),
    "Svc.cs": (
        "class Svc {\n"
        "  void Run(int retries = 3, string name = null) { }\n"
        '  string Host(string h) => h ?? "localhost";\n'
        "  string Must(string h) => h ?? throw new System.ArgumentNullException(nameof(h));\n"
        "}\n"
    ),
    "Dockerfile": "FROM debian\nARG PORT\nRUN echo ${PORT:-80}\n",
    "compose.yml.j2": (
        "services:\n  app:\n"
        '    image: "app:${TAG:-latest}"\n'
        "    user: \"{{ app_user | default('root') }}\"\n"
    ),
    "ok.py": (
        "import os\n\n\n"
        'def f(a=None, b=False, c="", d=(), *, e=b"", g=frozenset()):\n'
        "    return a, b, c, d, e, g\n\n\n"
        'x = os.environ.get("K", "") or []\n'
        'y = {}.get("k", None)\n'
        'z = getattr(os, "x", None)\n'
        'w = os.getenv("W", default=False)\n'
    ),
    "ok.sh": 'echo "${A:-} ${B:-""} ${C:=}"\n',
    "ok.yml": "a: \"{{ x | default(false) }} {{ y | default(None) }} {{ z | default('') }}\"\n",
    "ok.ts": "function f(a = null, b = undefined, c = '') { return a ?? null; }\n",
    "ok.js": 'const m = `user || "<none>" on host ?? "n/a" as ${user ?? ""}`;\n',
    "wrap.js": 'const n = check(\n  a,\n)\n  || "x";\nconst o = p ??\n  "y";\n',
    "subst.js": (
        "const url = `${process.env.URL ?? 'http://localhost'}/api`;\n"
        "const port = `${process.env.PORT || 8080}`;\n"
        'const m = `user ${f(x || "y")} on ${`${host ?? "n/a"}`}`;\n'
    ),
    "subst.ts": "export const url: string = `${process.env.URL ?? 'http://localhost'}/api`;\n",
    "subst.tsx": "export const A = () => <a href={`${base || '/'}x`}>x</a>;\n",
    "extra.py": "def g(x=1):\n    return x\n",
    "tern.js": (
        "const page = {\n"
        "  getByText: (text) =>\n"
        '    text === "OpenID"\n'
        "      ? control(() => true, {\n"
        "          click: async () => {\n"
        "            state.url = `${ISSUER}/auth`;\n"
        "          },\n"
        "        })\n"
        "      : hidden,\n"
        "  getByLabel: (pattern) => pattern,\n"
        "};\n"
    ),
    "typed.ts": "class A {\n  m(a = 1): (x: number) => void { return; }\n}\n",
    "t.sh": "# the probe needs a fixed port\necho ${A:-b}\n",
    "t.ts": "x = y ?? 1;\n",
    "quoted.yml": (
        'msg: "see #docs {{ port | default(8080) }}"\n'
        "# {{ x | default(1) }}\n"
        'key: "a #b" # {{ y | default(2) }}\n'
        "note: 'it''s # {{ z | default(3) }}'\n"
        'json: {"msg":"see #docs {{ port | default(8080) }}"}\n'
        'url: "http://h/#/x"  # {{ x | default(1) }}\n'
        "sq: 'x' # it's {{ x | default(1) }}\n"
        'bs: "x\\\\" # {{ x | default(1) }}\n'
        "ap: \"it's\" # {{ x | default(1) }}\n"
        "cut: cut -d':' -f2 /etc/passwd  # {{ x | default(1) }}\n"
        "ifs: IFS=':' read -r a b <<< \"$x\"  # {{ x | default(1) }}\n"
        "awk: awk -F'\":\"' '{print $2}' f.json  # {{ x | default(1) }}\n"
        "when: item.split(':')[0] == 1  # {{ x | default(1) }}\n"
        "cut_sq: cut -d' ' -f1 /etc/hosts  # {{ x | default(1) }}\n"
        'cut_dq: cut -d" " -f1 /etc/hosts  # {{ x | default(1) }}\n'
        "ifs_sq: IFS=' ' read -r a b <<< \"$x\"  # {{ x | default(1) }}\n"
        "split_sq: item.split(' ')[0] == 1  # {{ x | default(1) }}\n"
        'split_dq: item.split(" ")[0] == 1  # {{ x | default(1) }}\n'
        'starts: out.stdout.startswith(" ")  # {{ x | default(1) }}\n'
        "join: x | join(', ') == y  # {{ x | default(1) }}\n"
        "era: music from the '90s  # {{ x | default(1) }}\n"
        'flow: {"a" :"b #x {{ x | default(1) }}"}\n'
        "lookup: lookup('env', 'CI') | length > 0  # locally: ci | default(false)\n"
        "esc_sq: '{{ item.name | default('''') }}'\n"
        'esc_dq: "{{ item.name | default(\\"\\") }}"\n'
        "dollar: echo ${A:-x  # see }\n"
        "--- 'a # {{ x | default(1) }}'\n"
        '--- [a, "b # {{ x | default(1) }}"]\n'
    ),
}
DEFAULTS_HITS = {
    "Dockerfile": [3],
    "Makefile": [1, 2, 4],
    "Store.java": [2],
    "Svc.cs": [2, 3],
    "app.py": [4, 8, 12, 14, 16, 17, 18, 20, 21],
    "compose.yml.j2": [3, 4],
    "extra.py": [1],
    "lib.rs": [2, 3, 5],
    "main.tf": [2, 5],
    "run.sh": [1, 2],
    "schema.sql": [1, 2],
    "quoted.yml": [1, 4, 5, 22, 27, 28],
    "site.yml": [1, 3, 5],
    "subst.js": [1, 2, 3],
    "subst.ts": [1],
    "subst.tsx": [1],
    "t.sh": [2],
    "t.ts": [1],
    "typed.ts": [2],
    "web.ts": [1, 2, 3, 4, 9],
    "wrap.js": [4, 5],
}


def test_defaults_parity(target):
    for name, text in DEFAULTS_FIXTURES.items():
        target.write(name, text)
    target.commit()
    found = set(findings_of_rule(target.check("--all", "--json"), "clean.default-value"))
    assert found == {(name, line) for name, lines in DEFAULTS_HITS.items() for line in lines}


DEFAULT_VALUE = "clean.default-value"
AVATAR_DEFAULTS = (
    "export const port = Number(process.env.AVATAR_PORT || 8765);\n"
    "export const host = process.env.AVATAR_HOST || '127.0.0.1';\n"
    "export const origin = process.env.AVATAR_PUBLIC_ORIGIN || `http://${host}:${port}`;\n"
    "export function neutralFrame(sequence = 0, timestampMs = 0) {\n"
    "  return {sequence, timestampMs};\n"
    "}\n"
    "export class TimingWindow {\n"
    "  constructor(limit = 10000) {\n"
    "    this.limit = limit;\n"
    "  }\n"
    "}\n"
)
AVATAR_REQUIRED = (
    "export function serverPort(env) {\n"
    "  if (typeof env.AVATAR_PORT !== 'string') throw new Error('AVATAR_PORT must be set in the Avatar process environment');\n"
    "  return Number(env.AVATAR_PORT);\n"
    "}\n"
    "export function receivedAt(packet) {\n"
    "  return packet?.receivedAt ?? null;\n"
    "}\n"
    "export class LatestFrame {\n"
    "  frame(neutralFrame) {\n"
    "    return this.current || neutralFrame(0, 0);\n"
    "  }\n"
    "}\n"
)


def test_default_value_flags_the_old_avatar_shapes(target, mode):
    target.write("seed.py", "x = 1\n")
    target.start_feature(mode)
    target.write("renderer/defaults.mjs", AVATAR_DEFAULTS)
    target.write("renderer/required.mjs", AVATAR_REQUIRED)
    target.advance(mode)
    result = target.judge(mode, "--json")
    assert result.returncode == 1, result.stderr
    found = sorted(
        {(item["path"], item["line"], item["severity"]) for item in report(result)["findings"] if item["rule"] == DEFAULT_VALUE}
    )
    assert found == [("renderer/defaults.mjs", line, "medium") for line in (1, 2, 3, 4, 8)]
    summary = next(rule["summary"] for rule in catalogue() if rule["id"] == DEFAULT_VALUE)
    assert "fail early" in summary and "names the missing key and where to set it" in summary
    text = target.judge(mode).stdout.splitlines()
    for line in (1, 2, 3, 4, 8):
        assert f"renderer/defaults.mjs:{line}: {DEFAULT_VALUE} [medium] {summary}" in text


def test_default_value_takes_a_nocheck_never_a_plain_comment(target, mode):
    target.write("seed.py", "x = 1\n")
    target.start_feature(mode)
    default = "export const port = process.env.AVATAR_PORT || 8765;"
    target.write("commented.mjs", f"{default} // the renderer listens on 8765 on a laptop\n")
    target.write("waived.mjs", f"{default} // nocheck: {DEFAULT_VALUE} -- the local renderer port\n")
    target.advance(mode)
    result = target.judge(mode, "--json")
    assert result.returncode == 1, result.stderr
    assert findings_of_rule(result, DEFAULT_VALUE) == [("commented.mjs", 1)]
    assert report(result)["nocheck"] == [{"path": "waived.mjs", "line": 1, "rule": DEFAULT_VALUE}]


EMBEDDED_SHELL = r"""sh -c 'echo ${ONE:-1}'
dexec "$node" sh -c 'pid=$(cat /run/app.pid)
[ "${pid:-0}" -gt 0 ] || exit 0
echo "${EMPTY:-}" # ${NOTE:-1}
done'
bash -euc 'x=${TWO:-2}' _ arg
eval 'y=${THREE:=3}'
trap 'rm -f "${LOCK:-app.lock}"' EXIT
echo sh -c 'echo ${PRINTED:-1}'
printf '%s\n' '${LITERAL:-1}'
cat > stub <<STUB
#!/bin/sh
printf '%s' "\${OPTS:-{\\}}" "\${SET:?SET is required}"
echo "\${BLANK:-}"
STUB
cat > quoted <<'EOF'
#!/usr/bin/env bash
echo "${FOUR:-4}" "\${ESCAPED:-1}"
EOF
cat > notes.txt <<EOF
\${TEXT:-1}
EOF
cat > data.txt <<'EOF'
${DATA:-1}
EOF
"""
EMBEDDED_HITS = [1, 3, 6, 7, 8, 13, 18]


def test_default_value_reads_the_script_a_shell_runs_one_level_down(target):
    target.write("embedded.sh", EMBEDDED_SHELL)
    target.commit()
    found = findings_of_rule(target.check("--all", "--json"), DEFAULT_VALUE)
    assert found == [("embedded.sh", line) for line in EMBEDDED_HITS]


ROWS = r"(?m)^[^#\n]*?\$\{\w+:-(?!\})"


def astgrep_match(text: str, line: int, metadata: dict) -> dict:
    return {
        "ruleId": "clean.default-value/embedded",
        "text": text,
        "range": {"start": {"line": line, "column": 4}, "end": {"line": line + text.count("\n"), "column": 1}},
        "metadata": metadata,
    }


@pytest.mark.parametrize(
    ("text", "rows"),
    [
        ("'a\nb=${B:-1}\nc'", [11]),
        ("'${A:-1}\nb\n${C:-3} ${D:-4}'", [10, 12]),
        ("'a # ${A:-1}\n${B:-}\nc'", []),
    ],
)
def test_a_rows_pattern_reports_the_lines_it_matches_inside_the_text(text, rows):
    assert reported_rows(astgrep_match(text, 9, {"rows": ROWS})) == rows


def test_without_a_rows_pattern_the_first_line_is_reported():
    assert reported_rows(astgrep_match("'a\nb=${B:-1}\nc'", 9, {})) == [10]
