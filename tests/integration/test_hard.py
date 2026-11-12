import base64
import gzip
import io
import json
import os
import zipfile

import pytest

from quality.adapters import Collector, Runtime
from quality.adapters.base import Bound
from quality.environment import tool_environment
from quality.ruledata import load
from quality.snapshot import Snapshot
from tests.integration.support import (
    AUTHOR_EMAIL,
    AUTHOR_NAME,
    RAW_GITLEAKS,
    RULES,
    SECRET,
    SECRET_ENV_LINE,
    add_rules,
    catalogue,
    edit_yaml,
    raw_tool,
    report,
    rule_ids,
    rules_copy,
    rules_without_pending,
)

SECRET_RULE = "security.secret"
EVAL_RULE = "security.eval-exec"
PRAGMA_RULE = "clean.tool-pragma"
OVERSIZED_RULE = "security.oversized-code"
BINARY_RULE = "security.binary-code"
DOCKERFILE_RULE = "coding.dockerfile"
BINARY_PDF = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n\x00"
BINARY_ELF = b"\x7fELF\x02\x01\x01\x00\x00\x00\n"
# Exception: the value is split, so this repository's own secret scan passes.
BITBAKE_RECIPE = b'SUMMARY = "x"\nSRCREV_tokenizer = "' + b'9f8e7d6c5b4a39281706f5e4d3c2b1a098765432"\n'
K8S_SECRET = (
    b"apiVersion: v1\nkind: Secret\nmetadata:\n  name: db\ndata:\n"
    b"  dbconn: cG9zdGdyZXM6Ly9hZG1pbjpodW50ZXIyQGRiLmludGVybmFsOjU0MzIvcHJvZA==\n"
)
K8S_LINE = 2
SECRET_LINE = f'TOKEN = "{SECRET}"\n'
COMMIT_MESSAGE_CANARY = "QualityMessageCanary"
ALLOWLISTED_NAMES = [
    "creds.pdf",
    "keys.v2",
    ".gitleaks.toml",
    "go.sum",
    "package-lock.json",
    "logo.svg",
    "secrets.bin",
    "gradlew",
    "bootstrap-config.js",
    "verification-metadata.xml",
]


def test_hard_new_secret(target):
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.write("a.py", SECRET_LINE)
    target.stage()
    result = target.check("--staged", "--json")
    assert result.returncode == 1
    assert SECRET_RULE in rule_ids(result)


def test_hard_legacy_touched(target):
    target.write("a.py", SECRET_LINE)
    target.commit()
    target.write("a.py", SECRET_LINE + "x = 1\n")
    target.stage()
    result = target.check("--staged", "--json")
    assert result.returncode == 1
    assert SECRET_RULE in rule_ids(result)


def test_hard_legacy_untouched(target):
    target.write("a.py", SECRET_LINE)
    target.write("b.py", "x = 1\n")
    target.commit()
    target.write("b.py", "x = 2\n")
    target.stage()
    assert target.check("--staged").returncode == 0
    assert target.check("--all").returncode == 1


def test_hard_secret_in_range(target):
    target.write("a.py", "x = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    target.write("a.py", SECRET_LINE)
    added = target.commit(COMMIT_MESSAGE_CANARY)
    target.write("a.py", "x = 1\n")
    target.commit()
    result = target.check("--base", "main", "--json")
    assert result.returncode == 1
    findings = report(result)["findings"]
    assert [(item["rule"], item["path"], item["line"], item["commit"]) for item in findings] == [
        (SECRET_RULE, "a.py", 1, added)
    ]


@pytest.mark.parametrize(
    ("name", "source"),
    [
        (".env", SECRET_ENV_LINE),
        ("deploy/values.yml", f"github:\n  token: {SECRET}\n"),
        ("node_modules/pkg/index.js", SECRET_LINE),
        ("venv/lib/settings.txt", SECRET_ENV_LINE),
        *[
            (name, f'{{"env": "{SECRET_ENV_LINE.strip()}"}}\n' if name.endswith(".json") else SECRET_ENV_LINE)
            for name in ALLOWLISTED_NAMES
        ],
    ],
    ids=["env", "yml", "node-modules", "venv", *ALLOWLISTED_NAMES],
)
def test_secret_rule_binds_every_tracked_file(target, name, source):
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.write(name, source)
    target.stage()
    result = target.check("--staged", "--json")
    assert result.returncode == 1, result.stderr
    assert [(item["rule"], item["path"]) for item in report(result)["findings"]] == [
        (SECRET_RULE, name)
    ]


@pytest.mark.parametrize(
    ("name", "data", "line"),
    [
        ("infra/main.tf", b'resource "x" "y" {\n  password = "s3cr3tPw9q"\n}\n', 2),
        ("certs/key.p12", b"\x30\x82\x01\x00 pkcs12 body", None),
        ("k8s/gitleaks.toml.yaml", K8S_SECRET, K8S_LINE),
        ("certs/gitleaks.toml.pfx", b"\x30\x82\x01\x00 pkcs12 body", None),
        (
            "infra/verification-metadata.xml.tf",
            b'resource "x" "y" {\n  password = "s3cr3tPw9q"\n}\n',
            2,
        ),
    ],
    ids=["terraform", "pkcs12", "k8s-allowlisted-stem", "pfx-allowlisted-stem", "tf-allowlisted-stem"],
)
def test_secret_path_rules_keep_working(target, name, data, line):
    target.write("seed.py", "x = 1\n")
    target.commit()
    (target.path / name).parent.mkdir(parents=True)
    (target.path / name).write_bytes(data)
    target.stage()
    result = target.check("--staged", "--json")
    assert result.returncode == 1, result.stderr
    findings = report(result)["findings"]
    assert [(item["rule"], item["path"], item["line"]) for item in findings] == [
        (SECRET_RULE, name, line)
    ]


def test_secret_scanner_names_binary_content_unchecked(target, tmp_path):
    reduced = rules_without_pending(tmp_path / "rules")
    target.write("seed.py", "x = 1\n")
    target.commit()
    secret = f"\n{SECRET_ENV_LINE}".encode()
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("a.txt", secret)
    samples = {
        "doc.pdf": BINARY_PDF + secret,
        "bundle.zip": archive.getvalue(),
        "packed.gz": gzip.compress(secret),
        "tool.bin": BINARY_ELF + secret,
    }
    for name, data in samples.items():
        (target.path / name).write_bytes(data)
    target.stage()
    for mode_flags in (("--staged",), ("--all", "--rules", str(reduced))):
        result = target.check(*mode_flags, "--json")
        assert result.returncode == 0, result.stderr
        assert report(result)["unchecked"] == sorted(samples)
    text = target.check("--staged").stdout
    assert "unchecked: doc.pdf holds binary content, which no text rule can vouch for" in text


def test_text_behind_binary_magic_is_scanned(target):
    target.write("seed.py", "x = 1\n")
    target.commit()
    samples = {
        ".env.production": b"%!PS-Adobe-3.0\n" + SECRET_ENV_LINE.encode(),
        "app.properties": b"MZ=1\n" + SECRET_ENV_LINE.encode(),
        "deploy.ps1": f"\N{ZERO WIDTH NO-BREAK SPACE}x = 1\r\n{SECRET_ENV_LINE}".encode("utf-16-le"),
        "countries": b"MZ Mozambique\nNA Namibia\n",
        "pkg/db.py": b"SQLiteStore = None\n",
    }
    for name, data in samples.items():
        (target.path / name).parent.mkdir(parents=True, exist_ok=True)
        (target.path / name).write_bytes(data)
    target.stage()
    result = target.check("--staged", "--json")
    assert result.returncode == 1, result.stderr
    document = report(result)
    found = [(item["rule"], item["path"], item["line"]) for item in document["findings"]]
    assert [finding for finding in found if finding[0].startswith("security.")] == [
        (SECRET_RULE, ".env.production", 2),
        (SECRET_RULE, "app.properties", 2),
        (SECRET_RULE, "deploy.ps1", 2),
    ]
    assert document["unchecked"] == []


def test_secret_across_a_gitleaks_window_is_found(target):
    target.write("seed.py", "x = 1\n")
    target.commit()
    split = "x" * 124965 + SECRET + "x" * 5000 + "\n"
    lines = "".join(f"row {number} {'y' * 90}\n" for number in range(1, 3000))
    target.write("dist/app.js", split)
    target.write("dist/rows.txt", lines + SECRET_ENV_LINE)
    target.stage()
    result = target.check("--staged", "--json")
    assert result.returncode == 1, result.stderr
    findings = report(result)["findings"]
    assert [(item["rule"], item["path"], item["line"]) for item in findings] == [
        (SECRET_RULE, "dist/app.js", 1),
        (SECRET_RULE, "dist/rows.txt", 3000),
    ]


def magic_at(offset: int) -> bytes:
    body = bytearray((b"z" * 99 + b"\n") * 2500)
    body[offset : offset + 4] = b"DICM"
    body[120000:120000] = b"\n" + SECRET_ENV_LINE.encode()
    return bytes(body)


def deep_magic_samples() -> dict:
    secret = SECRET_ENV_LINE.encode()
    return {
        "dcm.yml": b"#" + b"a" * 126 + b"DICM\n" + secret,
        "notes.txt": b"#" + b"a" * 255 + b"ustar\n" + secret,
        "iso.md": (b"y" * 99 + b"\n") * 327 + b"y" * 68 + b"CD001\n" + secret,
        "code.py": b"#" + b"a" * 126 + b"DICM\n" + SECRET_LINE.encode(),
        "big.txt": magic_at(75126),
    }


def exact_magic_samples() -> dict:
    secret = SECRET_ENV_LINE.encode()
    return {
        "exact/dcm.yml": b"#" + b"a" * 127 + b"DICM\n" + secret,
        "exact/notes.txt": b"#" + b"a" * 256 + b"ustar\n" + secret,
        "exact/iso.md": (b"y" * 99 + b"\n") * 327 + b"y" * 69 + b"CD001\n" + secret,
        "exact/shift127.txt": magic_at(75127),
        "exact/shift128.txt": magic_at(75128),
    }


def planted_line(data: bytes) -> int:
    return data[: data.index(SECRET.encode())].count(b"\n") + 1


def filler(char: bytes, size: int) -> bytes:
    rows = (char * 99 + b"\n") * (size // 100)
    return rows + char * (size - len(rows))


def edge_samples() -> dict:
    secret = SECRET_ENV_LINE.encode()
    samples = {"size100001.txt": filler(b"q", 100_001 - len(secret)) + secret}
    for cut in (99_999, 174_998):
        start = cut - 33
        samples[f"cut{cut}.txt"] = filler(b"w", start - 1) + b"\n" + secret + filler(b"w", 30_000)
    return samples


def private_key(prefix: str, repeats: int) -> bytes:
    body = base64.b64encode(bytes(range(256)) * repeats).decode()
    rows = "\n".join(body[at : at + 64] for at in range(0, len(body), 64))
    key = f"{prefix}-----BEGIN RSA PRIVATE {'KEY'}-----\n{rows}\n-----END RSA PRIVATE {'KEY'}-----\n"
    return key.encode()


def long_key() -> bytes:
    data = filler(b"k", 40_000) + private_key("", 88)
    return data + filler(b"k", 95_000 - len(data))


def key_behind_a_long_line() -> bytes:
    return filler(b"a", 68_900) + private_key("x" * 30_000 + " ", 6) + filler(b"b", 120_000)


def mount_line_cut_at(cut: int) -> bytes:
    line = b"RUN --mount=type=secret,id=x API_KEY=" + b"Zx8Kq2Lm9Vb4Nc7Tq1Wr\n"
    head = cut - len(b"RUN --mount=type=secret,")
    return filler(b"m", head - 1) + b"\n" + line + filler(b"m", 40_000)


def bypass_samples() -> dict:
    secret = SECRET_ENV_LINE.encode()
    return {
        "key/long.txt": long_key(),
        "key/long-line.txt": key_behind_a_long_line(),
        "bom/bom.env": b"\xff\xfe" + secret,
        "bom/bom.sh": b"\xfe\xff#!/bin/sh\n" + secret,
        "mount/42226.txt": mount_line_cut_at(42_226),
        "mount/74999.txt": mount_line_cut_at(74_999),
    }


def write_samples(target, samples: dict) -> None:
    for name, data in samples.items():
        (target.path / name).parent.mkdir(parents=True, exist_ok=True)
        (target.path / name).write_bytes(data)


def direct_findings(target, names) -> list:
    found = []
    for name in names:
        result = raw_tool(target.path, "gitleaks", "dir", *RAW_GITLEAKS, name)
        found += [(name, item["StartLine"], item["RuleID"]) for item in json.loads(result.stdout)]
    return sorted(found)


def adapter_findings(target, tmp_path, names) -> list:
    data = load(RULES)
    home = tmp_path / "home"
    home.mkdir()
    empty = tmp_path / "empty.yaml"
    empty.touch()
    path_value = os.environ["PATH"]
    environment = tool_environment(path_value, home, None)
    runtime = Runtime(path_value, environment, empty, target.path, False, {"work_dir": tmp_path})
    snapshot = Snapshot(target.path, dict.fromkeys(names), [], set(), data.kinds, set(), {})
    kinds = {name: snapshot.kinds_of(name) for name in names}
    bound = [Bound(binding, names, kinds) for binding in data.bindings()["gitleaks"]]
    hits = Collector(data, runtime).run_tool("gitleaks", bound, snapshot)
    assert snapshot.unread == {}
    return sorted((hit.path, hit.line, hit.message) for hit in hits)


def test_text_behind_deep_magic_is_read_at_least_as_gitleaks_direct_reads_it(target):
    target.write("seed.py", "x = 1\n")
    target.commit()
    samples = {**deep_magic_samples(), **exact_magic_samples()}
    write_samples(target, samples)
    target.stage()
    result = target.check("--staged", "--json")
    assert result.returncode == 1, result.stderr
    document = report(result)
    found = [(item["rule"], item["path"], item["line"]) for item in document["findings"]]
    planted = [(name, planted_line(samples[name])) for name in sorted(samples)]
    assert [finding for finding in found if finding[0].startswith("security.")] == [
        (SECRET_RULE, path, line) for path, line in planted
    ]
    assert document["unchecked"] == []
    direct = [(path, line) for path, line, _ in direct_findings(target, sorted(samples))]
    assert [item for item in planted if item not in direct] == [
        ("exact/dcm.yml", 2),
        ("exact/iso.md", 329),
        ("exact/notes.txt", 2),
    ]


def test_scanner_matches_gitleaks_direct_once_per_secret(target, tmp_path):
    samples = {**deep_magic_samples(), **edge_samples(), **bypass_samples()}
    samples.update({"meta/recipe.bb": BITBAKE_RECIPE, "meta/other.inc": BITBAKE_RECIPE})
    samples["meta/recipe.txt"] = BITBAKE_RECIPE
    quiet = {"meta/recipe.bb", "meta/other.inc", "mount/42226.txt", "mount/74999.txt"}
    write_samples(target, samples)
    direct = direct_findings(target, sorted(samples))
    assert [path for path, _, _ in direct] == sorted(set(samples) - quiet)
    assert adapter_findings(target, tmp_path, sorted(samples)) == direct


def test_latin1_code_is_text(target):
    target.write("seed.py", "x = 1\n")
    target.commit()
    samples = {
        "scripts/legacy.sh": b"#!/bin/sh\n# R\xe9sum\xe9 der Ausgabe\necho ok\n",
        "tools/deploy.sh": b"#!/bin/sh\n# caf\xe9\nexport " + SECRET_ENV_LINE.encode(),
        "lib/Win.ps1": b"# Gr\xfc\xdfe\r\nWrite-Host ok\r\n",
    }
    write_samples(target, samples)
    target.stage()
    result = target.check("--staged", "--json")
    assert result.returncode == 1, result.stderr
    document = report(result)
    found = [(item["rule"], item["path"], item["line"]) for item in document["findings"]]
    assert [finding for finding in found if finding[0].startswith("security.")] == [
        (SECRET_RULE, "tools/deploy.sh", 3)
    ]
    assert document["unchecked"] == []


def test_binary_blob_with_a_code_name_is_a_hard_finding(target):
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    prefixes = {
        "credentials": BINARY_ELF,
        "run.py": BINARY_PDF,
        "install.SH": BINARY_PDF,
        "deploy.zsh": BINARY_ELF,
        "deploy.env": BINARY_PDF,
        "Dockerfile.prod": BINARY_ELF,
        "app.Dockerfile": BINARY_PDF,
        ".DS_Store": BINARY_ELF,
    }
    for name, prefix in prefixes.items():
        (target.path / name).write_bytes(prefix + SECRET_ENV_LINE.encode())
    target.stage()
    code_like = ["Dockerfile.prod", "app.Dockerfile", "credentials", "deploy.zsh", "install.SH", "run.py"]
    staged = target.check("--staged", "--json")
    assert staged.returncode == 1, staged.stderr
    assert binary_findings(staged) == [(path, None) for path in code_like]
    assert DOCKERFILE_RULE not in rule_ids(staged)
    assert report(staged)["unchecked"] == sorted(prefixes)
    added = target.commit()
    target.git("rm", "-q", *code_like)
    target.commit()
    result = target.check("--base", "main", "--json")
    assert result.returncode == 1, result.stderr
    assert binary_findings(result) == [(path, added) for path in code_like]


def binary_findings(result) -> list:
    findings = report(result)["findings"]
    return [(item["path"], item["commit"]) for item in findings if item["rule"] == BINARY_RULE]


def test_secret_in_symlink_text_and_named_submodule(target):
    target.write("seed.py", "x = 1\n")
    target.commit()
    (target.path / "link.py").symlink_to(f"GITHUB_TOKEN={SECRET}")
    submodule = target.git("rev-parse", "HEAD").stdout.strip()
    target.git("update-index", "--add", "--cacheinfo", f"160000,{submodule},vendor/lib")
    target.git("add", "link.py")
    for mode_flags in (("--staged",), ("--all",)):
        result = target.check(*mode_flags, "--json")
        assert result.returncode == 1, result.stderr
        document = report(result)
        assert [(item["rule"], item["path"]) for item in document["findings"]] == [
            (SECRET_RULE, "link.py")
        ]
        assert document["unchecked"] == ["vendor/lib"]
    assert "unchecked: vendor/lib is a submodule" in target.check("--all").stdout


def test_merged_legacy_secret_is_not_new(target):
    target.write("legacy.env", SECRET_ENV_LINE)
    target.write("a.py", "x = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    target.write("a.py", "x = 2\n")
    target.commit()
    target.git("checkout", "-q", "main")
    target.write("legacy.env", SECRET_ENV_LINE + "OTHER=1\n")
    target.commit()
    target.git("checkout", "-q", "feature")
    target.git("merge", "-q", "--no-edit", "main")
    result = target.check("--base", "main", "--json")
    assert result.returncode == 0, result.stdout
    assert report(result)["findings"] == []
    assert target.check("--all").returncode == 1


@pytest.mark.parametrize(
    "then_on_main",
    [
        lambda target: target.git("rm", "-q", "legacy.env"),
        lambda target: target.write("legacy.env", SECRET_ENV_LINE + "OTHER=1\n"),
    ],
    ids=["removed", "edited"],
)
def test_secret_merged_from_main_twice_is_never_the_branchs(target, then_on_main):
    target.write("a.py", "x = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    target.write("a.py", "x = 2\n")
    target.commit()
    target.git("checkout", "-q", "main")
    target.write("legacy.env", SECRET_ENV_LINE)
    target.commit()
    target.git("checkout", "-q", "feature")
    target.git("merge", "-q", "--no-edit", "main")
    target.git("checkout", "-q", "main")
    then_on_main(target)
    target.commit()
    target.git("checkout", "-q", "feature")
    target.git("merge", "-q", "--no-edit", "main")
    result = target.check("--base", "main", "--json")
    assert result.returncode == 0, result.stdout
    assert report(result)["findings"] == []


def test_secret_at_head_counts_once_with_its_commit(target):
    target.write("a.py", "x = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    target.write("a.py", SECRET_LINE)
    added = target.commit()
    target.write("b.py", "y = 1\n")
    target.commit()
    result = target.check("--base", "main", "--json")
    assert result.returncode == 1
    findings = report(result)["findings"]
    assert [(item["rule"], item["path"], item["commit"]) for item in findings] == [
        (SECRET_RULE, "a.py", added)
    ]
    assert target.check("--base", "main").stdout.splitlines()[-1] == "quality: 1 finding(s)"


@pytest.mark.parametrize(
    ("name", "prefix", "encoding"),
    [
        ("Dockerfile", "", "utf-8"),
        ("Dockerfile", "\N{ZERO WIDTH NO-BREAK SPACE}", "utf-8"),
        ("Dockerfile", "\r", "utf-8"),
        ("Dockerfile", "\N{ZERO WIDTH NO-BREAK SPACE}", "utf-16-le"),
        ("Dockerfile.prod", "", "latin-1"),
        ("app.Dockerfile", "", "latin-1"),
    ],
    ids=["plain", "bom", "cr", "utf16", "latin1-variant", "latin1-suffix"],
)
def test_legacy_hadolint_shell_pragma_does_not_hide_shellcheck(target, name, prefix, encoding):
    text = f"{prefix}# hadolint shell=powershell\nFROM debian:13\nRUN echo $1\n"
    text += "# caf\N{LATIN SMALL LETTER E WITH ACUTE}\n"
    (target.path / name).write_bytes(text.encode(encoding))
    target.commit()
    control = raw_tool(target.path, "hadolint", "--format", "json", name)
    assert control.stdout.strip() == "[]"
    result = target.check("--all", "--json")
    assert result.returncode == 1, result.stderr
    found = [(item["rule"], item["path"], item["line"]) for item in report(result)["findings"]]
    assert (DOCKERFILE_RULE, name, 3) in found
    assert BINARY_RULE not in [rule for rule, _, _ in found]


def test_secret_history_covers_a_merge_commit(target):
    target.write("a.py", "x = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "side")
    target.write("b.py", "y = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature", "main")
    target.git("merge", "-q", "--no-commit", "--no-ff", "side")
    target.write(".env", SECRET_ENV_LINE)
    target.stage()
    target.git("commit", "-q", "-m", COMMIT_MESSAGE_CANARY)
    merge = target.git("rev-parse", "HEAD").stdout.strip()
    target.git("rm", "-q", ".env")
    target.commit()
    result = target.check("--base", "main", "--json")
    assert result.returncode == 1
    assert [(item["rule"], item["commit"]) for item in report(result)["findings"]] == [
        (SECRET_RULE, merge)
    ]
    combined = result.stdout + result.stderr
    for canary in (AUTHOR_NAME, AUTHOR_EMAIL, COMMIT_MESSAGE_CANARY, SECRET):
        assert canary not in combined


@pytest.mark.parametrize(
    ("name", "source", "rule", "control"),
    [
        (
            "a.py",
            f'TOKEN = "{SECRET}"  # gitleaks:allow\n',
            SECRET_RULE,
            ("gitleaks", "dir", *RAW_GITLEAKS),
        ),
        (
            "Dockerfile",
            "# hadolint ignore=DL3006\nFROM debian\n",
            "coding.dockerfile",
            ("hadolint", "--format", "json"),
        ),
    ],
    ids=["gitleaks-allow", "hadolint-ignore"],
)
def test_tool_pragma_does_not_suppress(target, name, source, rule, control):
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.write(name, source)
    target.stage()
    result = target.check("--staged", "--json")
    assert result.returncode == 1, result.stderr
    assert rule_ids(result) == [PRAGMA_RULE, rule]
    honoured = raw_tool(target.path, *control, name)
    assert honoured.returncode == 0
    assert honoured.stdout.strip() == "[]"


def test_hard_eval_new(target):
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.write("a.py", "X = eval(input())\n")
    target.stage()
    result = target.check("--staged", "--json")
    assert result.returncode == 1
    assert rule_ids(result) == [EVAL_RULE]


def test_hard_eval_legacy_touched(target):
    target.write("a.py", "X = eval(input())\n")
    target.commit()
    target.write("a.py", "X = eval(input())\ny = 1\n")
    target.stage()
    result = target.check("--staged", "--json")
    assert result.returncode == 1
    assert rule_ids(result) == [EVAL_RULE]


def test_hard_eval_legacy_untouched(target):
    target.write("a.py", "X = eval(input())\n")
    target.write("b.py", "y = 1\n")
    target.commit()
    target.write("b.py", "y = 2\n")
    target.stage()
    assert target.check("--staged").returncode == 0
    assert target.check("--all").returncode == 1


def test_hard_eval_changed_in_range(target):
    target.write("a.py", "X = eval(input())\n")
    target.write("b.py", "y = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    target.write("b.py", "y = 2\n")
    target.commit()
    assert target.check("--base", "main").returncode == 0
    target.write("a.py", "X = eval(input())\nz = 1\n")
    target.commit()
    assert target.check("--base", "main").returncode == 1


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("subprocess.run(sys.argv[1], shell=True)", True),
        ('subprocess.run("ls", shell=True)', False),
        ("os.system(sys.argv[1])", True),
        ('os.system("ls")', False),
        ('requests.get("https://x", verify=False)', True),
    ],
)
def test_hard_shell_and_tls_rules(target, source, expected):
    target.write("seed.py", "x = 1\n")
    target.commit()
    header = "import os\nimport subprocess\nimport sys\n\nimport requests\n\n"
    target.write("a.py", f"{header}print(os, subprocess, sys, requests)\n{source}\n")
    target.stage()
    result = target.check("--staged", "--json")
    hard = [item for item in report(result)["findings"] if item["rule"].startswith("security.")]
    assert bool(hard) is expected


def test_hard_noqa_ignored(target):
    source = "X = eval(input())  # noqa: S307\n"
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.write("a.py", source)
    target.stage()
    result = target.check("--staged", "--json")
    assert result.returncode == 1
    assert EVAL_RULE in rule_ids(result)
    control = raw_tool(target.path, "ruff", "check", "--isolated", "--select", "S307", "a.py")
    assert control.returncode == 0


@pytest.mark.parametrize(
    ("name", "pragma_source"),
    [
        ("a.py", "x = 1  # noqa\n"),
        ("a.py", "x = 1  # NOQA\n"),
        ("a.py", "x = 1  # NoQa: E501\n"),
        ("a.py", "# ruff: noqa\nx = 1\n"),
        ("a.py", "# flake8: noqa\nx = 1\n"),
        ("a.py", "# ruff: disable[S307]\nx = 1\n"),
        ("s.sh", "#!/bin/bash\n# shellcheck disable=SC2086\necho hi\n"),
        ("a.py", "#lizard forgives\nx = 1\n"),
        ("a.py", "# ast-grep-ignore\nx = 1\n"),
        ("Dockerfile", "FROM debian:13\n# hadolint ignore=DL3008\nRUN true\n"),
        ("Dockerfile", "FROM debian:13\n# hadolint shell=powershell\nRUN true\n"),
        ("Dockerfile", "# hadolint global ignore=DL3008\nFROM debian:13\n"),
        ("Dockerfile", "\N{ZERO WIDTH NO-BREAK SPACE}# hadolint shell=powershell\nFROM debian:13\n"),
        ("a.py", "x = 1  # gitleaks:allow\n"),
    ],
    ids=[
        "noqa",
        "noqa-upper",
        "noqa-mixed",
        "ruff-file",
        "flake8-file",
        "ruff-disable",
        "shellcheck",
        "lizard",
        "ast-grep",
        "hadolint-ignore",
        "hadolint-shell",
        "hadolint-global",
        "hadolint-shell-bom",
        "gitleaks-allow",
    ],
)
def test_pragma_added(target, name, pragma_source):
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.write(name, pragma_source)
    target.stage()
    result = target.check("--staged", "--json")
    assert result.returncode == 1
    assert PRAGMA_RULE in rule_ids(result)


def test_pragma_legacy_passes_and_string_is_no_pragma(target):
    target.write("a.py", "x = 1  # noqa\n")
    target.commit()
    target.write("a.py", "x = 1  # noqa\ny = 2\n")
    target.stage()
    assert target.check("--staged").returncode == 0
    target.write("b.py", 'z = "# noqa"\n')
    target.stage()
    assert target.check("--staged").returncode == 0


@pytest.mark.parametrize(
    ("name", "first_line"),
    [
        ("tool", "#!/usr/bin/env python3"),
        ("tool", "#!/usr/bin/python3.12"),
        ("tool", "#!/usr/bin/env -S python3 -u"),
        ("tool", "#!/usr/bin/env -Spython3"),
        ("tool", "#!/usr/bin/env -u NAME python3"),
        ("tool", "#! /usr/bin/python"),
        ("tool", "#!/usr/bin/pypy3"),
        ("tool.v2", "#!/usr/bin/env python3"),
        ("tool.txt", "#!/usr/bin/python3"),
    ],
    ids=[
        "env",
        "versioned",
        "env-S",
        "env-S-attached",
        "env-u",
        "blank-after-marker",
        "pypy",
        "unknown-suffix",
        "txt-suffix",
    ],
)
def test_hard_rule_reaches_every_python_interpreter_line(target, name, first_line):
    target.write("seed.py", "x = 1\n")
    target.commit()
    target.write(name, f"{first_line}\nX = eval(input())\n")
    target.stage()
    result = target.check("--staged", "--json")
    assert result.returncode == 1
    assert EVAL_RULE in rule_ids(result)


def test_s603_and_s607_are_not_hard():
    for rule in catalogue():
        if rule.get("hard"):
            enforcer = rule["enforcer"]
            for settings in enforcer.values() if isinstance(enforcer, dict) else ():
                codes = settings.get("codes", ())
                assert "S603" not in codes
                assert "S607" not in codes


def history_rules(directory) -> None:
    add_rules(
        directory,
        [
            {
                "id": "security.fixture-token",
                "severity": "critical",
                "summary": "Fixture token",
                "hard": True,
                "history": True,
                "enforcer": {"python": {"tool": "rg", "pattern": "FIXTURETOKEN[0-9]+"}},
            }
        ],
    )


def test_history_rule_scans_every_commit_and_prints_only_the_sha(target, tmp_path):
    rules = rules_copy(tmp_path / "rules")
    history_rules(rules)
    target.write("a.py", "x = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    target.write("a.py", 'x = "FIXTURETOKEN123"\n')
    added = target.commit(COMMIT_MESSAGE_CANARY)
    target.write("a.py", "x = 1\n")
    target.commit("removed again")
    result = target.check("--base", "main", "--json", "--rules", str(rules))
    assert result.returncode == 1
    findings = report(result)["findings"]
    assert [(item["rule"], item["commit"]) for item in findings] == [
        ("security.fixture-token", added)
    ]
    for flags in (("--json",), ()):
        output = target.check("--base", "main", *flags, "--rules", str(rules))
        combined = output.stdout + output.stderr
        assert added in combined
        for canary in (AUTHOR_NAME, AUTHOR_EMAIL, COMMIT_MESSAGE_CANARY, "FIXTURETOKEN123"):
            assert canary not in combined
    log = target.git("log", "--format=%an %ae %s").stdout
    assert AUTHOR_NAME in log
    assert COMMIT_MESSAGE_CANARY in log


def test_history_rule_covers_a_merge_commit(target, tmp_path):
    rules = rules_copy(tmp_path / "rules")
    history_rules(rules)
    target.write("a.py", "x = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "side")
    target.write("b.py", "y = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature", "main")
    target.git("merge", "-q", "--no-commit", "--no-ff", "side")
    target.write("c.py", 'z = "FIXTURETOKEN123"\n')
    target.stage()
    target.git("commit", "-q", "-m", "evil merge")
    merge = target.git("rev-parse", "HEAD").stdout.strip()
    target.write("c.py", "z = 1\n")
    target.commit()
    result = target.check("--base", "main", "--json", "--rules", str(rules))
    assert result.returncode == 1
    assert [item["commit"] for item in report(result)["findings"]] == [merge]


def test_history_names_an_oversized_code_file_added_and_removed(target, tmp_path):
    rules = rules_copy(tmp_path / "rules")
    history_rules(rules)
    edit_yaml(rules / "limits.yml", lambda document: document.update(blob_max_bytes=128))
    target.write("a.py", "x = 1\n")
    target.commit()
    target.git("checkout", "-q", "-b", "feature")
    target.write("big.py", "# pad\n" * 30 + 'x = "FIXTURETOKEN123"\n')
    added = target.commit()
    target.git("rm", "-q", "big.py")
    target.commit()
    result = target.check("--base", "main", "--json", "--rules", str(rules))
    assert result.returncode == 1
    findings = report(result)["findings"]
    assert [(item["rule"], item["path"], item["commit"]) for item in findings] == [
        (OVERSIZED_RULE, "big.py", added)
    ]
