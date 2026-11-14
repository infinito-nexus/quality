import base64
import gzip
import io
import json
import os
import zipfile

from quality.adapters import Collector, Runtime
from quality.adapters.base import Bound, thread_environment
from quality.environment import tool_environment
from quality.ruledata import load
from quality.snapshot import Snapshot
from tests.integration.hard.support import (
    BINARY_RULE,
    DOCKERFILE_RULE,
    SECRET_LINE,
    SECRET_RULE,
)
from tests.integration.support import (
    RAW_GITLEAKS,
    RULES,
    SECRET,
    SECRET_ENV_LINE,
    TOOL_THREADS,
    raw_tool,
    report,
    rule_ids,
    rules_without_pending,
)

BINARY_PDF = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n\x00"
BINARY_ELF = b"\x7fELF\x02\x01\x01\x00\x00\x00\n"
BITBAKE_RECIPE = b'SUMMARY = "x"\nSRCREV_tokenizer = "' + b'9f8e7d6c5b4a39281706f5e4d3c2b1a098765432"\n'


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
    environment = {**tool_environment(path_value, home, None), **thread_environment(TOOL_THREADS)}
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
