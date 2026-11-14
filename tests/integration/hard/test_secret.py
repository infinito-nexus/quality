import pytest

from tests.integration.hard.support import (
    COMMIT_MESSAGE_CANARY,
    SECRET_LINE,
    SECRET_RULE,
)
from tests.integration.support import (
    AUTHOR_EMAIL,
    AUTHOR_NAME,
    SECRET,
    SECRET_ENV_LINE,
    report,
    rule_ids,
)

K8S_SECRET = (
    b"apiVersion: v1\nkind: Secret\nmetadata:\n  name: db\ndata:\n"
    b"  dbconn: cG9zdGdyZXM6Ly9hZG1pbjpodW50ZXIyQGRiLmludGVybmFsOjU0MzIvcHJvZA==\n"
)
K8S_LINE = 2

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
