import importlib.util
import io
import json
from pathlib import Path, PurePosixPath

import pytest
import yaml

from quality.ruledata import gitignore_spec

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("ort_excludes", ROOT / ".github" / "ort" / "excludes.py")
excludes = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(excludes)
RULES = yaml.safe_load((ROOT / "rules" / "legal.yml").read_text(encoding="utf-8"))
PATHS = [
    "tests/service/requirements.txt",
    "service/web/requirements.txt",
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-test.txt",
    "service/requirements-dev.txt",
    "a/test/requirements.txt",
    "a/b/tests/c/package.json",
    "attests/requirements.txt",
    "pyproject.toml",
    "service/web/package-lock.json",
]


def excluded(config: str) -> list:
    """
    Args:
        config: An .ort.yml as excludes.py writes it.

    Returns:
        Its path exclude patterns.
    """
    return [entry["pattern"] for entry in yaml.safe_load(config)["excludes"]["paths"]]


def exempt_of(rules: list) -> list:
    return next(rule for rule in rules if rule["id"] == excludes.RULE)["enforcer"]["any"]["exempt"]


@pytest.mark.parametrize("path", PATHS)
def test_ort_excludes_exactly_the_paths_rules_legal_exempts(path):
    exempt = gitignore_spec(exempt_of(RULES))
    patterns = excluded(excludes.ort_config(RULES))
    assert any(PurePosixPath(path).full_match(pattern) for pattern in patterns) is exempt.match_file(path), patterns


def test_ort_excludes_the_test_requirements_and_keeps_the_shipped_ones():
    patterns = excluded(excludes.ort_config(RULES))
    assert any(PurePosixPath("tests/service/requirements.txt").full_match(pattern) for pattern in patterns)
    assert not any(PurePosixPath("service/web/requirements.txt").full_match(pattern) for pattern in patterns)


@pytest.mark.parametrize(
    ("exempt", "patterns"),
    [
        ("tests/", ["**/tests/**"]),
        ("*dev*.txt", ["**/*dev*.txt", "**/*dev*.txt/**"]),
        ("/build/", ["build/**"]),
        ("docs/requirements.txt", ["docs/requirements.txt", "docs/requirements.txt/**"]),
    ],
)
def test_ant_patterns_keep_the_gitignore_anchoring(exempt, patterns):
    assert excludes.ant_patterns(exempt) == patterns


@pytest.mark.parametrize("exempt", ["!tests/keep.txt", "test[0-9].txt", "a\\*b.txt"])
def test_ant_patterns_refuse_what_ant_cannot_express(exempt):
    with pytest.raises(excludes.ExcludeError):
        excludes.ant_patterns(exempt)


def test_main_writes_the_config_and_fails_on_rules_without_the_rule(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(RULES)))
    assert excludes.main([]) == 0
    assert excluded(capsys.readouterr().out) == excluded(excludes.ort_config(RULES))
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps([{"id": "legal.other"}])))
    assert excludes.main([]) == 1
    assert "expected 1" in capsys.readouterr().err
    assert excludes.main(["rules.json"]) == 2
