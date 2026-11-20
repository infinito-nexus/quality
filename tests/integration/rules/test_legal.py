import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from quality import db
from quality.legal import index
from tests.integration.support import edit_yaml, keep_rules, report, rules_copy

MIT = "MIT License\n\nPermission is hereby granted, free of charge, to any person obtaining a copy\nof this software\n"
GPL = "                    GNU GENERAL PUBLIC LICENSE\n                       Version 3, 29 June 2007\n"
SEED = {"LICENSE": MIT, "seed.py": "x = 1\n"}
CONFIG = ".quality/legal.yml"
FONT = '<link href="https://fonts.googleapis.com/css2?family=Inter" rel="stylesheet">\n'
LOCAL_FONT = '<link href="/static/fonts/inter.css" rel="stylesheet">\n'
TEMPLATE = "templates/base.html.j2"
PACKAGES = {"PyPI": {"apache-lib": {"*": "Apache-2.0"}, "gpl-lib": {"1.0": "GPL-3.0-only"}, "mit0-lib": {"*": "MIT-0"}}}
CLEAN = (100, 0, 0, [])
DEPENDENCY = "legal.dependency-license"
NO_DATA_NOTE = "unchecked: requirements.txt:1: legal.dependency-license has no licence data for this dependency in the bundle"


def bundle(tmp_path: Path) -> str:
    root = tmp_path / "bundle"
    (root / db.TRIVY_DIR).mkdir(parents=True)
    licenses = index.write_index(root, PACKAGES)
    db.write_manifest(root, datetime.now(timezone.utc), db.tree_digest(root), licenses)
    return str(root)


def legal(document: dict) -> tuple:
    hits = [(item["rule"], item["path"], item["line"]) for item in document["findings"] if item["rule"].startswith("legal.")]
    return document["legal"], document["legal_blockers"], document["legal_unchecked"], hits


def judged(target, mode: str, before: dict, after: dict, *flags: str) -> dict:
    """
    Args:
        target: Fixture repository.
        mode: staged or base.
        before: Files of the base side, path to text.
        after: Files the change writes on top of it.
        flags: Further check options.

    Returns:
        The JSON report of the change.
    """
    for path, text in before.items():
        target.write(path, text)
    target.start_feature(mode)
    for path, text in after.items():
        target.write(path, text)
    target.advance(mode)
    return report(target.judge(mode, "--json", *flags))


@pytest.mark.parametrize(
    "case",
    [
        (MIT, "apache-lib==2.0\n", CLEAN),
        (MIT, "mit0-lib==2.1\n", CLEAN),
        (MIT, "gpl-lib==1.0\n", (50, 1, 0, [(DEPENDENCY, "requirements.txt", 1)])),
        (GPL, "gpl-lib==1.0\n", CLEAN),
    ],
    ids=["apache-in-mit", "mit0-in-mit", "gpl-in-mit", "gpl-in-gpl"],
)
def test_dependency_license_follows_the_project_licence(target, mode, tmp_path, case):
    project, requirement, expected = case
    document = judged(target, mode, {**SEED, "LICENSE": project}, {"requirements.txt": requirement}, "--db", bundle(tmp_path))
    assert legal(document) == expected


def test_dependency_without_licence_data_is_unchecked_and_never_clean(target, mode, tmp_path):
    document = judged(target, mode, SEED, {"requirements.txt": "unknown-lib==3.0\n"}, "--db", bundle(tmp_path))
    assert legal(document) == (100, 0, 1, [])
    assert NO_DATA_NOTE in document["notes"]
    without_bundle = report(target.judge(mode, "--json", "--db", str(tmp_path / "none")))
    assert legal(without_bundle) == (100, 0, 1, [])


def test_oversized_lockfile_stays_an_unchecked_path_of_the_fast_tier(target, mode, tmp_path):
    rules = rules_copy(tmp_path / "rules")
    edit_yaml(rules / "limits.yml", lambda document: document.update(blob_max_bytes=128))
    document = judged(target, mode, SEED, {"package-lock.json": lockfile("gpl-run")}, "--rules", str(rules))
    assert legal(document) == CLEAN
    assert document["unchecked"] == ["package-lock.json"]


def test_dependency_of_a_project_without_licence_file_is_unchecked(target, mode, tmp_path):
    document = judged(target, mode, {"seed.py": "x = 1\n"}, {"requirements.txt": "apache-lib==2.0\n"}, "--db", bundle(tmp_path))
    assert legal(document) == (100, 0, 1, [])
    assert any(note.startswith("unchecked: requirements.txt:1: ") for note in document["notes"])


def lockfile(*names: str) -> str:
    packages = {"": {"name": "app"}, "node_modules/gpl-dev": {"version": "1.0.0", "license": "GPL-3.0-only", "dev": True}}
    packages.update({f"node_modules/{name}": {"version": "1.0.0", "license": "GPL-3.0-only"} for name in names})
    return json.dumps({"lockfileVersion": 3, "packages": packages}, indent=2) + "\n"


@pytest.mark.parametrize(
    ("names", "expected"),
    [((), CLEAN), (("gpl-run",), (50, 1, 0, [(DEPENDENCY, "package-lock.json", 12)]))],
    ids=["dev-only", "runtime"],
)
def test_lockfile_licence_counts_only_runtime_dependencies(target, mode, names, expected):
    assert legal(judged(target, mode, SEED, {"package-lock.json": lockfile(*names)})) == expected


@pytest.mark.parametrize(
    ("line", "expected"),
    [(LOCAL_FONT, CLEAN), (FONT, (75, 0, 0, [("legal.external-request", TEMPLATE, 3)]))],
    ids=["self-hosted", "web-font"],
)
def test_external_request_in_a_template(target, mode, line, expected):
    document = judged(target, mode, {**SEED, TEMPLATE: "<html>\n" + LOCAL_FONT}, {TEMPLATE: "<html>\n" + LOCAL_FONT + line})
    assert legal(document) == expected


@pytest.mark.parametrize(
    ("extra", "expected"),
    [({"vendor/lib/LICENSE": MIT}, CLEAN), ({}, (50, 1, 0, [("legal.vendored-license", "vendor/lib", None)]))],
    ids=["with-licence", "without-licence"],
)
def test_vendored_folder_needs_a_licence_file(target, mode, extra, expected):
    before = {**SEED, CONFIG: "vendored: [vendor/lib]\n"}
    assert legal(judged(target, mode, before, {"vendor/lib/lib.js": "export const a = 1;\n", **extra})) == expected


DECLARED = "legal.license-declared"
PYPROJECT = '[project]\nname = "app"\nlicense = "MIT"\n'


def declared(path: str, line: int | None) -> tuple:
    return 75, 0, 0, [(DECLARED, path, line)]


@pytest.mark.parametrize(
    ("before", "after", "expected"),
    [
        (SEED, {"package.json": '{\n  "name": "app",\n  "license": "MIT"\n}\n'}, CLEAN),
        (SEED, {"package.json": '{\n  "name": "app",\n  "license": "GPL-3.0-only"\n}\n'}, declared("package.json", 3)),
        (SEED, {"a.py": "# SPDX-License-Identifier: MIT\ny = 1\n"}, CLEAN),
        (SEED, {"a.py": "# SPDX-License-Identifier: GPL-3.0-or-later\ny = 1\n"}, declared("a.py", 1)),
        (SEED, {"pyproject.toml": PYPROJECT}, CLEAN),
        ({"seed.py": "x = 1\n"}, {"pyproject.toml": PYPROJECT}, declared("pyproject.toml", None)),
    ],
    ids=["field-agrees", "field-differs", "header-agrees", "header-differs", "licence-file", "no-licence-file"],
)
def test_license_declared_agrees_with_the_licence_file(target, mode, before, after, expected):
    assert legal(judged(target, mode, before, after)) == expected


REUSE_READY = "# SPDX-FileCopyrightText: 2026 Example\n# SPDX-License-Identifier: MIT\ny = 1\n"


@pytest.mark.parametrize(
    ("config", "text", "expected"),
    [
        ("reuse: false\n", "y = 1\n", CLEAN),
        ("reuse: true\n", REUSE_READY, CLEAN),
        ("reuse: true\n", "y = 1\n", (75, 0, 0, [("legal.reuse", "a.py", None)])),
    ],
    ids=["not-opted-in", "reuse-data", "missing-reuse-data"],
)
def test_reuse_only_in_a_repository_that_opts_in(target, mode, config, text, expected):
    before = {**SEED, "LICENSES/MIT.txt": MIT, CONFIG: config}
    assert legal(judged(target, mode, before, {"a.py": text})) == expected


def test_hits_on_unchanged_lines_never_count(target, mode, tmp_path):
    before = {
        **SEED,
        CONFIG: "vendored: [vendor/lib]\n",
        "requirements.txt": "gpl-lib==1.0\n",
        TEMPLATE: "<html>\n" + FONT,
        "a.py": "# SPDX-License-Identifier: GPL-3.0-or-later\ny = 1\n",
        "vendor/lib/lib.js": "export const a = 1;\n",
    }
    after = {
        "requirements.txt": "gpl-lib==1.0\napache-lib==2.0\n",
        TEMPLATE: "<html>\n" + FONT + "<p>hello</p>\n",
        "a.py": "# SPDX-License-Identifier: GPL-3.0-or-later\ny = 2\n",
        "vendor/lib/lib.js": "export const a = 2;\n",
    }
    assert legal(judged(target, mode, before, after, "--db", bundle(tmp_path))) == CLEAN
    whole = report(target.check("--all", "--json", "--db", bundle(tmp_path / "whole")))
    assert legal(whole)[:3] == (None, None, None)
    assert {hit[0] for hit in legal(whole)[3]} == {DEPENDENCY, "legal.external-request", DECLARED, "legal.vendored-license"}


ORIGIN = "legal.foreign-origin"
GPL_HEADER = (
    "# Copyright (C) 2024 Foreign Author <foreign@example.org>\n"
    "#\n"
    "# This program is free software: you can redistribute it and/or modify\n"
    "# it under the terms of the GNU General Public License as published by\n"
    "# the Free Software Foundation, either version 3 of the License, or\n"
    "# (at your option) any later version.\n"
)
OWNED_MIT = MIT.replace("\n\n", "\n\nCopyright (c) 2026 Example Project\n\n", 1)
MIT_HEADER = "# Copyright (c) 2026 {holder}\n# SPDX-License-Identifier: MIT\n"


def origin_rules(tmp_path) -> Path:
    rules = rules_copy(tmp_path / "rules", True)
    keep_rules(rules, lambda rule: rule.get("tier") != "deep" or rule["id"].startswith("legal."))
    return rules


def origin_report(target, tmp_path, files: tuple, rules: Path) -> dict:
    """
    Args:
        target: Fixture repository.
        tmp_path: Scratch directory of the test.
        files: Files of the base side and files the change writes on top of
            it, each path to text.
        rules: Rule data of origin_rules().

    Returns:
        The JSON report of the change under --base, which runs the deep tier.
    """
    before, after = files
    return judged(target, "base", before, after, "--rules", str(rules), "--db", bundle(tmp_path))


def origin_judged(target, tmp_path, before: dict, after: dict) -> tuple:
    return legal(origin_report(target, tmp_path, (before, after), origin_rules(tmp_path)))


@pytest.mark.parametrize(
    ("before", "after", "expected"),
    [
        (SEED, {"a.py": GPL_HEADER + "y = 1\n"}, (50, 1, 0, [(ORIGIN, "a.py", 3)])),
        (SEED, {"a.py": "y = 1\n"}, CLEAN),
        ({**SEED, "a.py": GPL_HEADER + "y = 1\n"}, {"a.py": GPL_HEADER + "y = 2\n"}, CLEAN),
        (
            {**SEED, "LICENSE": OWNED_MIT},
            {"a.py": MIT_HEADER.format(holder="Example Project") + "y = 1\n"},
            CLEAN,
        ),
        (
            {**SEED, "LICENSE": OWNED_MIT},
            {"a.py": MIT_HEADER.format(holder="Foreign Author") + "y = 1\n"},
            (75, 0, 0, [("legal.foreign-copyright", "a.py", 1)]),
        ),
        (SEED, {"a.py": 'REFUSED = "GPL-3.0"\ny = 1\n'}, CLEAN),
        (SEED, {"a.py": "# SPDX-License-Identifier: GPL-3.0-or-later\ny = 1\n"}, declared("a.py", 1)),
    ],
    ids=[
        "gpl-header-in-mit",
        "no-header",
        "gpl-header-at-base",
        "own-mit-header",
        "foreign-mit-header",
        "licence-reference",
        "spdx-identifier",
    ],
)
def test_foreign_origin_judges_licence_texts_by_the_project_licence(target, tmp_path, before, after, expected):
    assert origin_judged(target, tmp_path, before, after) == expected


def test_foreign_origin_scans_a_file_scancode_skips_by_its_name(target, tmp_path):
    after = {".gitattributes": GPL_HEADER + "* text=auto\n"}
    assert origin_judged(target, tmp_path, SEED, after) == (50, 1, 0, [(ORIGIN, ".gitattributes", 3)])


def test_foreign_origin_judges_each_chunk_of_a_split_command(target, tmp_path):
    rules = origin_rules(tmp_path)
    edit_yaml(rules / "limits.yml", lambda document: document.update(argv_max_bytes=1))
    after = {"a.py": "y = 1\n", "b.py": GPL_HEADER + "y = 1\n", "c.py": "z = 1\n"}
    document = origin_report(target, tmp_path, (SEED, after), rules)
    assert legal(document) == (50, 1, 0, [(ORIGIN, "b.py", 3)])
