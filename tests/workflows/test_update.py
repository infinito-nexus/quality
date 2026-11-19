import importlib.util
import io
import json
import tarfile
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / ".github" / "update" / "inputs.py"
SPEC = importlib.util.spec_from_file_location("update_inputs", SCRIPT)
inputs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inputs)

PYPI_DIR = "https://files.pythonhosted.org/packages/ab/cd/" + "e" * 60
OLD_WHEEL = f"{PYPI_DIR}/gizmo-3.20-cp314-cp314-manylinux2014_x86_64.manylinux_2_17_x86_64.whl"
NEW_WHEEL = f"{PYPI_DIR}/gizmo-3.21-cp314-cp314-manylinux2014_x86_64.manylinux_2_17_x86_64.whl"
OLD_NPM = "https://registry.npmjs.org/widget-linux-x64-gnu/-/widget-linux-x64-gnu-5.4.2.tgz"
NEW_NPM = "https://registry.npmjs.org/widget-linux-x64-gnu/-/widget-linux-x64-gnu-5.5.0.tgz"
OLD_TAG = "https://github.com/acme/gadget/archive/refs/tags/v18.8.0.tar.gz"
NEW_TAG = "https://github.com/acme/gadget/archive/refs/tags/v18.9.0.tar.gz"
OLD_HASH = "sha256-" + "A" * 43 + "="
NEW_HASH = "sha256-" + "B" * 43 + "="
FLAKE = (
    '  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";\n'
    f'  inputs.widget-x86_64-linux = {{\n    url = "{OLD_NPM}";\n    flake = false;\n  }};\n'
    f'  inputs.gizmo-x86_64-linux = {{\n    url = "{OLD_WHEEL}";\n    flake = false;\n  }};\n'
    f'  inputs.gadget = {{\n    url = "{OLD_TAG}";\n    flake = false;\n  }};\n'
    f'        src = inputs.gadget;\n        npmDepsHash = "{OLD_HASH}";\n'
)


def wheel(version: str, yanked: bool) -> dict:
    name = f"gizmo-{version}-cp314-cp314-manylinux2014_x86_64.manylinux_2_17_x86_64.whl"
    return {"filename": name, "url": f"{PYPI_DIR}/{name}", "yanked": yanked}


def archive(root: str) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as bundle:
        data = b'{"lockfileVersion": 3}'
        member = tarfile.TarInfo(f"{root}/package-lock.json")
        member.size = len(data)
        bundle.addfile(member, io.BytesIO(data))
    return buffer.getvalue()


def answers() -> dict:
    releases = {
        "3.20": [wheel("3.20", False)],
        "3.21": [wheel("3.21", False)],
        "3.22": [wheel("3.22", True)],
        "4.0rc1": [wheel("4.0rc1", False)],
    }
    return {
        "https://registry.npmjs.org/widget-linux-x64-gnu/latest": {"version": "5.5.0", "dist": {"tarball": NEW_NPM}},
        "https://pypi.org/pypi/gizmo/json": {"releases": releases},
        "https://api.github.com/repos/acme/gadget/releases/latest": {
            "tag_name": "v18.9.0",
            "prerelease": False,
            "draft": False,
        },
        NEW_TAG: archive("gadget-18.9.0"),
    }


def stub(table: dict):
    def get(url: str) -> bytes:
        assert url in table, f"unexpected request: {url}"
        value = table[url]
        return value if isinstance(value, bytes) else json.dumps(value).encode()

    return get


def prefetch(path: Path) -> str:
    assert json.loads(path.read_text(encoding="utf-8")) == {"lockfileVersion": 3}
    return NEW_HASH


def test_each_versioned_input_moves_to_its_newest_stable_release():
    flake, moved = inputs.update(FLAKE, stub(answers()), prefetch)
    assert OLD_NPM not in flake and NEW_NPM in flake
    assert OLD_TAG not in flake and NEW_TAG in flake
    assert f'npmDepsHash = "{NEW_HASH}"' in flake
    assert "gizmo-3.22" not in flake and "4.0rc1" not in flake
    assert flake.count("gizmo-3.21") == 1 and "gizmo-3.20" not in flake
    assert '"github:NixOS/nixpkgs/nixos-unstable"' in flake
    assert len(moved) == 3


def test_an_input_already_on_its_newest_release_stays_and_keeps_its_hash():
    current = FLAKE.replace(OLD_NPM, NEW_NPM).replace(OLD_WHEEL, NEW_WHEEL).replace(OLD_TAG, NEW_TAG)
    table = {key: value for key, value in answers().items() if key != NEW_TAG}
    assert inputs.update(current, stub(table), prefetch) == (current, [])


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda table: table["https://registry.npmjs.org/widget-linux-x64-gnu/latest"].update(version="5.6.0-beta.1"), "no stable release"),
        (lambda table: table["https://pypi.org/pypi/gizmo/json"]["releases"].update({"3.21": [dict(wheel("3.21", False), filename="gizmo-3.21-cp313-cp313-linux_x86_64.whl")]}), "no single unyanked file"),
        (lambda table: table["https://api.github.com/repos/acme/gadget/releases/latest"].update(prerelease=True), "pre-release"),
        (lambda table: table["https://registry.npmjs.org/widget-linux-x64-gnu/latest"]["dist"].update(tarball=NEW_NPM.replace("https", "http")), "not https"),
        (lambda table: table["https://registry.npmjs.org/widget-linux-x64-gnu/latest"]["dist"].update(tarball=OLD_NPM), "does not name"),
        (lambda table: table.update({NEW_TAG: archive("a/b")}), "no package-lock.json at its root"),
    ],
)
def test_a_malformed_or_unstable_answer_fails_loud(change, message):
    table = answers()
    change(table)
    with pytest.raises(inputs.UpdateError, match=message):
        inputs.update(FLAKE, stub(table), prefetch)


def test_a_lock_file_larger_than_the_download_cap_is_refused(monkeypatch):
    monkeypatch.setattr(inputs, "MAX_BYTES", 8)
    with pytest.raises(inputs.UpdateError, match="exceeds 8 bytes"):
        inputs.update(FLAKE, stub(answers()), prefetch)


def test_a_registry_url_of_unknown_shape_and_plain_http_are_refused():
    with pytest.raises(inputs.UpdateError, match="no known versioned shape"):
        inputs.update(FLAKE.replace(OLD_WHEEL, "https://files.pythonhosted.org/packages/source/g/gizmo/gizmo-3.20.tar.gz"), stub(answers()), prefetch)
    with pytest.raises(inputs.UpdateError, match="not https"):
        inputs.fetch("http://pypi.org/pypi/gizmo/json")
