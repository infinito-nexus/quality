import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "src"


def test_every_package_under_src_ships():
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["setuptools"]
    found = {".".join(path.parent.relative_to(SOURCE).parts) for path in SOURCE.rglob("__init__.py")}
    assert found - set(config["packages"]) == set()
