from pathlib import Path

import pytest
import yaml

SKILLS = Path(__file__).resolve().parents[2] / "skills"
FENCE = "---\n"


def frontmatter(path: Path) -> dict:
    """
    Args:
        path: A SKILL.md.

    Returns:
        Its YAML frontmatter, the mapping between the first two `---` lines;
        ValueError when the file opens with none or it is no mapping.
    """
    text = path.read_text(encoding="utf-8")
    if not text.startswith(FENCE):
        raise ValueError(f"{path}: no frontmatter")
    head, fence, _body = text.removeprefix(FENCE).partition(f"\n{FENCE}")
    data = yaml.safe_load(head) if fence else None
    if not isinstance(data, dict):
        raise ValueError(f"{path}: the frontmatter is no closed YAML mapping")
    return data


def misnamed(skills: Path) -> list:
    """
    Args:
        skills: A skills folder holding one folder per skill.

    Returns:
        One line per skill folder without a SKILL.md or whose frontmatter
        name differs from the folder name.
    """
    found = []
    for folder in sorted(path for path in skills.iterdir() if path.is_dir()):
        skill = folder / "SKILL.md"
        if not skill.is_file():
            found.append(f"{folder.name}: no SKILL.md")
            continue
        name = frontmatter(skill).get("name")
        if name != folder.name:
            found.append(f"{folder.name}: frontmatter name {name!r}")
    return found


def skill(skills: Path, folder: str, text: str) -> None:
    (skills / folder).mkdir(parents=True)
    (skills / folder / "SKILL.md").write_text(text, encoding="utf-8")


def test_every_skill_of_the_repository_names_its_folder():
    folders = [path.name for path in SKILLS.iterdir() if path.is_dir()]
    assert folders
    assert misnamed(SKILLS) == []


def test_a_matching_name_passes(tmp_path):
    skill(tmp_path, "kvb-quality-alpha", "---\nname: kvb-quality-alpha\ndescription: Alpha.\n---\n# Alpha\n")
    assert misnamed(tmp_path) == []


def test_a_wrong_name_fails(tmp_path):
    skill(tmp_path, "kvb-quality-alpha", "---\nname: kvb-quality-beta\ndescription: Alpha.\n---\n")
    assert misnamed(tmp_path) == ["kvb-quality-alpha: frontmatter name 'kvb-quality-beta'"]


def test_a_missing_name_or_skill_file_fails(tmp_path):
    skill(tmp_path, "kvb-quality-alpha", "---\ndescription: Alpha.\n---\n")
    (tmp_path / "kvb-quality-beta").mkdir()
    assert misnamed(tmp_path) == ["kvb-quality-alpha: frontmatter name None", "kvb-quality-beta: no SKILL.md"]


@pytest.mark.parametrize(
    "text",
    ["# Alpha\nname: kvb-quality-alpha\n", "---\nname: kvb-quality-alpha\n", "---\n- kvb-quality-alpha\n---\n"],
)
def test_a_missing_unclosed_or_non_mapping_frontmatter_fails(tmp_path, text):
    skill(tmp_path, "kvb-quality-alpha", text)
    with pytest.raises(ValueError):
        misnamed(tmp_path)
