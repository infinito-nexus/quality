import re

import pytest

from quality import QualityError
from quality.architecture import contract
from tests.integration.support import findings_of_rule, report, rule_ids

LAYER = "architecture.layer"
CYCLE = "architecture.cycle"
CONTRACT = ".quality/architecture.yml"
PYTHON_CONTRACT = (
    "python:\n"
    "  source: src\n"
    "  packages: [shop]\n"
    "  layers: [shop.web, shop.domain]\n"
    "  forbidden: []\n"
)
JAVASCRIPT_CONTRACT = "javascript:\n  source: web\n  layers: [web/ui, web/core]\n  forbidden: []\n"
MODEL = "src/shop/domain/model.py"
CLEAN_MODEL = 'NAME = "model"\n'
FORBIDDEN_MODEL = 'from shop.web import views\n\nNAME = views.NAME\n'
CORE = "web/core/a.js"
CORE_WITHOUT_CYCLE = 'import { b } from "./b.js";\n\nexport const a = () => b;\n'
OTHER = "web/core/b.js"
OTHER_WITHOUT_CYCLE = "export const b = 1;\n"
OTHER_WITH_CYCLE = 'import { a } from "./a.js";\n\nexport const b = () => a;\n'
UI_IMPORT = 'import { view } from "../ui/view.js";\n\nexport const c = () => view;\n'


def write_python(target, model: str) -> None:
    target.write("src/shop/__init__.py", "")
    target.write("src/shop/web/__init__.py", "")
    target.write("src/shop/web/views.py", 'NAME = "views"\n')
    target.write("src/shop/domain/__init__.py", "")
    target.write(MODEL, model)


def write_javascript(target, other: str) -> None:
    target.write("web/ui/view.js", "export const view = 1;\n")
    target.write(CORE, CORE_WITHOUT_CYCLE)
    target.write(OTHER, other)


def write_both(target, model: str, other: str) -> None:
    target.write(CONTRACT, PYTHON_CONTRACT + JAVASCRIPT_CONTRACT)
    write_python(target, model)
    write_javascript(target, other)


def architecture(result) -> tuple:
    document = report(result)
    return document["architecture"], sorted((item["rule"], item["lens"]) for item in document["findings"])


def test_python_import_of_a_higher_layer_counts_until_it_is_removed(target, mode):
    target.write(CONTRACT, PYTHON_CONTRACT)
    write_python(target, CLEAN_MODEL)
    target.start_feature(mode)
    target.write(MODEL, FORBIDDEN_MODEL)
    target.advance(mode)
    result = target.judge(mode, "--json")
    assert architecture(result) == (75, [(LAYER, "SRP")])
    assert findings_of_rule(result, LAYER) == [(MODEL, 1)]
    target.write(MODEL, CLEAN_MODEL)
    target.advance(mode)
    assert architecture(target.judge(mode, "--json")) == (100, [])


def test_javascript_import_cycle_counts_once_until_it_is_broken(target, mode):
    target.write(CONTRACT, JAVASCRIPT_CONTRACT)
    write_javascript(target, OTHER_WITHOUT_CYCLE)
    target.start_feature(mode)
    target.write(OTHER, OTHER_WITH_CYCLE)
    target.advance(mode)
    result = target.judge(mode, "--json")
    assert architecture(result) == (75, [(CYCLE, "SRP")])
    assert findings_of_rule(result, CYCLE) == [(CORE, None)]
    target.write(OTHER, OTHER_WITHOUT_CYCLE)
    target.advance(mode)
    assert architecture(target.judge(mode, "--json")) == (100, [])


def test_javascript_import_of_a_higher_layer_counts(target):
    target.write(CONTRACT, JAVASCRIPT_CONTRACT)
    write_javascript(target, OTHER_WITHOUT_CYCLE)
    target.start_feature("staged")
    target.write("web/core/c.js", UI_IMPORT)
    target.advance("staged")
    result = target.judge("staged", "--json")
    assert architecture(result) == (75, [(LAYER, "SRP")])
    assert findings_of_rule(result, LAYER) == [("web/core/c.js", None)]


def test_each_new_layer_import_and_cycle_lowers_the_score_by_25(target, mode):
    write_both(target, CLEAN_MODEL, OTHER_WITHOUT_CYCLE)
    target.start_feature(mode)
    target.write(MODEL, FORBIDDEN_MODEL)
    target.write(OTHER, OTHER_WITH_CYCLE)
    target.advance(mode)
    assert architecture(target.judge(mode, "--json")) == (50, [(CYCLE, "SRP"), (LAYER, "SRP")])


def test_violations_at_the_base_do_not_count(target, mode):
    write_both(target, FORBIDDEN_MODEL, OTHER_WITH_CYCLE)
    target.start_feature(mode)
    target.write(MODEL, FORBIDDEN_MODEL + 'OTHER = "x"\n')
    target.write(OTHER, OTHER_WITH_CYCLE + "export const d = 2;\n")
    target.advance(mode)
    assert architecture(target.judge(mode, "--json")) == (100, [])
    assert sorted(rule_ids(target.check("--all", "--json"))) == [CYCLE, LAYER]


def test_a_repository_without_the_contract_runs_neither_tool(target):
    write_python(target, FORBIDDEN_MODEL)
    write_javascript(target, OTHER_WITH_CYCLE)
    target.commit()
    result = target.check("--all", "--json", "--verbose")
    assert rule_ids(result) == []
    assert "tool lint-imports:" not in result.stderr
    assert "tool depcruise:" not in result.stderr
    target.write(CONTRACT, PYTHON_CONTRACT + JAVASCRIPT_CONTRACT)
    target.commit()
    control = target.check("--all", "--json", "--verbose")
    assert "tool lint-imports: exit 1" in control.stderr
    assert "tool depcruise: exit 0" in control.stderr
    assert sorted(rule_ids(control)) == [CYCLE, LAYER]


def test_a_section_the_contract_leaves_out_is_not_checked(target):
    target.write(CONTRACT, JAVASCRIPT_CONTRACT)
    write_python(target, FORBIDDEN_MODEL)
    write_javascript(target, OTHER_WITHOUT_CYCLE)
    target.commit()
    assert rule_ids(target.check("--all", "--json")) == []


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("[[[\n", f"{CONTRACT} is no valid YAML"),
        ("ruby: {}\n", "has unknown key 'ruby'"),
        ("python:\n  source: src\n  layers: [shop.web]\n  forbidden: []\n", "python is missing key 'packages'"),
        (PYTHON_CONTRACT + "  extra: 1\n", "python has unknown key 'extra'"),
        (PYTHON_CONTRACT.replace("source: src", "source: ../src"), "python.source must be a relative path"),
        (PYTHON_CONTRACT.replace("[shop]", "[json]"), "python.packages[0] names 'json', a standard library module"),
        (PYTHON_CONTRACT.replace("shop.web,", "other.web,"), "names module 'other.web' outside python.packages"),
        (JAVASCRIPT_CONTRACT.replace("web/ui,", "lib/ui,"), "names path 'lib/ui' outside javascript.source"),
        (JAVASCRIPT_CONTRACT.replace("forbidden: []", "forbidden: [{from: [web/core]}]"), "javascript.forbidden[0] is missing key 'to'"),
    ],
)
def test_a_malformed_contract_names_its_key(text: str, message: str):
    with pytest.raises(QualityError, match=re.escape(message)):
        contract.parse(text.encode())


def test_a_malformed_contract_fails_closed(target):
    target.write(CONTRACT, PYTHON_CONTRACT.replace("  packages: [shop]\n", ""))
    write_python(target, CLEAN_MODEL)
    target.commit()
    target.write(MODEL, FORBIDDEN_MODEL)
    target.stage()
    result = target.check("--staged", "--json")
    assert result.returncode == 2
    assert f"{CONTRACT}: python is missing key 'packages'" in result.stderr
    target.write(CONTRACT, PYTHON_CONTRACT)
    target.stage()
    assert rule_ids(target.check("--staged", "--json")) == [LAYER]
