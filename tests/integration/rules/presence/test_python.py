import pytest

from tests.integration.support import findings_of_rule

RULE = "test.text-presence"
POSITIVE = "tests/test_positive.py"
HEAD = "import copy\nimport json\nimport tarfile\nfrom pathlib import Path\n\nimport yaml\n\nMAX_LINES = 500\nDEBUG = 'debug: true'\n\n\n"
CASES = {
    "a parsed leaf is text, as a needle in another file a cross-reference": (
        (
            "def test_the_task_runs_the_migration():\n"
            "    task = json.loads(Path('task.json').read_text())\n"
            "    assert 'php artisan migrate' in task['shell']\n"
        ),
        (
            "def test_the_image_installs_the_package():\n"
            "    name = json.loads(Path('package.json').read_text())['name']\n"
            "    assert name in Path('Dockerfile').read_text()\n"
        ),
    ),
    "a finding is judged by the condition that produces it": (
        (
            "def test_every_shared_role_documents_it():\n"
            "    missing = []\n"
            "    for path in sorted(Path('roles').glob('*/meta.yml')):\n"
            "        if not yaml.safe_load(path.read_text()).get('shared'):\n"
            "            continue\n"
            "        if 'shared:' not in path.with_name('README.md').read_text():\n"
            "            missing.append(path.name)\n"
            "    assert missing == []\n"
        ),
        (
            "def test_every_owned_role_names_a_team():\n"
            "    missing = []\n"
            "    for path in sorted(Path('roles').glob('*/meta.yml')):\n"
            "        text = path.read_text()\n"
            "        if 'owner:' not in text:\n"
            "            continue\n"
            "        if yaml.safe_load(text)['owner'] == '':\n"
            "            missing.append(path.name)\n"
            "    assert missing == []\n"
        ),
    ),
    "an exemption lacking a literal loses to a later presence filter": (
        (
            "def test_every_download_retries():\n"
            "    missing = []\n"
            "    for line in Path('install.sh').read_text().splitlines():\n"
            "        if 'curl ' not in line:\n"
            "            continue\n"
            "        if '--retry' in line:\n"
            "            continue\n"
            "        missing.append(line)\n"
            "    assert missing == []\n"
        ),
        (
            "def test_no_compose_verb_is_left():\n"
            "    offenders = []\n"
            "    for line in Path('tasks.yml').read_text().splitlines():\n"
            "        if 'notify:' in line:\n"
            "            continue\n"
            "        if 'compose up' not in line:\n"
            "            continue\n"
            "        offenders.append(line)\n"
            "    assert offenders == []\n"
        ),
    ),
    "a named limit is no presence, a literal count is": (
        "def test_become_is_set_more_than_twice():\n    assert Path('role.yml').read_text().count('become') > 2\n",
        (
            "def test_every_file_stays_short():\n"
            "    long = []\n"
            "    for path in sorted(Path('src').glob('*.py')):\n"
            "        if path.read_bytes().count(b'\\n') <= MAX_LINES:\n"
            "            continue\n"
            "        long.append(path.name)\n"
            "    assert long == []\n"
        ),
    ),
    "a line planted beside read text by an f-string or a dict merge": (
        (
            "def test_both_roles_name_become():\n"
            "    combined = f\"{Path('a.yml').read_text()}{Path('b.yml').read_text()}\"\n"
            "    assert 'become' in combined\n"
        ),
        (
            "def test_a_planted_debug_line_is_found():\n"
            "    text = f\"{Path('role.yml').read_text()}{DEBUG}\\n\"\n"
            "    assert 'debug' in text\n"
            "\n"
            "\n"
            "def test_a_planted_file_is_found():\n"
            "    files = {**{'role.yml': Path('role.yml').read_text()}, 'planted.yml': 'src: x.j2\\n'}\n"
            "    assert 'src: x.j2' in files['planted.yml']\n"
        ),
    ),
    "a lookup helper's closing raise is no check": (
        (
            "def location(uri):\n"
            "    for block in Path('nginx.conf').read_text().split('location '):\n"
            "        if block.startswith(uri):\n"
            "            return block\n"
            "    raise AssertionError(uri)\n"
            "\n"
            "\n"
            "def test_media_is_internal():\n"
            "    assert 'internal;' in location('/media')\n"
        ),
        (
            "def test_no_debug_is_left():\n"
            "    if 'debug' in Path('role.yml').read_text():\n"
            "        raise AssertionError('debug left')\n"
        ),
    ),
    "a scalar leaf compared with 0 or an empty string is structure": (
        (
            "def test_every_mount_is_read_only():\n"
            "    mounts = yaml.safe_load(Path('vars.yml').read_text())['mounts']\n"
            "    assert [mount for mount in mounts if not mount.endswith(':ro')] == []\n"
        ),
        (
            "def test_checkouts_fetch_the_full_history():\n"
            "    steps = yaml.safe_load(Path('ci.yml').read_text())['steps']\n"
            "    checkouts = [step for step in steps if step.get('uses', '').startswith('actions/checkout@')]\n"
            "    assert checkouts\n"
            "    assert all(step.get('with', {}).get('fetch-depth') == 0 for step in checkouts)\n"
        ),
    ),
    "archive entries are paths, lines of an opened file text": (
        (
            "def test_the_notes_name_the_notices():\n"
            "    with open('notes.txt', encoding='utf-8') as handle:\n"
            "        lines = handle.read().splitlines()\n"
            "    assert 'NOTICES' in lines\n"
        ),
        (
            "def test_the_image_ships_the_notices():\n"
            "    names = []\n"
            "    with tarfile.open('image.tar') as archive:\n"
            "        for member in archive:\n"
            "            names.append(member.name)\n"
            "    assert 'NOTICES' in names\n"
        ),
    ),
    "a type check selects parsed entries, it decides nothing": (
        (
            "def flat(tasks):\n"
            "    found = []\n"
            "    for task in tasks:\n"
            "        if isinstance(task, dict):\n"
            "            found.append(task)\n"
            "            found.extend(flat(task.get('block', [])))\n"
            "    return found\n"
            "\n"
            "\n"
            "def test_an_include_names_the_stage():\n"
            "    tasks = flat(yaml.safe_load(Path('tasks.yml').read_text()))\n"
            "    assert 'stage.yml' in ' '.join(str(task.get('include_tasks')) for task in tasks)\n"
        ),
        "def test_the_tasks_are_a_list():\n    assert isinstance(yaml.safe_load(Path('tasks.yml').read_text()), list)\n",
    ),
    "a deep copy of read data is a planted control": (
        "def test_the_tasks_name_the_secret():\n    assert '--secret' in str(yaml.safe_load(Path('kv.yml').read_text()))\n",
        (
            "def test_a_secret_on_argv_is_found():\n"
            "    planted = copy.deepcopy(yaml.safe_load(Path('kv.yml').read_text()))\n"
            "    planted[0]['cmd'] += ' --secret'\n"
            "    assert '--secret' in str(planted)\n"
        ),
    ),
    "a helper named for evaluating a condition runs it": (
        (
            "def first_word(gate, facts):\n"
            "    return facts.get(gate.split()[0], False)\n"
            "\n"
            "\n"
            "def test_the_sso_gate_names_sso():\n"
            "    gate = Path('gate.j2').read_text()\n"
            "    assert 'sso' in gate\n"
            "    assert not first_word(gate, {'sso': False})\n"
        ),
        (
            "def holds(gate, facts):\n"
            "    return facts.get(gate.split()[0], False)\n"
            "\n"
            "\n"
            "def test_the_sso_gate_refuses():\n"
            "    gate = Path('gate.j2').read_text()\n"
            "    assert 'sso' in gate\n"
            "    assert not holds(gate, {'sso': False})\n"
        ),
    ),
    "a parsed value is a sequence where the test treats it as one": (
        (
            "def test_the_step_runs_the_linter():\n"
            "    run = yaml.safe_load(Path('ci.yml').read_text())['run']\n"
            "    assert 'make lint' in run, run\n"
        ),
        (
            "def test_the_role_depends_on_the_database():\n"
            "    dependencies = yaml.safe_load(Path('meta.yml').read_text())['dependencies']\n"
            "    assert 'svc db' in dependencies, sorted(dependencies)\n"
        ),
    ),
    "a comparison stored past a filter keeps its own tag": (
        (
            "def test_every_lookup_is_indented():\n"
            "    missing = []\n"
            "    for line in Path('compose.yml.j2').read_text().splitlines():\n"
            "        if 'lookup(' not in line:\n"
            "            continue\n"
            "        unfiltered = '| indent(' not in line\n"
            "        if unfiltered:\n"
            "            missing.append(line)\n"
            "    assert missing == []\n"
        ),
        (
            "def test_no_lookup_takes_a_raw_port():\n"
            "    offenders = []\n"
            "    for line in Path('compose.yml.j2').read_text().splitlines():\n"
            "        if 'lookup(' not in line:\n"
            "            continue\n"
            "        raw = 'raw_port' in line\n"
            "        if raw:\n"
            "            offenders.append(line)\n"
            "    assert offenders == []\n"
        ),
    ),
    "a comparison on str() of parsed data checks its value": (
        (
            "def test_the_first_line_names_the_flavor():\n"
            "    first = Path('sso.txt').read_text().splitlines()[0]\n"
            "    assert str(first).strip() == 'flavor: oauth2'\n"
        ),
        (
            "def test_the_gate_is_oauth2():\n"
            "    sso = yaml.safe_load(Path('services.yml').read_text())['sso']\n"
            "    assert str(sso.get('flavor') or '').strip() == 'oauth2'\n"
        ),
    ),
    "a dash made an underscore plants nothing": (
        (
            "def test_the_tasks_set_the_flag():\n"
            "    text = Path('tasks.yml').read_text().replace('-', '_')\n"
            "    assert 'run_once_web_app' in text\n"
        ),
        (
            "def test_a_planted_flag_is_found():\n"
            "    text = Path('tasks.yml').read_text().replace('when:', 'run_once_web_app: true\\nwhen:')\n"
            "    assert 'run_once_web_app' in text\n"
        ),
    ),
    "a waiver lookup beside a condition states nothing of the text": (
        (
            "def has_nocheck(path):\n"
            "    return 'nocheck: license' in path.read_text()\n"
            "\n"
            "\n"
            "def test_every_file_names_its_license():\n"
            "    missing = []\n"
            "    for path in sorted(Path('src').glob('*.py')):\n"
            "        if 'License:' not in path.read_text() and not has_nocheck(path):\n"
            "            missing.append(path.name)\n"
            "    assert missing == []\n"
        ),
        (
            "def has_nocheck(path):\n"
            "    return 'nocheck: size' in path.read_text()\n"
            "\n"
            "\n"
            "def test_every_file_stays_short():\n"
            "    long = []\n"
            "    for path in sorted(Path('src').glob('*.py')):\n"
            "        if path.read_bytes().count(b'\\n') > MAX_LINES and not has_nocheck(path):\n"
            "            long.append(path.name)\n"
            "    assert long == []\n"
        ),
    ),
}


def first_lines(source: str) -> list:
    return [index for index, line in enumerate(source.splitlines(), start=1) if line.startswith("def test_")]


@pytest.mark.parametrize("case", sorted(CASES))
def test_only_the_positive_case_of_a_rule_is_flagged(target, case):
    positive, negative = (HEAD + source for source in CASES[case])
    target.write(POSITIVE, positive)
    target.write("tests/test_negative.py", negative)
    target.commit()
    assert findings_of_rule(target.check("--all", "--json"), RULE) == [(POSITIVE, line) for line in first_lines(positive)]


def test_a_helper_imported_from_another_module_is_followed(target):
    target.write("tests/helpers.py", "from pathlib import Path\n\n\ndef role_text():\n    return Path('role.yml').read_text()\n")
    target.write("app/render.py", "from pathlib import Path\n\n\ndef render():\n    return Path('role.yml').read_text().upper()\n")
    target.write(
        "tests/test_imported.py",
        "from app.render import render\n"
        "from tests.helpers import role_text\n"
        "\n"
        "\n"
        "def test_role_names_become():\n"
        "    assert 'become' in role_text()\n"
        "\n"
        "\n"
        "def test_render_names_become():\n"
        "    assert 'BECOME' in render()\n",
    )
    target.commit()
    assert findings_of_rule(target.check("--all", "--json"), RULE) == [("tests/test_imported.py", 5)]
