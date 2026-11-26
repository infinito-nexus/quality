import pytest

from tests.integration.support import findings_of_rule

RULE = "test.text-presence"
PYTHON = (
    "import json\n"
    "import re\n"
    "import subprocess\n"
    "import unittest\n"
    "from pathlib import Path\n"
    "\n"
    "ROLE = Path('role.yml').read_text()\n"
    "\n"
    "\n"
    "def section(text, name):\n"
    "    return text.split(f'[{name}]', 1)[1].split('[', 1)[0]\n"
    "\n"
    "\n"
    "def test_role_text():\n"
    "    content = Path('role.yml').read_text()\n"
    "    assert 'become: true' in content\n"
    "\n"
    "\n"
    "def test_role_text_read_inline():\n"
    "    assert 'become' in Path('role.yml').read_text(encoding='utf-8')\n"
    "\n"
    "\n"
    "def test_role_text_with_open():\n"
    "    with open('role.yml', encoding='utf-8') as handle:\n"
    "        content = handle.read()\n"
    "    assert 'become' in content.lower()\n"
    "\n"
    "\n"
    "def test_every_role_names_its_owner():\n"
    "    missing = []\n"
    "    for path in sorted(Path('roles').glob('*/meta.yml')):\n"
    "        if 'owner:' not in path.read_text():\n"
    "            missing.append(path.name)\n"
    "    assert missing == []\n"
    "\n"
    "\n"
    "def test_the_scan_reaches_an_owner():\n"
    "    matched = [path for path in Path('roles').glob('*.yml') if 'owner:' in path.read_text()]\n"
    "    assert matched\n"
    "\n"
    "\n"
    "def test_section_holds_the_key():\n"
    "    assert 'key = 1' in section(Path('setup.cfg').read_text(), 'tool')\n"
    "\n"
    "\n"
    "def test_module_constant_names_become():\n"
    "    assert 'become' in ROLE\n"
    "\n"
    "\n"
    "def test_order_of_the_tasks():\n"
    "    text = Path('role.yml').read_text()\n"
    "    assert text.index('install') < text.index('start')\n"
    "\n"
    "\n"
    "def test_become_is_set_once():\n"
    "    assert Path('role.yml').read_text().count('become') == 1\n"
    "\n"
    "\n"
    "def test_image_is_extracted():\n"
    "    assert re.findall(r'image: (\\S+)', Path('compose.yml').read_text()) == ['nginx']\n"
    "\n"
    "\n"
    "class RoleTest(unittest.TestCase):\n"
    "    def setUp(self):\n"
    "        self.text = Path('role.yml').read_text()\n"
    "\n"
    "    def test_role_text_in_a_case(self):\n"
    "        content = Path('role.yml').read_text()\n"
    "        self.assertIn('become', content)\n"
    "        self.assertNotIn('debug', content)\n"
    "\n"
    "    def test_set_up_text_names_become(self):\n"
    "        self.assertIn('become', self.text)\n"
    "\n"
    "    def test_conf_text(self):\n"
    "        content = read_text(str(self._conf_path()))\n"
    "        self.assertIn('lua', content)\n"
    "\n"
    "    def test_mirror_writes_its_stanza(self):\n"
    "        mirror(self.path)\n"
    "        text = Path(self.path).read_text()\n"
    "        self.assertIn('urgency=medium', text)\n"
    "\n"
    "    def test_apply_keeps_the_vault_tag(self):\n"
    "        written = self.apply('tor')\n"
    "        out = written.read_text()\n"
    "        self.assertIn('!vault', out)\n"
    "\n"
    "    def test_planted_script_keeps_the_secret(self):\n"
    "        text = Path('members.sh').read_text()\n"
    "        self.assertIn('list', text)\n"
    "        self.assertIn('client-secret', self.leftovers())\n"
    "\n"
    "    def test_failed_apply_warns(self):\n"
    "        _calls, stderr = self.step('apply')\n"
    "        self.assertNotIn('make ', stderr)\n"
    "        self.assertIn('is not running', Path('apply.sh').read_text())\n"
    "\n"
    "\n"
    "def test_parsed():\n"
    "    content = Path('role.json').read_text()\n"
    "    assert 'become' in json.loads(content)\n"
    "\n"
    "\n"
    "def test_runtime():\n"
    "    expected = Path('out.txt').read_text()\n"
    "    assert expected in subprocess.run(['tool'], capture_output=True, text=True).stdout\n"
    "\n"
    "\n"
    "def test_policy():\n"
    "    content = Path('role.yml').read_text()\n"
    "    assert 'debug' not in content\n"
    "\n"
    "\n"
    "def test_equality():\n"
    "    content = Path('role.yml').read_text()\n"
    "    assert 'become' in content\n"
    "    assert version() == '1.0'\n"
    "\n"
    "\n"
    "def test_wrote_fixture(tmp_path):\n"
    "    (tmp_path / 'role.yml').write_text('become: true')\n"
    "    assert 'become' in (tmp_path / 'role.yml').read_text()\n"
    "\n"
    "\n"
    "def test_no_role_keeps_debug():\n"
    "    offenders = [path.name for path in Path('roles').glob('*.yml') if 'debug' in path.read_text()]\n"
    "    assert offenders == []\n"
    "\n"
    "\n"
    "def test_every_used_variable_is_defined():\n"
    "    used = set(re.findall(r'\\{\\{ (\\w+) \\}\\}', Path('role.j2').read_text()))\n"
    "    defined = set(re.findall(r'^(\\w+):', Path('vars.yml').read_text()))\n"
    "    assert used - defined == set()\n"
    "\n"
    "\n"
    "def test_planted_control_is_caught():\n"
    "    planted = Path('role.yml').read_text().replace('become: true', 'become: false')\n"
    "    assert 'become: false' in planted\n"
    "\n"
    "\n"
    "def test_recipe_names_its_server():\n"
    "    assert 'server' in published()\n"
    "    assert 'HOST=' in Path('replay.sh').read_text()\n"
    "\n"
    "\n"
    "def role_text():\n"
    "    content = Path('role.yml').read_text()\n"
    "    assert 'become' in content\n"
)
WEB = (
    "const fs = require('fs');\n"
    "\n"
    "test('role text', () => {\n"
    "  const content = fs.readFileSync('role.yml', 'utf8');\n"
    "  expect(content).toContain('become: true');\n"
    "});\n"
    "\n"
    "test('parsed', () => {\n"
    "  const content = fs.readFileSync('role.json', 'utf8');\n"
    "  expect(Object.keys(JSON.parse(content))).toContain('become');\n"
    "});\n"
    "\n"
    "test('runtime', async ({ page }) => {\n"
    "  const expected = fs.readFileSync('title.txt', 'utf8');\n"
    "  await page.goto('/');\n"
    "  await expect(page.locator('h1')).toContainText(expected);\n"
    "});\n"
    "\n"
    "test('policy', () => {\n"
    "  const content = fs.readFileSync('role.yml', 'utf8');\n"
    "  expect(content).not.toContain('debug');\n"
    "});\n"
    "\n"
    "test('equality', () => {\n"
    "  const content = fs.readFileSync('role.yml', 'utf8');\n"
    "  expect(content).toContain('become');\n"
    "  expect(content.length).toBe(12);\n"
    "});\n"
    "\n"
    "function roleText() {\n"
    "  const content = fs.readFileSync('role.yml', 'utf8');\n"
    "  expect(content).toContain('become');\n"
    "}\n"
    "\n"
    "const ROLE = fs.readFileSync('role.yml', 'utf8');\n"
    "\n"
    "test('module constant', () => {\n"
    "  assert.ok(ROLE.includes('become'));\n"
    "});\n"
    "\n"
    "test('builtin require', () => {\n"
    "  const fs = require('node:fs');\n"
    "  assert.ok(fs.readFileSync('role.yml', 'utf8').includes('become'));\n"
    "});\n"
    "\n"
    "test('helper on a constant', () => {\n"
    "  assert.ok(names(ROLE, 'become'));\n"
    "});\n"
)
GO = (
    "package role\n"
    "\n"
    "import (\n"
    '\t"os"\n'
    '\t"os/exec"\n'
    '\t"strings"\n'
    '\t"testing"\n'
    "\n"
    '\t"gopkg.in/yaml.v3"\n'
    ")\n"
    "\n"
    "func TestRoleText(t *testing.T) {\n"
    '\tcontent, err := os.ReadFile("role.yml")\n'
    "\tif err != nil {\n"
    "\t\tt.Fatal(err)\n"
    "\t}\n"
    '\tif !strings.Contains(string(content), "become: true") {\n'
    '\t\tt.Error("become missing")\n'
    "\t}\n"
    "}\n"
    "\n"
    "func TestParsed(t *testing.T) {\n"
    '\tcontent, _ := os.ReadFile("role.yml")\n'
    "\tvar role map[string]any\n"
    "\tif err := yaml.Unmarshal(content, &role); err != nil {\n"
    "\t\tt.Fatal(err)\n"
    "\t}\n"
    '\tif !strings.Contains(string(content), "become") {\n'
    '\t\tt.Error("become missing")\n'
    "\t}\n"
    "}\n"
    "\n"
    "func TestRuntime(t *testing.T) {\n"
    '\texpected, _ := os.ReadFile("out.txt")\n'
    '\tout, _ := exec.Command("tool").Output()\n'
    "\tif !strings.Contains(string(out), string(expected)) {\n"
    '\t\tt.Error("output differs")\n'
    "\t}\n"
    "}\n"
    "\n"
    "func TestPolicy(t *testing.T) {\n"
    '\tcontent, _ := os.ReadFile("role.yml")\n'
    '\tif strings.Contains(string(content), "debug") {\n'
    '\t\tt.Error("debug left")\n'
    "\t}\n"
    "}\n"
    "\n"
    "func TestEquality(t *testing.T) {\n"
    '\tcontent, _ := os.ReadFile("role.yml")\n'
    '\tif !strings.Contains(string(content), "become") {\n'
    '\t\tt.Error("become missing")\n'
    "\t}\n"
    "\tif len(content) != 12 {\n"
    '\t\tt.Error("size")\n'
    "\t}\n"
    "}\n"
    "\n"
    "func roleText(t *testing.T) {\n"
    '\tcontent, _ := os.ReadFile("role.yml")\n'
    '\tif !strings.Contains(string(content), "become") {\n'
    '\t\tt.Error("become missing")\n'
    "\t}\n"
    "}\n"
)
RUST = (
    "use std::fs;\n"
    "use std::process::Command;\n"
    "\n"
    "#[test]\n"
    "fn role_text() {\n"
    '    let content = fs::read_to_string("role.yml").unwrap();\n'
    '    assert!(content.contains("become: true"));\n'
    "}\n"
    "\n"
    "#[test]\n"
    "fn parsed() {\n"
    '    let content = fs::read_to_string("role.toml").unwrap();\n'
    "    let role: toml::Table = toml::from_str(&content).unwrap();\n"
    '    assert!(role.contains_key("become"));\n'
    "}\n"
    "\n"
    "#[test]\n"
    "fn runtime() {\n"
    '    let expected = fs::read_to_string("out.txt").unwrap();\n'
    '    let out = Command::new("tool").output().unwrap();\n'
    "    assert!(String::from_utf8_lossy(&out.stdout).contains(&expected));\n"
    "}\n"
    "\n"
    "#[test]\n"
    "fn policy() {\n"
    '    let content = fs::read_to_string("role.yml").unwrap();\n'
    '    assert!(!content.contains("debug"));\n'
    "}\n"
    "\n"
    "#[test]\n"
    "fn equality() {\n"
    '    let content = fs::read_to_string("role.yml").unwrap();\n'
    '    assert!(content.contains("become"));\n'
    "    assert_eq!(content.len(), 12);\n"
    "}\n"
    "\n"
    "fn role_text_helper() {\n"
    '    let content = fs::read_to_string("role.yml").unwrap();\n'
    '    assert!(content.contains("become"));\n'
    "}\n"
)
JAVA = (
    "import java.nio.file.Files;\n"
    "import java.nio.file.Path;\n"
    "\n"
    "class RoleTest {\n"
    "    @Test\n"
    "    void roleText() throws Exception {\n"
    '        String content = Files.readString(Path.of("role.yml"));\n'
    '        assertTrue(content.contains("become: true"));\n'
    "    }\n"
    "\n"
    "    @Test\n"
    "    void parsed() throws Exception {\n"
    '        String content = Files.readString(Path.of("role.yml"));\n'
    "        Map<String, Object> role = new Yaml().load(content);\n"
    '        assertTrue(role.containsKey("become"));\n'
    "    }\n"
    "\n"
    "    @Test\n"
    "    void runtime() throws Exception {\n"
    '        String expected = Files.readString(Path.of("out.txt"));\n'
    '        Process process = new ProcessBuilder("tool").start();\n'
    "        assertTrue(new String(process.getInputStream().readAllBytes()).contains(expected));\n"
    "    }\n"
    "\n"
    "    @Test\n"
    "    void policy() throws Exception {\n"
    '        String content = Files.readString(Path.of("role.yml"));\n'
    '        assertFalse(content.contains("debug"));\n'
    "    }\n"
    "\n"
    "    @Test\n"
    "    void equality() throws Exception {\n"
    '        String content = Files.readString(Path.of("role.yml"));\n'
    '        assertTrue(content.contains("become"));\n'
    "        assertEquals(12, content.length());\n"
    "    }\n"
    "\n"
    "    void roleTextHelper() throws Exception {\n"
    '        String content = Files.readString(Path.of("role.yml"));\n'
    '        assertTrue(content.contains("become"));\n'
    "    }\n"
    "}\n"
)
PHP = (
    "<?php\n"
    "\n"
    "final class RoleTest extends TestCase\n"
    "{\n"
    "    public function testRoleText(): void\n"
    "    {\n"
    "        $content = file_get_contents('role.yml');\n"
    "        $this->assertStringContainsString('become: true', $content);\n"
    "    }\n"
    "\n"
    "    public function testParsed(): void\n"
    "    {\n"
    "        $role = json_decode(file_get_contents('role.json'), true);\n"
    "        $this->assertArrayHasKey('become', $role);\n"
    "    }\n"
    "\n"
    "    public function testRuntime(): void\n"
    "    {\n"
    "        $expected = file_get_contents('out.txt');\n"
    "        $this->assertStringContainsString($expected, shell_exec('tool'));\n"
    "    }\n"
    "\n"
    "    public function testPolicy(): void\n"
    "    {\n"
    "        $content = file_get_contents('role.yml');\n"
    "        $this->assertStringNotContainsString('debug', $content);\n"
    "    }\n"
    "\n"
    "    public function testEquality(): void\n"
    "    {\n"
    "        $content = file_get_contents('role.yml');\n"
    "        $this->assertStringContainsString('become', $content);\n"
    "        $this->assertSame(12, strlen($content));\n"
    "    }\n"
    "\n"
    "    public function roleText(): void\n"
    "    {\n"
    "        $content = file_get_contents('role.yml');\n"
    "        $this->assertStringContainsString('become', $content);\n"
    "    }\n"
    "}\n"
)
RUBY = (
    "class RoleTest < Minitest::Test\n"
    "  def test_role_text\n"
    '    content = File.read("role.yml")\n'
    '    assert_includes content, "become: true"\n'
    "  end\n"
    "\n"
    "  def test_parsed\n"
    '    role = JSON.parse(File.read("role.json"))\n'
    '    assert_includes role.keys, "become"\n'
    "  end\n"
    "\n"
    "  def test_runtime\n"
    '    expected = File.read("out.txt")\n'
    "    assert_includes `tool`, expected\n"
    "  end\n"
    "\n"
    "  def test_policy\n"
    '    content = File.read("role.yml")\n'
    '    refute_includes content, "debug"\n'
    "  end\n"
    "\n"
    "  def test_equality\n"
    '    content = File.read("role.yml")\n'
    '    assert_includes content, "become"\n'
    "    assert_equal 12, content.length\n"
    "  end\n"
    "\n"
    "  def role_text\n"
    '    content = File.read("role.yml")\n'
    '    assert_includes content, "become"\n'
    "  end\n"
    "end\n"
)
BASH = (
    "#!/bin/bash\n"
    "\n"
    "test_role_text() {\n"
    "  grep -q 'become: true' role.yml || fail 'become missing'\n"
    "}\n"
    "\n"
    "test_parsed() {\n"
    "  assertEquals 'true' \"$(yq '.become' role.yml)\"\n"
    "}\n"
    "\n"
    "test_runtime() {\n"
    "  assertContains \"$(./deploy.sh)\" 'done'\n"
    "}\n"
    "\n"
    "test_policy() {\n"
    "  grep -q 'debug' role.yml && fail 'debug left'\n"
    "}\n"
    "\n"
    "test_equality() {\n"
    "  grep -q 'become' role.yml || fail 'become missing'\n"
    '  assertEquals 12 "$(wc -c < role.yml)"\n'
    "}\n"
    "\n"
    "role_text() {\n"
    "  grep -q 'become' role.yml || fail 'become missing'\n"
    "}\n"
)
CASES = {
    "test_role.py": (PYTHON, [14, 19, 23, 29, 37, 42, 46, 50, 55, 59, 67, 72, 75]),
    "role.test.js": (WEB, [3, 37, 41, 46]),
    "role.test.ts": (WEB, [3, 37, 41, 46]),
    "role.test.tsx": (WEB, [3, 37, 41, 46]),
    "role_test.go": (GO, [12]),
    "role.rs": (RUST, [5]),
    "RoleTest.java": (JAVA, [6]),
    "RoleTest.php": (PHP, [5]),
    "role_test.rb": (RUBY, [2]),
    "role_test.sh": (BASH, [3]),
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_only_a_test_that_reads_a_file_for_text_is_flagged(target, name):
    source, lines = CASES[name]
    target.write(name, source)
    target.commit()
    assert findings_of_rule(target.check("--all", "--json"), RULE) == [(name, line) for line in lines]
