import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from quality import db
from tests.integration.support import path_with, quality, write_shim

REGISTRY_REF = "registry.example/x/nginx:1.27"
MIRROR_REF = "mirror.example/nginx:1.27"
ABSENT_REF = "nowhere.example/thing:1"
NGINX_ID = "sha256:" + "a" * 64
TRIVY_REPORT = {
    "Results": [
        {
            "Vulnerabilities": [
                {"VulnerabilityID": "CVE-2024-0001", "PkgName": "openssl", "InstalledVersion": "3.0.2", "Severity": "CRITICAL", "FixedVersion": "3.0.13"},
                {"VulnerabilityID": "CVE-2024-0002", "PkgName": "openssl", "InstalledVersion": "3.0.2", "Severity": "HIGH", "FixedVersion": "3.0.9, 3.0.14"},
                {"VulnerabilityID": "CVE-2024-0003", "PkgName": "zlib", "InstalledVersion": "1.2.13", "Severity": "MEDIUM"},
                {"VulnerabilityID": "CVE-2024-0004", "PkgName": "libx", "InstalledVersion": "1.0", "Severity": "LOW", "FixedVersion": "1.1"},
            ]
        }
    ]
}
DEBIAN = "Debian:12"
ENGINE_ERROR = 'echo "Scanning local image tarball" >&2\necho "FATAL  unable to open archive" >&2\necho "second line" >&2\nexit 2'


def osv_affected(ecosystem: str, fixed: str) -> dict:
    return {"package": {"name": "openssl", "ecosystem": ecosystem}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": fixed}]}]}


OSV_REPORT = {
    "results": [
        {
            "packages": [
                {
                    "package": {"name": "openssl", "version": "3.0.2", "ecosystem": DEBIAN},
                    "groups": [{"ids": ["DEBIAN-CVE-2024-0001"], "max_severity": "9.8"}, {"ids": ["GHSA-abcd"], "max_severity": ""}],
                    "vulnerabilities": [
                        {"id": "DEBIAN-CVE-2024-0001", "affected": [osv_affected(DEBIAN, "3.0.15"), osv_affected("Debian:11", "9.9")]},
                        {"id": "GHSA-abcd", "aliases": ["CVE-2024-0005"]},
                    ],
                }
            ]
        }
    ]
}


class Fakes:
    def __init__(self, root: Path, failing: str | None = None):
        """
        Args:
            root: Directory for the shims, their reports, the call log and a bundle.
            failing: trivy or osv-scanner to make fail with two error lines, or None.
        """
        self.root = root
        self.log = root / "calls.log"
        self.log.touch()
        shims = root / "bin"
        (root / "trivy.json").write_text(json.dumps(TRIVY_REPORT), encoding="utf-8")
        (root / "osv.json").write_text(json.dumps(OSV_REPORT), encoding="utf-8")
        write_shim(shims, "docker", self.docker_body())
        reports = {
            "trivy": f'cat "{root}/trivy.json"',
            "osv-scanner": f'eval last=\\${{$#}}\ntar -tf "$last" >> "{self.log}" 2>/dev/null\ncat "{root}/osv.json"\nexit 1',
        }
        for name, report in reports.items():
            body = ENGINE_ERROR if name == failing else report
            write_shim(shims, name, f'echo "{name} $*" >> "{self.log}"\n{body}')
        self.path = path_with(shims)
        self.db = root / "db"
        self.db.mkdir()
        db.write_manifest(self.db, datetime.now(timezone.utc), db.tree_digest(self.db))

    def docker_body(self) -> str:
        return "\n".join(
            [
                f'echo "docker $*" >> "{self.log}"',
                'if [ "$1" = image ] && [ "$2" = inspect ]; then',
                f'  case "$6" in "{REGISTRY_REF}"|"{MIRROR_REF}") echo {NGINX_ID}; exit 0;; esac',
                '  echo "Error: No such image: $6" >&2',
                "  exit 1",
                "fi",
                'if [ "$1" = save ]; then printf docker-archive > "$3"; exit 0; fi',
                "exit 3",
            ]
        )

    def run(self, *args: str, db_dir: Path | None = None):
        location = self.db if db_dir is None else db_dir
        return quality(self.root, "image", *args, "--db", str(location), path_value=self.path)

    def calls(self, program: str) -> list:
        return [line for line in self.log.read_text(encoding="utf-8").splitlines() if line.startswith(f"{program} ")]


def findings_without_path(result) -> list:
    return [{key: value for key, value in item.items() if key != "path"} for item in json.loads(result.stdout)["findings"]]


@pytest.fixture
def fakes(tmp_path):
    return Fakes(tmp_path)


def test_a_local_ref_is_saved_once_per_digest_and_reported(fakes):
    result = fakes.run(REGISTRY_REF, MIRROR_REF, REGISTRY_REF, "--json")
    assert result.returncode == 1, result.stderr
    assert len([call for call in fakes.calls("docker") if call.startswith("docker save")]) == 1
    document = json.loads(result.stdout)
    openssl = [item for item in document["findings"] if item["path"] == REGISTRY_REF and item["package"] == "openssl"]
    assert len(openssl) == 1
    assert openssl[0]["rule"] == "security.vulnerable-image"
    assert (openssl[0]["installed"], openssl[0]["fixed"]) == ("3.0.2", "3.0.15")
    assert sorted(openssl[0]["vulnerabilities"]) == ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0005"]
    assert openssl[0]["engines"] == ["osv-scanner", "trivy"]
    assert openssl[0]["message"] == "openssl 3.0.2 (fixed in 3.0.15): CVE-2024-0001, CVE-2024-0002, CVE-2024-0005"
    assert {item["path"] for item in document["findings"]} == {REGISTRY_REF, MIRROR_REF}
    assert len(fakes.calls("trivy")) == 1
    assert document["unscanned"] == []


def test_archive_and_oci_layout_give_the_findings_of_the_daemon_ref(fakes):
    archive = fakes.root / "nginx.tar"
    archive.write_bytes(b"docker-archive")
    layout = fakes.root / "layout"
    (layout / "blobs").mkdir(parents=True)
    (layout / "index.json").write_text("{}", encoding="utf-8")
    (layout / "oci-layout").write_text("{}", encoding="utf-8")
    daemon = findings_without_path(fakes.run(REGISTRY_REF, "--json"))
    assert findings_without_path(fakes.run(str(archive), "--json")) == daemon
    assert findings_without_path(fakes.run(str(layout), "--json")) == daemon
    trivy_inputs = [call.split("--input ")[1].split(" ")[0] for call in fakes.calls("trivy")]
    assert trivy_inputs[1:] == [str(archive), str(layout)]
    assert "index.json" in fakes.log.read_text(encoding="utf-8")


def test_a_ref_missing_locally_is_unscanned_and_never_pulled(fakes):
    result = fakes.run(ABSENT_REF, "--json")
    assert result.returncode == 1, result.stderr
    assert json.loads(result.stdout)["unscanned"] == [{"path": ABSENT_REF, "reason": "not local"}]
    assert not [call for call in fakes.calls("docker") if " pull" in call or call.startswith("docker save")]
    assert fakes.calls("trivy") == []
    assert fakes.calls("osv-scanner") == []


def test_engines_run_offline_on_the_archive_only(fakes):
    fakes.run(REGISTRY_REF)
    trivy = fakes.calls("trivy")[0].split()
    osv = fakes.calls("osv-scanner")[0].split()
    assert {"--input", "--offline-scan", "--skip-db-update"} <= set(trivy)
    assert {"--archive", "--offline", "--offline-vulnerabilities"} <= set(osv)
    assert REGISTRY_REF not in trivy + osv


def test_a_missing_bundle_exits_2_naming_db_update(fakes):
    result = fakes.run(REGISTRY_REF, db_dir=fakes.root / "none")
    assert result.returncode == 2
    assert "quality db update" in result.stderr
    assert fakes.calls("docker") == []


@pytest.mark.parametrize(("failing", "working"), [("trivy", "osv-scanner"), ("osv-scanner", "trivy")])
def test_an_engine_error_is_an_unscanned_entry_with_its_first_line(tmp_path, failing, working):
    fakes = Fakes(tmp_path, failing)
    result = fakes.run(REGISTRY_REF, "--json")
    assert result.returncode == 1
    document = json.loads(result.stdout)
    assert document["unscanned"] == [{"path": REGISTRY_REF, "reason": f"{failing}: FATAL  unable to open archive"}]
    assert {engine for item in document["findings"] for engine in item["engines"]} == {working}


def test_report_joins_registry_and_mirror_and_lists_unscanned(fakes):
    first, second = fakes.root / "a.json", fakes.root / "b.json"
    first.write_text(fakes.run(REGISTRY_REF, "--json").stdout, encoding="utf-8")
    second.write_text(fakes.run(MIRROR_REF, ABSENT_REF, "--json").stdout, encoding="utf-8")
    text = quality(fakes.root, "image", "report", str(first), str(second))
    assert text.returncode == 0, text.stderr
    assert text.stdout.splitlines() == [
        "image\ttag\tsev\tfix\tnofix\tengines",
        "registry.example/x/nginx\t1.27\tC1 H1 M1 L1 ?1\t3/5 openssl>3.0.15; libx>1.1\tCVE-2024-0003,CVE-2024-0005\tosv-scanner,trivy",
        "unscanned:",
        f"{ABSENT_REF}: not local",
    ]
    document = json.loads(quality(fakes.root, "image", "report", str(first), str(second), "--json").stdout)
    assert document["images"] == [
        {
            "image": "registry.example/x/nginx",
            "tag": "1.27",
            "severities": {"C": 1, "H": 1, "M": 1, "L": 1, "?": 1},
            "fixed": 3,
            "total": 5,
            "packages": [{"package": "openssl", "fixed": "3.0.15", "ids": 2}, {"package": "libx", "fixed": "1.1", "ids": 1}],
            "nofix": ["CVE-2024-0003", "CVE-2024-0005"],
            "engines": ["osv-scanner", "trivy"],
        }
    ]
    assert document["unscanned"] == [{"image": ABSENT_REF, "reason": "not local"}]


def test_report_refuses_a_file_that_is_no_image_report(fakes):
    other = fakes.root / "other.json"
    other.write_text('{"findings": []}', encoding="utf-8")
    result = quality(fakes.root, "image", "report", str(other))
    assert result.returncode == 2
    assert "quality image --json" in result.stderr
