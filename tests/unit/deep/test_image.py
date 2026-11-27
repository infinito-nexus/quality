import pytest

from quality.image import engines
from quality.image.report import image_row, split_ref
from quality.image.scan import first_line, merged

OSV_STDERR = (
    b'Scanning local image tarball "/x/a.tar"\n'
    b"Starting filesystem walk for root: \n"
    b"could not load db for Alpine ecosystem: unable to fetch OSV database\n"
    b"Error during extraction: (extracting as vulnmatch/osvlocal) unable to fetch OSV database\n"
)


def test_first_line_skips_progress_lines():
    assert first_line(OSV_STDERR) == "could not load db for Alpine ecosystem: unable to fetch OSV database"
    assert first_line(b"progress\nlast words\n") == "last words"
    assert first_line(b"") == "no error output"


@pytest.mark.parametrize(
    ("ref", "expected"),
    [
        ("nginx", ("nginx:latest", "nginx", "latest")),
        ("nginx:1.27", ("nginx:1.27", "nginx", "1.27")),
        ("registry.example/x/nginx:1.27", ("nginx:1.27", "registry.example/x/nginx", "1.27")),
        ("localhost:5000/nginx", ("nginx:latest", "localhost:5000/nginx", "latest")),
        ("mirror.example/nginx:1.27@sha256:" + "a" * 64, ("nginx:1.27", "mirror.example/nginx", "1.27")),
    ],
)
def test_split_ref(ref, expected):
    assert split_ref(ref) == expected


def test_canonical_prefers_a_cve_id_from_the_id_or_its_aliases():
    assert engines.canonical("DEBIAN-CVE-2024-1234", []) == "CVE-2024-1234"
    assert engines.canonical("GHSA-abcd", ["PYSEC-1", "CVE-2023-9"]) == "CVE-2023-9"
    assert engines.canonical("GHSA-abcd", []) == "GHSA-abcd"


def test_cvss_scores_map_to_severities():
    assert [engines.cvss_severity(score) for score in ("9.8", "7.0", "5", "0.1", "0", "", None)] == [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        engines.UNKNOWN,
        engines.UNKNOWN,
        engines.UNKNOWN,
    ]


def test_highest_orders_versions_naturally():
    assert engines.highest(["3.0.9", "3.0.14", ""]) == "3.0.14"
    assert engines.highest(["", ""]) == ""


def test_merge_joins_both_engines_ids_with_the_gravest_severity_and_highest_fix():
    rows = [
        ("openssl", "3.0.2", "CVE-1", "HIGH", "3.0.13", "trivy"),
        ("openssl", "3.0.2", "CVE-1", "CRITICAL", "3.0.15", "osv-scanner"),
        ("openssl", "3.0.2", "CVE-2", engines.UNKNOWN, "", "osv-scanner"),
    ]
    assert merged(rows) == {
        ("openssl", "3.0.2"): {
            "engines": {"trivy", "osv-scanner"},
            "vulnerabilities": {
                "CVE-1": {"severity": "CRITICAL", "fixed": "3.0.15"},
                "CVE-2": {"severity": engines.UNKNOWN, "fixed": ""},
            },
        }
    }


def test_image_row_counts_severities_and_fixes():
    ids = {
        "CVE-1": {"severity": "CRITICAL", "fixes": {"openssl": "3.0.15"}},
        "CVE-2": {"severity": "HIGH", "fixes": {"openssl": "3.0.14", "libssl": "3.0.14"}},
        "CVE-3": {"severity": "HIGH", "fixes": {}},
        "CVE-4": {"severity": "LOW", "fixes": {"zlib": "1.3"}},
    }
    row = image_row({"image": "nginx", "tag": "1.27", "engines": {"trivy"}, "ids": ids})
    assert row["severities"] == {"C": 1, "H": 2, "M": 0, "L": 1, "?": 0}
    assert (row["fixed"], row["total"]) == (3, 4)
    assert row["packages"] == [{"package": "openssl", "fixed": "3.0.15", "ids": 2}, {"package": "libssl", "fixed": "3.0.14", "ids": 1}]
    assert row["nofix"] == ["CVE-3"]


def test_trivy_rows_take_the_highest_of_several_fixed_versions():
    report = b'{"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-1", "PkgName": "a", "InstalledVersion": "1", "Severity": "HIGH", "FixedVersion": "1.9, 1.10"}]}]}'
    assert engines.trivy_rows(report) == [("a", "1", "CVE-1", "HIGH", "1.10")]
