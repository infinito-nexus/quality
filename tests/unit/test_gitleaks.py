import json

import pytest

from quality import QualityError
from quality.adapters import gitleaks
from quality.adapters.base import Bound, Command
from quality.ruledata import ANY_KIND, Binding, build_rule
from quality.snapshot import Snapshot, textual

RULE = build_rule(
    {
        "id": "security.secret",
        "severity": "critical",
        "summary": "fixture",
        "hard": True,
        "enforcer": {ANY_KIND: {"tool": "gitleaks"}},
    },
    "fixture",
    {},
)
BINDING = Binding(RULE, "gitleaks", {"tool": "gitleaks"}, frozenset({ANY_KIND}))
FILES = {
    ".gitleaks.toml": b"content of .gitleaks.toml\nsecond line\n",
    ".gitleaksignore": b"\x7fELF\x02\x01\x01\x00binary",
    "node_modules/pkg/a.js": b"content of a.js\nsecond line\n",
}
NAMES = list(FILES)
BOUND = Bound(BINDING, NAMES, dict.fromkeys(NAMES, frozenset()))
NAMED = ["file.toml", "file", "file.js"]
FIRST = [f"scanning path path={index}/0/path/{name}" for index, name in enumerate(NAMES)]
SECOND = [
    *FIRST,
    *(f"scanning path path={index}/0/named/{name}" for index, name in enumerate(NAMED)),
    "scanning path path=0/0/content",
    "scanning path path=2/0/content",
]


def snapshot_of(root, files: dict) -> Snapshot:
    for path, data in files.items():
        destination = root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
    return Snapshot(root, dict.fromkeys(files), [], set(), None, set(), {})


def trace(*events: str) -> bytes:
    return "".join(f"9:31AM TRC {event}\n" for event in events).encode()


def command_with(*events: str, rescan: bool) -> Command:
    return Command([], NAMES, [BOUND], trace(*events), rescan)


def test_any_kind_binds_kindless_files():
    python = Binding(RULE, "ruff", {}, frozenset({"python"}))
    assert BINDING.binds(frozenset())
    assert BINDING.binds(frozenset({"python"}))
    assert not python.binds(frozenset())
    assert python.binds(frozenset({"python", "shell"}))


@pytest.mark.parametrize(
    ("data", "text"),
    [
        (b"SQLite notes\n", b"SQLite notes\n"),
        (b"%PDF-1.4\nTOKEN=x\n", b"%PDF-1.4\nTOKEN=x\n"),
        (b"caf\xe9\n", b"caf\xe9\n"),
        (b"\xef\xbb\xbfa\n", b"\xef\xbb\xbfa\n"),
        ("\N{ZERO WIDTH NO-BREAK SPACE}a\r\n".encode("utf-16-le"), b"a\r\n"),
        ("\N{ZERO WIDTH NO-BREAK SPACE}a\n".encode("utf-16-be"), b"a\n"),
        ("\N{ZERO WIDTH NO-BREAK SPACE}a\n".encode("utf-32-le"), b"a\n"),
        (b"a\x00b", None),
        (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR", None),
        ("a\n".encode("utf-16-le"), None),
    ],
    ids=[
        "sqlite",
        "pdf",
        "latin1",
        "utf8-bom",
        "utf16le",
        "utf16be",
        "utf32le",
        "nul",
        "png",
        "no-bom",
    ],
)
def test_runner_decides_text(data, text):
    assert textual(data) == text


def test_first_run_stages_own_paths_and_second_adds_neutral_names(tmp_path):
    snapshot = snapshot_of(tmp_path / "snapshot", FILES)
    for rescan in (False, True):
        work = tmp_path / f"work-{rescan}"
        work.mkdir()
        command = command_with(rescan=rescan)
        assert gitleaks.operands(command, snapshot, work) == ["--gitleaks-ignore-path", ".", "--", "."]
        assert sorted(entry.name for entry in work.iterdir()) == ["0", "1", "2"]
        for index, (path, named) in enumerate(zip(NAMES, NAMED, strict=True)):
            piece = work / str(index) / "0"
            own = piece / "path" / path
            padding = b"\n" * gitleaks.SNIFF if rescan and index != 1 else b""
            assert own.read_bytes() == padding + FILES[path]
            assert (own.stat().st_ino == (snapshot.root / path).stat().st_ino) == (index == 1)
            assert (piece / "named").exists() == rescan
            assert (piece / "content").exists() == (rescan and index != 1)
            if rescan:
                assert (piece / "named" / named).stat().st_ino == own.stat().st_ino


@pytest.mark.parametrize("padded", [False, True])
def test_windows_cut_at_line_starts_overlap_and_map_lines_back(tmp_path, padded):
    lines = [f"line {number:06d} {'x' * (number % 900)}" for number in range(1, 2000)]
    data = "\n".join(lines).encode()
    snapshot = snapshot_of(tmp_path / "snapshot", {"big.txt": data})
    layout = gitleaks.pieces("big.txt", snapshot, padded)
    padding = b"\n" * gitleaks.SNIFF if padded else b""
    assert len(layout) > 2
    for piece in layout:
        assert len(piece.data) <= gitleaks.WINDOW
        assert piece.data.startswith(padding)
        body = piece.data[len(padding) :]
        first = len(padding) + 1
        assert body.split(b"\n")[0] == lines[first + piece.offset - 1].encode()
    spans = gitleaks.bounds(data, gitleaks.WINDOW - len(padding))
    for (_, end), (start, _) in zip(spans, spans[1:], strict=False):
        assert data[end - 1 : end] == b"\n"
        assert data[start - 1 : start] == b"\n"
        assert end - start >= gitleaks.PEEK
    assert spans[-1][1] == len(data)


def test_a_line_longer_than_the_overlap_is_cut_inside_once_it_began_earlier():
    data = b"short\n" + b"m" * 300_000 + b"\nend\n"
    spans = gitleaks.bounds(data, gitleaks.WINDOW)
    assert spans[:2] == [(0, gitleaks.WINDOW), (6, 6 + gitleaks.WINDOW)]
    assert spans[2][0] == 6 + gitleaks.WINDOW - gitleaks.PEEK
    assert all(end - start >= gitleaks.PEEK for (_, end), (start, _) in zip(spans, spans[1:], strict=False))
    assert spans[-1][1] == len(data)


@pytest.mark.parametrize("limit", [2 * gitleaks.PEEK, gitleaks.PEEK])
def test_a_window_within_two_overlaps_fails_fast(limit):
    with pytest.raises(QualityError):
        gitleaks.bounds(b"a\n" * 100_000, limit)


def test_a_byte_order_mark_adds_the_decoded_copy(tmp_path):
    files = {
        "bom.env": b"\xff\xfeGITHUB_TOKEN=xy\n",
        "wide.ps1": "\N{ZERO WIDTH NO-BREAK SPACE}a\nb\n".encode("utf-16-le"),
        "plain.txt": b"a\n",
    }
    snapshot = snapshot_of(tmp_path / "snapshot", files)
    for name, data in files.items():
        copies = [piece.data for piece in gitleaks.pieces(name, snapshot, False)]
        decoded = textual(data)
        assert copies == ([data] if decoded == data else [data, decoded])


@pytest.mark.parametrize(
    ("name", "named"),
    [
        ("k8s/gitleaks.toml.yaml", "file.yaml"),
        ("verification-metadata.xml", "file.xml"),
        ("Database.refactorlog", "file.refactorlog"),
        ("gradlew", "file"),
        ("odd.a b", "file"),
        ("src/NuGet.Config", "nuget.config"),
        ("my.nuget.config", "nuget.config"),
    ],
)
def test_named_copy_keeps_only_the_suffix(name, named):
    assert gitleaks.named_copy(name) == named


def test_first_run_hands_skipped_own_paths_to_the_second(tmp_path):
    snapshot = snapshot_of(tmp_path / "snapshot", FILES)
    events = [
        "scanning path path=1/0/path/.gitleaksignore",
        "skipping binary file mime_type=application/x-executable path=1/0/path/.gitleaksignore",
        "skipping file: global allowlist path=0/0/path/.gitleaks.toml",
        "skipping binary file mime_type=application/dicom path=2/0/path/node_modules/pkg/a.js",
    ]
    command = command_with(*events, rescan=False)
    stdout = json.dumps([{"File": "2/0/path/node_modules/pkg/a.js", "StartLine": 1, "RuleID": "pat"}])
    assert gitleaks.parse(stdout.encode(), command, snapshot) == []
    assert gitleaks.rescan(command, snapshot) == [".gitleaks.toml", "node_modules/pkg/a.js"]
    assert gitleaks.rescan(command_with(*FIRST, rescan=False), snapshot) == []


def test_second_run_trusts_the_own_path_unless_gitleaks_skipped_it(tmp_path):
    snapshot = snapshot_of(tmp_path / "snapshot", FILES)
    events = [event for event in SECOND if not event.endswith("0/0/path/.gitleaks.toml")]
    command = command_with(
        *events, "skipping file: global allowlist path=0/0/path/.gitleaks.toml", rescan=True
    )
    line_two = gitleaks.SNIFF + 2
    stdout = json.dumps(
        [
            {"File": "2/0/path/node_modules/pkg/a.js", "StartLine": line_two, "RuleID": "pat"},
            {"File": "2/0/content", "StartLine": line_two, "RuleID": "generic"},
            {"File": "1/0/path/.gitleaksignore", "StartLine": 1, "RuleID": "pat"},
            {"File": "0/0/path/.gitleaks.toml", "StartLine": line_two, "RuleID": "pat"},
            {"File": "0/0/named/file.toml", "StartLine": 0, "RuleID": "path-only"},
        ]
    ).encode()
    hits = gitleaks.parse(stdout, command, snapshot)
    assert [(hit.path, hit.line, hit.message) for hit in hits] == [
        ("node_modules/pkg/a.js", 2, "pat"),
        (".gitleaksignore", 1, "pat"),
        (".gitleaks.toml", None, "path-only"),
    ]


def test_unread_names_binary_blobs_only(tmp_path):
    snapshot = snapshot_of(tmp_path / "snapshot", FILES)
    assert gitleaks.unread(command_with(*FIRST, rescan=False), snapshot) == {
        ".gitleaksignore": gitleaks.BINARY
    }


@pytest.mark.parametrize(
    ("events", "rescan"),
    [
        (FIRST[:-1], False),
        (SECOND[:-1], True),
        ([*SECOND, "skipping binary file mime_type=application/x-tar path=0/0/content"], True),
        ([*SECOND, "skipping binary file mime_type=application/pdf path=2/0/named/file.js"], True),
        (
            [*SECOND, "skipping binary file mime_type=application/pdf path=2/0/path/node_modules/pkg/a.js"],
            True,
        ),
        ([*FIRST, "skipping file: too large path=1/0/path/.gitleaksignore"], False),
        ([*FIRST, 'scanning path path="2/named/x path=9/0/content"', "ERR failed"], False),
    ],
    ids=[
        "silent-first",
        "silent-second",
        "text-skipped",
        "text-named-binary",
        "text-own-binary-twice",
        "unknown-skip",
        "error-line",
    ],
)
def test_parse_fails_closed(events, rescan, tmp_path):
    snapshot = snapshot_of(tmp_path / "snapshot", FILES)
    complete = FIRST if not rescan else SECOND
    assert gitleaks.parse(b"[]", command_with(*complete, rescan=rescan), snapshot) == []
    log = trace(*events).replace(b"TRC ERR failed", b"ERR failed")
    command = Command([], NAMES, [BOUND], log, rescan)
    with pytest.raises(QualityError):
        gitleaks.parse(b"[]", command, snapshot)
