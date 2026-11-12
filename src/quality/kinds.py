import re
from dataclasses import dataclass
from pathlib import PurePosixPath

VERSION_SUFFIX = re.compile(r"[0-9.]+$")
CODE_KIND = "code"


def interpreter_name(word: str) -> str:
    return VERSION_SUFFIX.sub("", PurePosixPath(word.removeprefix("-S")).name)


@dataclass(frozen=True, eq=False)
class KindMap:
    extensions: dict
    shebangs: dict
    globs: dict
    names: dict
    known: dict
    binary_names: list
    code: tuple
    markers: dict
    templates: tuple

    def kinds_of(self, path: str, first_line: bytes) -> frozenset:
        """
        Args:
            path: Path relative to the repository root.
            first_line: Start of the file, read only without a known extension.

        Returns:
            Every kind the file belongs to. Extensions, globs and names match
            case-insensitively. A name never claims a known extension, so
            `Dockerfile.PY` is Python only, while globs always apply. A
            template suffix such as `.j2` adds its own kind and the kinds of
            the name without it, so that `deploy.sh.j2` is Jinja and shell.
        """
        found = set()
        for layer in self.layers(path):
            found |= {kind for kind, spec in self.globs.items() if spec.match_file(str(layer).lower())}
            found |= {kind for kind, stems in self.names.items() if self.named(str(layer), stems)}
            if self.suffix_kind(layer.suffix) is not None:
                found.add(self.suffix_kind(layer.suffix))
        kind = self.shebang_kind(first_line) if self.needs_first_line(path) else None
        if kind is not None:
            found.add(kind)
        return frozenset(found)

    def named(self, path: str, stems: list) -> bool:
        """
        Args:
            path: Path of a file; only its base name counts.
            stems: Lowercase names of one kind, such as dockerfile.

        Returns:
            True for a stem itself, `<x>.<stem>`, or `<stem>.<variant>` whose
            suffix names no kind and no known file type, so `Dockerfile.prod`
            counts and `Dockerfile.png` or `Dockerfile.erb` does not.
        """
        name = PurePosixPath(path).name.lower()
        suffix = PurePosixPath(name).suffix
        known = suffix in self.extensions or any(suffix in listed for listed in self.known.values())
        return any(
            name == stem
            or name.endswith(f".{stem}")
            or (name.startswith(f"{stem}.") and not known)
            for stem in stems
        )

    def suffix_kind(self, suffix: str) -> str | None:
        """
        Args:
            suffix: File name suffix with its dot.

        Returns:
            Its kind, in any case, because `.J2` would otherwise hand an
            unrendered template to a parsing tool.
        """
        return self.extensions.get(suffix.lower())

    def is_template(self, path: PurePosixPath) -> bool:
        return self.suffix_kind(path.suffix) in self.templates

    def parsed_kinds(self, path: str, kinds: frozenset) -> frozenset:
        """
        Args:
            path: Path relative to the repository root.
            kinds: Every kind of the file.

        Returns:
            The kinds a parsing tool may bind: a template keeps only its
            template kinds, because its inner type does not parse before it
            is rendered.
        """
        if self.is_template(PurePosixPath(path)):
            return kinds & frozenset(self.templates)
        return kinds

    def layers(self, path: str) -> list:
        """
        Args:
            path: Path relative to the repository root.

        Returns:
            The path, then the path without each trailing template suffix.
        """
        current = PurePosixPath(path)
        found = [current]
        while self.is_template(current):
            current = current.with_suffix("")
            found.append(current)
        return found

    def shebang_kind(self, first_line: bytes) -> str | None:
        """
        Args:
            first_line: Start of the file.

        Returns:
            The kind of its interpreter. Every word after `env` counts, because
            `env -S python3 -u` and `env -u NAME python3` both run Python.
        """
        if not first_line.startswith(b"#!"):
            return None
        names = [interpreter_name(w) for w in first_line[2:].decode("utf-8", "replace").split()]
        candidates = names[1:] if names[:1] == ["env"] else names[:1]
        return next((self.shebangs[name] for name in candidates if name in self.shebangs), None)

    def needs_first_line(self, path: str) -> bool:
        return self.suffix_kind(self.layers(path)[-1].suffix) is None

    def code_name(self, path: str) -> bool:
        """
        Args:
            path: Path of a file.

        Returns:
            True for a name without extension, other than a known binary name
            such as .DS_Store, for a code extension, and for a name of a kind
            such as Dockerfile.prod; a template counts by its name without the
            template suffix, so `run.sh.j2` and `Dockerfile.prod.j2` count.
        """
        if PurePosixPath(path).name.lower() in self.binary_names:
            return False
        inner = str(self.layers(path)[-1])
        suffix = lower_suffix(inner)
        code = not suffix or self.suffix_kind(suffix) in self.code
        named = any(self.named(inner, stems) for stems in self.names.values())
        return code or suffix in self.known[CODE_KIND] or named


def lower_suffix(path: str) -> str:
    return PurePosixPath(path).suffix.lower()
