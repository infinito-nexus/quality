import subprocess


class GitCase:
    """
    Attributes:
        repo: the fixture repository, set by the test's setUp.
        env: the environment of every git call, set there too.
    """

    def git(self, *args: str) -> str:
        return subprocess.run(
            ["git", *args], cwd=self.repo, env=self.env, capture_output=True, text=True, check=True
        ).stdout

    def write(self, files: dict[str, str]) -> None:
        for name, text in files.items():
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")

    def commit(self, files: dict[str, str]) -> None:
        self.write(files)
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "base")
