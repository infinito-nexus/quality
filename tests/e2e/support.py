import html
import json
import re
import secrets
import subprocess
from collections import namedtuple
from pathlib import Path
from urllib.parse import urlsplit

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
ROLE = ROOT / "ansible" / "roles" / "web-app-cst-quality-check"
CORE_VARIABLE = "INFINITO_CORE_DIR"
OPENRESTY_META = Path("roles") / "svc-prx-openresty" / "meta" / "services.yml"
LAUNCHER_CONFIG = "launcher.json"
MAKE_SECONDS = 900
CURL_SECONDS = 120
LOOPBACK = "127.0.0.1"
UNSAFE = re.compile(r"[\"'$`\\\n]")
MAKE_UNSAFE = re.compile(r"['$\n]")
CHALLENGE = re.compile(r'challenge="([^"]+)"')
WRITE_OUT = "%{http_code} %{local_ip} %{redirect_url}"
NGINX_UNITS = {"k": 1 << 10, "m": 1 << 20, "g": 1 << 30}
Response = namedtuple("Response", "status address location")


def role_meta(name: str) -> dict:
    return yaml.safe_load((ROLE / "meta" / f"{name}.yml").read_text(encoding="utf-8"))


SERVICES = role_meta("services")
WEB = SERVICES["quality-check"]["name"]
PROXY = SERVICES["proxy"]
WEB_CONFIG = role_meta("volumes")["web_config"]["mounts"][0]["target"]


def quote(value: str) -> str:
    """
    Args:
        value: One shell word of a command that core's compose-exec or compose-app-exec runs.

    Returns:
        The word in double quotes.
    """
    if UNSAFE.search(value):
        raise ValueError(f"{value!r} cannot pass through core's cmd variable")
    return f'"{value}"'


def command(*words: str) -> str:
    return " ".join(quote(word) for word in words)


def body_limit(size: str) -> int:
    """
    Args:
        size: An nginx size such as 3m, as meta/server.yml sets client_max_body_size.

    Returns:
        The size in bytes.
    """
    unit = size[-1].lower()
    return int(size[:-1]) * NGINX_UNITS[unit] if unit in NGINX_UNITS else int(size)


def loopback_address() -> str:
    return "127." + ".".join(str(secrets.randbelow(253) + 2) for _ in range(3))


def multipart(fields: dict) -> tuple:
    """
    Args:
        fields: Form field name to its text, or to (file name, bytes) for an upload.

    Returns:
        (Content-Type header value, body).
    """
    boundary = secrets.token_hex(16)
    parts = []
    for name, value in fields.items():
        disposition = f'Content-Disposition: form-data; name="{name}"'
        if isinstance(value, tuple):
            disposition += f'; filename="{value[0]}"\r\nContent-Type: application/octet-stream'
            content = value[1]
        else:
            content = value.encode("utf-8")
        parts.append(f"--{boundary}\r\n{disposition}\r\n\r\n".encode() + content + b"\r\n")
    return f"multipart/form-data; boundary={boundary}", b"".join(parts) + f"--{boundary}--\r\n".encode()


def solve(challenge_json: str) -> str:
    altcha = pytest.importorskip("altcha", reason="the captcha solver needs altcha from service/web/requirements.txt: make test-live installs it")
    challenge = altcha.Challenge.from_dict(json.loads(challenge_json))
    return altcha.Payload(challenge, altcha.solve_challenge(challenge)).to_base64()


class Core:
    def __init__(self, directory: Path):
        self.directory = directory

    def make(self, target: str, stdin: bytes = b"", **variables) -> subprocess.CompletedProcess:
        """
        Args:
            target: Target of core's Makefile, such as compose-exec.
            stdin: Bytes the target's command reads on its standard input.
            variables: Variables of the target, each passed as name=value; none may hold a single quote, `$` or newline.

        Returns:
            The finished make process, its output as bytes.
        """
        if any(MAKE_UNSAFE.search(value) for value in variables.values()):
            raise ValueError(f"make {target}: a variable holds a character core's recipe cannot pass")
        argv = ["make", "-s", "--no-print-directory", "-C", str(self.directory), target]
        argv += [f"{name}={value}" for name, value in variables.items()]
        return subprocess.run(argv, input=stdin, capture_output=True, timeout=MAKE_SECONDS, check=False)

    def run(self, target: str, stdin: bytes = b"", **variables) -> str:
        result = self.make(target, stdin, **variables)
        if result.returncode != 0:
            lines = result.stderr.decode("utf-8", "replace").strip().splitlines()
            raise AssertionError(f"make {target} failed: {' | '.join(lines[-3:])}")
        return result.stdout.decode("utf-8", "replace")

    def shell(self, line: str, stdin: bytes = b"") -> str:
        return self.run("compose-exec", stdin, cmd=line)

    def app(self, container: str, line: str) -> str:
        return self.run("compose-app-exec", app=container, cmd=line)

    def logs(self, container: str) -> str:
        result = self.make("compose-app-logs", app=container, tail="all")
        assert result.returncode == 0, f"make compose-app-logs app={container} failed"
        return (result.stdout + result.stderr).decode("utf-8", "replace")

    def inspect(self, *names: str) -> list:
        return json.loads(self.shell(command("docker", "inspect", *names)))

    def network(self, name: str) -> dict:
        return json.loads(self.shell(command("docker", "network", "inspect", name)))[0]

    def openresty(self) -> str:
        return yaml.safe_load((self.directory / OPENRESTY_META).read_text(encoding="utf-8"))["openresty"]["name"]


class Stack:
    def __init__(self, core: Core, web: dict):
        """
        Args:
            core: Core checkout whose development stack runs the role.
            web: `docker inspect` of the web service.
        """
        self.core = core
        self.web = web
        self.config = json.loads(core.app(WEB, command("cat", WEB_CONFIG)))
        self.url = self.config["public_url"].rstrip("/")
        hosts = [urlsplit(self.url).hostname]
        if self.config["oidc"] is not None:
            hosts.append(urlsplit(self.config["oidc"]["issuer"]).hostname)
        authorities = core.shell("ls /etc/*/ca/root-ca.crt").split()
        assert len(authorities) == 1, f"the stack host holds {len(authorities)} root CAs below /etc/*/ca"
        self.curl_options = ["--cacert", authorities[0]]
        for host in hosts:
            self.curl_options += ["--resolve", f"{host}:443:{LOOPBACK}"]

    def holders(self, container: str, needles: list, directories: list) -> str:
        """
        Args:
            container: Container of the stack to search.
            needles: Fixed strings, none of which may appear.
            directories: Directories searched recursively; a missing one is skipped.

        Returns:
            The files holding any needle, one per line.
        """
        patterns = [word for needle in needles for word in ("-e", needle)]
        files = command("find", *directories, "-type", "f", "-exec", "grep", "-lFs", *patterns, "{}", "+")
        return self.core.app(container, files + "; true").strip()

    def spool(self) -> set:
        return set(self.core.app(WEB, command("ls", "-A", f"{self.config['state_dir']}/spool")).split())

    def launcher(self) -> dict:
        """
        Returns:
            The launcher configuration the role writes on the stack host beside the web configuration it mounts.
        """
        source = next(mount["Source"] for mount in self.web["Mounts"] if mount["Destination"] == WEB_CONFIG)
        return json.loads(self.core.shell(command("cat", str(Path(source).with_name(LAUNCHER_CONFIG)))))


class Client:
    def __init__(self, stack: Stack):
        self.stack = stack
        self.address = loopback_address()

    def curl(self, url: str, *options: str, stdin: bytes = b"") -> str:
        argv = ["curl", "--silent", "--show-error", "--max-time", str(CURL_SECONDS), "--interface", self.address]
        return self.stack.core.shell(command(*argv, *self.stack.curl_options, *options, url), stdin)

    def request(self, url: str, *options: str, stdin: bytes = b"") -> Response:
        status, address, location = self.curl(url, "--output", "/dev/null", "--write-out", WRITE_OUT, *options, stdin=stdin).split(" ", 2)
        assert address == self.address, f"curl left from {address}, not from {self.address}"
        return Response(int(status), address, location.strip())

    def post_form(self, path: str, fields: dict, *options: str) -> Response:
        content_type, body = multipart(fields)
        headers = ["--header", f"Content-Type: {content_type}", "--header", f"Origin: {self.stack.url}"]
        return self.request(self.stack.url + path, *headers, *options, "--data-binary", "@-", stdin=body)

    def submit(self, fields: dict, *options: str) -> Response:
        page = self.curl(self.stack.url + "/")
        found = CHALLENGE.search(page)
        assert found, "the anonymous form at / carries no captcha challenge"
        return self.post_form("/submit", {**fields, "altcha": solve(html.unescape(found.group(1)))}, *options)

    def abort(self, url: str, *options: str, stdin: bytes = b"") -> int:
        """
        Args:
            url: Address the request goes to.
            options: curl options that make curl give up before the exchange ends.
            stdin: Request body curl sends.

        Returns:
            The exit status of make, non-zero when curl gave up.
        """
        argv = ["curl", "--silent", "--max-time", str(CURL_SECONDS), "--interface", self.address, "--output", "/dev/null"]
        line = command(*argv, *self.stack.curl_options, *options, url)
        return self.stack.core.make("compose-exec", stdin, cmd=line).returncode
