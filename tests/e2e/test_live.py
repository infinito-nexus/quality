import html
import json
import os
import re
import secrets
import time
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest

from tests.e2e.support import (
    CORE_VARIABLE,
    PROXY,
    ROLE,
    WEB,
    Client,
    Core,
    Stack,
    body_limit,
    command,
    role_meta,
)
from tests.service.support import load_launcher

MEMBER_VARIABLE = "QUALITY_LIVE_MEMBER"
MEMBER_PASSWORD_VARIABLE = "QUALITY_LIVE_MEMBER_PASSWORD_FILE"
SOCKETS = {"docker.sock", "containerd.sock", "podman.sock", "crio.sock"}
RUNTIME_DIRECTORIES = {"/run", "/var/run", "/run/docker", "/var/run/docker", "/run/containerd"}
CONTAINER_TMP = "/tmp"  # nocheck: security.temp-path -- a stack container's own /tmp, reached through core's make targets, never this host's
OPENRESTY_SPOOLS = [CONTAINER_TMP, "/var/run/openresty", "/usr/local/openresty/nginx"]
TEXT_JOB = {"kind": "text", "language": "python", "text": "import os\n"}
HEALTHY_SECONDS = 180
POLL_SECONDS = 2
SLOW_BODY_BYTES = 65536
LOGIN_FORM = re.compile(r'<form\b[^>]*\bid="kc-form-login"[^>]*>')
ACTION = re.compile(r'\baction="([^"]+)"')


@pytest.fixture(scope="module")
def stack():
    if CORE_VARIABLE not in os.environ:
        pytest.skip(f"{CORE_VARIABLE} names no core checkout, so no stack of make verify-compose is at hand")
    core = Core(Path(os.environ[CORE_VARIABLE]))
    probe = core.make("compose-exec", cmd=command("docker", "inspect", WEB))
    if probe.returncode != 0:
        pytest.skip(f"core's stack runs no {WEB}: make verify-compose {CORE_VARIABLE}={core.directory} deploys it")
    return Stack(core, json.loads(probe.stdout)[0])


def required(variable: str) -> str:
    if variable not in os.environ:
        pytest.fail(f"{variable} is required: the account of the member group that test_add_to_existing_realm logs in as")
    return os.environ[variable]


def hour() -> int:
    return int(time.time() // 3600)


def forged_address() -> str:
    return f"198.{18 + secrets.randbelow(2)}.{secrets.randbelow(256)}.{secrets.randbelow(254) + 1}"


def report_id(location: str) -> str:
    return urlsplit(location).path.rsplit("/", 1)[-1]


def filled(marker: str, size: int) -> bytes:
    return (marker.encode() * (size // len(marker) + 1))[:size]


def exhaust(client: Client, limit: int) -> list:
    """
    Args:
        client: Client with its own source address.
        limit: anonymous_per_ip_hour of the deployed web app.

    Returns:
        The responses of limit + 1 captcha-solved submissions.
    """
    return [client.submit(TEXT_JOB) for _ in range(limit + 1)]


def is_socket(mount: dict) -> bool:
    paths = (mount["Source"], mount["Destination"])
    return any(Path(path).name in SOCKETS for path in paths) or mount["Source"] in RUNTIME_DIRECTORIES


def ipv4_subnets(network: dict) -> list:
    return [entry["Subnet"] for entry in network["IPAM"]["Config"] if ":" not in entry["Subnet"]]


def test_live_no_socket(stack):
    assert [mount["Destination"] for mount in stack.web["Mounts"] if is_socket(mount)] == []
    networks = stack.web["NetworkSettings"]["Networks"]
    assert len(networks) == 1, sorted(networks)
    assert ipv4_subnets(stack.core.network(next(iter(networks)))) == [role_meta("networks")["local"]["subnet"]]


def test_live_fetch_network(stack):
    network = stack.core.network(PROXY["network"])
    assert network["Name"] == PROXY["network"]
    assert network["Internal"] is True
    assert ipv4_subnets(network) == [PROXY["subnet"]]
    assert network["Options"]["com.docker.network.bridge.inhibit_ipv4"] == "true"
    bridge = f"br-{network['Id'][:12]}"
    assert stack.core.shell(command("ip", "-o", "-4", "address", "show", "dev", bridge)).strip() == ""
    assert network["Containers"], f"nothing is attached to {PROXY['network']}, not even the proxy"
    members = stack.core.inspect(*network["Containers"])
    label = load_launcher().LABEL
    assert [member["Name"].lstrip("/") for member in members if label not in member["Config"]["Labels"]] == [PROXY["name"]]
    proxy = next(member for member in members if member["Name"].lstrip("/") == PROXY["name"])
    assert proxy["NetworkSettings"]["Networks"][PROXY["network"]]["IPAddress"] == PROXY["address"]
    assert proxy["HostConfig"]["Runtime"] == stack.launcher()["runtime"]


def test_scan_holder_runs(stack):
    holder = stack.core.inspect(role_meta("services")["scan"]["name"])[0]
    assert (holder["State"]["Status"], holder["RestartCount"]) == ("running", 0)
    wrapper = holder["Config"]["Entrypoint"][0]
    assert wrapper in {mount["Destination"] for mount in holder["Mounts"]}, f"{wrapper} is no mounted CA trust wrapper"


def state_directory(stack) -> str:
    spool = f"{stack.config['state_dir']}/spool"
    return str(Path(next(mount["Source"] for mount in stack.web["Mounts"] if mount["Destination"] == spool)).parent)


def below(stack, directory: str) -> str:
    return stack.core.shell(command("find", directory, "-mindepth", "1")).strip()


def wait_healthy(stack) -> None:
    deadline = time.monotonic() + HEALTHY_SECONDS
    while stack.core.inspect(WEB)[0]["State"]["Health"]["Status"] != "healthy":
        assert time.monotonic() < deadline, f"{WEB} is not healthy {HEALTHY_SECONDS} s after its state mount returned"
        time.sleep(POLL_SECONDS)


def unmounted_start(stack, state: str) -> None:
    stack.core.shell(command("umount", state))
    assert below(stack, state) == "", f"the root filesystem holds files below {state}"
    refused = stack.core.make("compose-exec", cmd=command("docker", "start", WEB))
    assert refused.returncode != 0, f"{WEB} started without its state mount"
    assert stack.core.inspect(WEB)[0]["State"]["Running"] is False
    assert below(stack, state) == "", f"starting {WEB} wrote below {state} on the root filesystem"


def test_reboot_state_mount(stack):
    state = state_directory(stack)
    units = [f"{ROLE.name}*.timer", f"{ROLE.name}*.service"]
    listed = stack.core.shell(command("systemctl", "list-units", "--plain", "--no-legend", "--state=active", units[0]))
    timers = [line.split()[0] for line in listed.splitlines() if line.strip()]
    stack.core.shell(command("systemctl", "stop", *units))
    stack.core.shell(command("docker", "stop", WEB))
    try:
        unmounted_start(stack, state)
    finally:
        stack.core.shell("mount -a")
        stack.core.shell("systemd-tmpfiles --create")
        stack.core.shell(command("docker", "start", WEB))
        if timers:
            stack.core.shell(command("systemctl", "start", *timers))
    assert stack.core.shell(command("findmnt", "--noheadings", "--output", "FSTYPE", state)).strip() == "tmpfs"
    wait_healthy(stack)
    probe = f".e2e-{secrets.token_hex(8)}"
    stack.core.app(WEB, command("touch", f"{stack.config['state_dir']}/spool/{probe}") + " && " + command("rm", f"{stack.config['state_dir']}/spool/{probe}"))
    stack.core.shell(command("touch", f"{state}/reports/{probe}") + " && " + command("rm", f"{state}/reports/{probe}"))


def test_upload_too_large(stack):
    client = Client(stack)
    limit = stack.config["limits"]["upload_bytes"]
    proxy_limit = body_limit(role_meta("server")["client_max_body_size"])
    marker = secrets.token_hex(16)
    before = stack.spool()
    over_app = client.submit({"kind": "file", "file": ("large.txt", filled(marker, limit + 1))})
    over_proxy = client.post_form("/submit", {"kind": "file", "file": ("large.txt", filled(marker, proxy_limit + 1))})
    assert (over_app.status, over_proxy.status) == (413, 413)
    assert stack.spool() - before == set()
    assert stack.holders(WEB, [marker], [CONTAINER_TMP, stack.config["state_dir"]]) == ""
    assert stack.holders(stack.core.openresty(), [marker], OPENRESTY_SPOOLS) == ""


def test_forwarded_for_ignored(stack):
    client = Client(stack)
    limit = stack.config["rate_limits"]["anonymous_per_ip_hour"]
    started = hour()
    codes = [response.status for response in exhaust(client, limit)]
    forged = [("X-Real-IP", forged_address()), ("X-Forwarded-For", forged_address())]
    headers = [("--header", f"{name}: {address}") for name, address in forged]
    spoofed = [client.submit(TEXT_JOB, *header).status for header in [*headers, headers[0] + headers[1]]]
    control = Client(stack).submit(TEXT_JOB).status
    if hour() != started:
        pytest.skip("the hour turned during the test, which empties every rate limit bucket")
    if control == 429:
        pytest.skip("the anonymous hourly total or queue cap is reached, so no bucket can be told apart; rerun after the hour")
    assert codes == [303] * limit + [429]
    assert spoofed == [429, 429, 429]


def test_no_address_on_disk(stack):
    client = Client(stack)
    responses = exhaust(client, stack.config["rate_limits"]["anonymous_per_ip_hour"])
    ids = [report_id(response.location) for response in responses if response.status == 303]
    if not ids:
        pytest.skip("the anonymous hourly total or queue cap is reached, so no submission created a report link")
    assert responses[-1].status == 429
    report = f"{stack.url}/r/{ids[0]}"
    assert client.abort(report, "--request", "GET", "--data-binary", "@-", "--limit-rate", "1K", "--max-time", "3", stdin=bytes(SLOW_BODY_BYTES)) != 0
    assert client.abort(report, "--max-filesize", "1") != 0
    oversized = body_limit(role_meta("server")["client_max_body_size"]) + 1
    assert client.post_form("/submit", {"kind": "file", "file": ("large.txt", bytes(oversized))}).status == 413
    assert stack.holders(WEB, [client.address], [CONTAINER_TMP, stack.config["state_dir"]]) == ""
    assert stack.holders(WEB, ids, [CONTAINER_TMP]) == ""
    logs = {name: stack.core.logs(name) for name in (WEB, stack.core.openresty())}
    found = {name: [needle for needle in [client.address, *ids] if needle in text] for name, text in logs.items()}
    assert found == {name: [] for name in logs}


def login_action(page: str) -> str:
    form = LOGIN_FORM.search(page)
    assert form, "Keycloak served no login form for the role's client"
    action = ACTION.search(form.group(0))
    assert action, "Keycloak's login form names no action"
    return html.unescape(action.group(1))


def log_in(client: Client, jar: str, user: str, password: str) -> None:
    """
    Args:
        client: Client the session belongs to.
        jar: Cookie file in the stack host's /tmp.
        user: Keycloak account in the role's member group.
        password: Its password, sent on stdin only.
    """
    cookies = ("--cookie", jar, "--cookie-jar", jar)
    start = client.request(f"{client.stack.url}/account/login", *cookies)
    assert start.status == 302
    assert parse_qs(urlsplit(start.location).query)["client_id"] == [client.stack.config["oidc"]["client_id"]]
    action = login_action(client.curl(start.location, *cookies))
    form = urlencode({"username": user, "password": password, "credentialId": ""}).encode()
    callback = client.request(action, *cookies, "--data-binary", "@-", stdin=form)
    assert callback.location.startswith(f"{client.stack.url}/account/callback"), "Keycloak refused the member's login"
    session = client.request(callback.location, *cookies)
    assert (session.status, urlsplit(session.location).path) == (302, "/account/")


def test_add_to_existing_realm(stack):
    if stack.config["oidc"] is None:
        pytest.skip("the deployed variant runs without SSO, so it has no realm; deploy variant 0")
    user = required(MEMBER_VARIABLE)
    password = Path(required(MEMBER_PASSWORD_VARIABLE)).read_text(encoding="utf-8").strip()
    client = Client(stack)
    discovery = client.request(f"{stack.config['oidc']['issuer']}/.well-known/openid-configuration")
    assert discovery.status == 200, "the realm the role joins does not exist"
    jar = f"{CONTAINER_TMP}/quality-e2e-{secrets.token_hex(8)}.cookies"
    try:
        log_in(client, jar, user, password)
        limit = stack.config["rate_limits"]["registered_per_user_hour"]
        codes = [client.post_form("/account/submit", TEXT_JOB, "--cookie", jar).status for _ in range(limit + 1)]
    finally:
        stack.core.shell(command("rm", "-f", jar))
    assert codes == [303] * (limit + 1)
