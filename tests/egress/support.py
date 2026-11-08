import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PEER = Path(__file__).with_name("peer.py")
COMPOSE = ROOT / "service" / "compose.yml"
SCAN_IMAGE = "quality-check/scan:local"
PROXY_IMAGE = "quality-check/proxy:local"
FETCH_NETWORK = "quality-check-fetch"
EGRESS_NETWORK = "quality-check-inspect_egress"
STACK_PROXY = "10.213.0.2"
LABEL = "quality-check.test=egress"
LOW_PORTS = "--sysctl=net.ipv4.ip_unprivileged_port_start=0"
SANDBOX = ["--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=64"]


def docker(*args, timeout=180):
    """
    Args:
        args: Arguments of the docker CLI.
        timeout: Seconds before the call fails; 180 outlasts a container start on a loaded host, and the one call that waits longer passes its own.
    """
    result = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout, check=False)
    if result.returncode != 0:
        raise AssertionError(f"docker {args[0]} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def peer(*args, network=FETCH_NETWORK, detach=False, extra=(), timeout=180):
    """
    Args:
        args: Mode and arguments of tests/egress/peer.py.
        network: Network the peer joins; the fetch network by default, whose egress every probe but the internet check tests.
        detach: Keep the peer running and return its container id instead of its output.
        extra: Further `docker run` flags.
        timeout: Seconds before the call fails; 180 for the reason docker() gives.
    """
    lifetime = ["-d", "--label", LABEL] if detach else ["--rm"]
    mount = ["-v", f"{PEER}:/peer.py:ro"]
    command = ["run", *lifetime, f"--network={network}", *SANDBOX, *mount, *extra, SCAN_IMAGE]
    return docker(*command, "python3", "/peer.py", *args, timeout=timeout)


def start_proxy(site_conf, hosts):
    """
    Args:
        site_conf: Host path of the site.conf the production squid.conf includes.
        hosts: {name: address} entries for the proxy's /etc/hosts.

    Returns:
        The proxy's address on the fetch network.
    """
    entries = [f"--add-host={name}:{address}" for name, address in hosts.items()]
    flags = ["--user=65534:65534", "--tmpfs=/tmp:size=16m", "--memory=256m", "--cpus=0.5"]
    mount = ["-v", f"{site_conf}:/etc/squid/site.conf:ro"]
    container = docker("run", "-d", "--label", LABEL, f"--network={FETCH_NETWORK}", *SANDBOX, *flags, *mount, *entries, PROXY_IMAGE)
    return address(container)


def address(container):
    networks = json.loads(docker("inspect", "--format", "{{json .NetworkSettings.Networks}}", container))
    return networks[FETCH_NETWORK]["IPAddress"]


def site_conf(directory, resolver, own_address):
    path = directory / "site.conf"
    path.write_text(f"dns_nameservers {resolver}\nhosts_file /etc/hosts\nacl own_address dst {own_address}\n", encoding="utf-8")
    path.chmod(0o644)
    return path


def remove_labelled():
    containers = docker("ps", "-aq", "--filter", f"label={LABEL}").split()
    if containers:
        docker("rm", "-f", *containers)
