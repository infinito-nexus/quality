import json

import pytest

from tests.egress.support import (
    COMPOSE,
    EGRESS_NETWORK,
    FETCH_NETWORK,
    LOW_PORTS,
    STACK_PROXY,
    address,
    docker,
    peer,
    site_conf,
    start_proxy,
)

INTERNAL = {
    "this": "0.1.2.3",
    "ten": "10.1.2.3",
    "shared": "100.64.1.2",
    "loopback": "127.0.0.2",
    "link": "169.254.1.2",
    "seventeen": "172.16.1.2",
    "ietf": "192.0.0.8",
    "home": "192.168.1.2",
    "bench": "198.18.1.2",
    "multicast": "224.0.0.5",
    "reserved": "240.0.0.5",
    "unspecified6": "::",
    "loopback6": "::1",
    "unique6": "fd00::1",
    "link6": "fe80::1",
    "multicast6": "ff02::1",
    "mapped6": "::ffff:10.0.0.1",
}
OWN = "203.0.113.7"
PUBLIC = "198.51.100.7"
UNROUTED = "203.0.113.10"
REBIND_SECONDS = 130
UNREACHABLE = {"ENETUNREACH", "EHOSTUNREACH", "timeout"}


def name(label):
    return f"{label}.egress.test"


def statuses(proxy, *lines):
    return json.loads(peer("request", proxy, *lines))


@pytest.fixture(scope="module")
def proxy(tmp_path_factory):
    hosts = {name(label): value for label, value in {**INTERNAL, "own": OWN, "public": PUBLIC}.items()}
    return start_proxy(site_conf(tmp_path_factory.mktemp("egress"), "127.0.0.11", OWN), hosts)


def test_egress_blocks_internal(proxy):
    labels = [*INTERNAL, "own"]
    codes = statuses(proxy, *(f"CONNECT {name(label)}:443" for label in labels), f"CONNECT {name('public')}:443")
    assert dict(zip(labels, codes)) == dict.fromkeys(labels, 403)
    assert codes[-1] == 503


def test_egress_connect_only(proxy):
    assert statuses(proxy, f"GET http://{name('public')}/") == [403]


@pytest.mark.usefixtures("internet")
def test_egress_port_443_only():
    codes = statuses(STACK_PROXY, "CONNECT example.org:80", "CONNECT example.org:25", "CONNECT example.org:443")
    assert codes == [403, 403, 200]


def test_egress_no_direct_route():
    fetch = json.loads(docker("network", "inspect", FETCH_NETWORK))[0]
    assert fetch["Options"]["com.docker.network.bridge.inhibit_ipv4"] == "true"
    assert [config.get("Gateway") for config in fetch["IPAM"]["Config"]] == [None]
    hosts = [
        config["Gateway"]
        for network in ("bridge", EGRESS_NETWORK)
        for config in json.loads(docker("network", "inspect", network))[0]["IPAM"]["Config"]
        if config.get("Gateway")
    ]
    targets = ["9.9.9.9:443", *(f"{host}:443" for host in hosts)]
    results = json.loads(peer("direct", *targets, f"{STACK_PROXY}:3128"))
    assert results[-1] == "connected"
    assert len(hosts) == 2
    assert all(result in UNREACHABLE for result in results[:-1]), dict(zip(targets, results))


def test_egress_rebinding(tmp_path):
    listener = peer("listen", detach=True, extra=[LOW_PORTS])
    private = address(listener)
    resolver = peer("dns", UNROUTED, private, detach=True, extra=[LOW_PORTS])
    assert json.loads(peer("direct", f"{private}:443")) == ["connected"]
    proxy = start_proxy(site_conf(tmp_path, address(resolver), "127.0.0.1"), {})
    line = f"CONNECT {name('rebind')}:443"
    codes = json.loads(peer("repeat", proxy, str(REBIND_SECONDS), line, timeout=REBIND_SECONDS + 60))
    assert set(codes) == {403, 503}
    assert docker("logs", listener).split().count("hit") == 1
    assert docker("logs", resolver).count("query") >= 2


def test_proxy_flags():
    container = docker("compose", "-f", str(COMPOSE), "ps", "-q", "proxy")
    info = json.loads(docker("inspect", container))[0]
    host = info["HostConfig"]
    assert host["ReadonlyRootfs"] is True
    assert host["CapDrop"] == ["ALL"]
    assert "no-new-privileges:true" in host["SecurityOpt"]
    assert min(host["PidsLimit"], host["Memory"], host["NanoCpus"]) > 0
    (tmpfs_options,) = host["Tmpfs"].values()
    assert "size=" in tmpfs_options
    assert info["Config"]["User"] == "65534:65534"
    assert set(info["NetworkSettings"]["Networks"]) == {FETCH_NETWORK, EGRESS_NETWORK}
