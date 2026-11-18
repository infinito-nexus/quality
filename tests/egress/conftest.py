import json
import os

import pytest

from tests.egress.isolation_support import build_images, stack_launcher_stopped
from tests.egress.support import docker, peer, remove_labelled
from tests.integration import conftest as integration

RUNTIMES = "EGRESS_RUNTIMES"
vulnerability_database = integration.vulnerability_database


def selected_runtimes():
    runtimes = os.environ.get(RUNTIMES, "").split()
    if not runtimes:
        pytest.fail(f'{RUNTIMES} must name the container runtimes the egress tests run under, such as "runc sysbox-runc"', pytrace=False)
    return runtimes


def pytest_generate_tests(metafunc):
    if "runtime" in metafunc.fixturenames:
        metafunc.parametrize("runtime", selected_runtimes(), scope="module")


@pytest.fixture(scope="session", autouse=True)
def offered_runtimes():
    offered = json.loads(docker("info", "--format", "{{json .Runtimes}}"))
    missing = [runtime for runtime in selected_runtimes() if runtime not in offered]
    if missing:
        reason = f"{RUNTIMES} names {missing}, which docker info does not offer; it offers {sorted(offered)}"
        pytest.exit(reason, returncode=pytest.ExitCode.USAGE_ERROR)


@pytest.fixture(scope="session", autouse=True)
def labelled_containers():
    remove_labelled()
    yield
    remove_labelled()


@pytest.fixture(scope="module")
def quiet_stack():
    with stack_launcher_stopped():
        yield


@pytest.fixture(scope="module")
def pair(tmp_path_factory):
    return build_images(tmp_path_factory.mktemp("images"))


@pytest.fixture(scope="session")
def internet_reachable():
    return json.loads(peer("direct", "example.org:443", network="bridge")) == ["connected"]


@pytest.fixture
def internet(internet_reachable, request):
    if not internet_reachable:
        pytest.skip(f"[internet] {request.node.nodeid}: example.org:443 is not reachable from a container on the default bridge")
