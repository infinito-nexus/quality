import json

import pytest

from tests.egress.support import peer, remove_labelled


@pytest.fixture(scope="session", autouse=True)
def labelled_containers():
    remove_labelled()
    yield
    remove_labelled()


@pytest.fixture(scope="session")
def internet():
    if json.loads(peer("direct", "example.org:443", network="bridge")) != ["connected"]:
        pytest.skip("[internet] example.org:443 is not reachable from a container on the default bridge")
