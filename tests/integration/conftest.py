import pytest

from tests.integration.support import Target


@pytest.fixture
def target(tmp_path):
    return Target.create(tmp_path / "repo")


@pytest.fixture(params=["staged", "base"])
def mode(request):
    return request.param
