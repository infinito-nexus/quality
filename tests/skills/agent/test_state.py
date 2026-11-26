from pathlib import Path

import pytest

from quality.agent import state


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("AGENTS_COUNCIL_ROOT", raising=False)
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    return tmp_path


def test_agents_share_one_root_and_the_host_keeps_another_by_default(home):
    local = home / ".local" / "state"
    assert (state.root(), state.durable()) == (local / "agents-shared", local / "agents-council")


@pytest.mark.parametrize("value", ["", "relative", "./state"])
def test_an_empty_or_relative_state_home_counts_as_unset(home, monkeypatch, value):
    monkeypatch.setenv("XDG_STATE_HOME", value)
    local = home / ".local" / "state"
    assert (state.state_home(), state.root(), state.durable()) == (
        local,
        local / "agents-shared",
        local / "agents-council",
    )


def test_an_absolute_state_home_moves_both_roots(home, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", "/srv/state")
    assert (state.root(), state.durable()) == (Path("/srv/state/agents-shared"), Path("/srv/state/agents-council"))


def test_an_absolute_council_root_wins_and_never_moves_the_host_root(home, monkeypatch):
    monkeypatch.setenv("AGENTS_COUNCIL_ROOT", "/srv/council")
    monkeypatch.setenv("XDG_STATE_HOME", "/srv/state")
    assert (state.root(), state.durable()) == (Path("/srv/council"), Path("/srv/state/agents-council"))


@pytest.mark.parametrize("value", ["", "relative-council", "./council"])
def test_an_empty_or_relative_council_root_counts_as_unset(home, monkeypatch, value):
    monkeypatch.setenv("AGENTS_COUNCIL_ROOT", value)
    assert state.root() == home / ".local" / "state" / "agents-shared"
    monkeypatch.setenv("XDG_STATE_HOME", "/srv/state")
    assert state.root() == Path("/srv/state/agents-shared")


def test_the_ledger_and_the_journal_keep_the_names_the_skills_used():
    assert (state.ACCEPTED, state.JOURNAL) == ("security-accepted.jsonl", "scores.jsonl")
