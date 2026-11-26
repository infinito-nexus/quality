from __future__ import annotations

import os
from pathlib import Path

SHARED = "agents-shared"
DURABLE = "agents-council"
ACCEPTED = "security-accepted.jsonl"
JOURNAL = "scores.jsonl"


def state_home() -> Path:
    """
    Environment:
        XDG_STATE_HOME: The state home when it is an absolute path; an empty
            or relative value counts as unset.
        HOME: Else the state home is ~/.local/state.

    Returns:
        The directory both roots lie below.
    """
    state = os.environ.get("XDG_STATE_HOME", "")
    if os.path.isabs(state):
        return Path(state)
    return Path.home() / ".local" / "state"


def durable() -> Path:
    """
    Returns:
        The host-only root, <state home>/agents-council, which
        AGENTS_COUNCIL_ROOT never moves.
    """
    return state_home() / DURABLE


def root() -> Path:
    """
    Environment:
        AGENTS_COUNCIL_ROOT: The council root when it is an absolute path; an
            empty or relative value counts as unset.

    Returns:
        The council root every agent on the host shares, else
        <state home>/agents-shared.
    """
    explicit = os.environ.get("AGENTS_COUNCIL_ROOT", "")
    if os.path.isabs(explicit):
        return Path(explicit)
    return state_home() / SHARED
