"""In-memory session store for the agentic wizard."""
from __future__ import annotations
from typing import TypedDict
from models import ApplicationDescriptor, ThreatModel, Threat


class SessionState(TypedDict):
    descriptor: ApplicationDescriptor | None
    threats: list[Threat]
    model: ThreatModel | None


_STORE: dict[str, SessionState] = {}


def get_session(session_id: str) -> SessionState:
    """Return the state for session_id, creating a fresh one if missing."""
    if session_id not in _STORE:
        _STORE[session_id] = {"descriptor": None, "threats": [], "model": None}
    return _STORE[session_id]


def has_session(session_id: str) -> bool:
    """Return True if session_id has a descriptor set."""
    return session_id in _STORE and _STORE[session_id]["descriptor"] is not None


def reset_session(session_id: str) -> None:
    """Delete session_id's state entirely."""
    _STORE.pop(session_id, None)
