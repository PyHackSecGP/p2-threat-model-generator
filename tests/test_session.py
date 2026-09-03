"""Unit tests for agent session store."""
from __future__ import annotations
import pytest
from agent.session import get_session, reset_session, has_session
from models import ApplicationDescriptor


def test_get_session_creates_empty_state() -> None:
    reset_session("s1")
    state = get_session("s1")
    assert state["descriptor"] is None
    assert state["threats"] == []
    assert state["model"] is None


def test_has_session_false_before_init() -> None:
    reset_session("s2")
    assert has_session("s2") is False


def test_has_session_true_after_descriptor_set() -> None:
    reset_session("s3")
    state = get_session("s3")
    state["descriptor"] = ApplicationDescriptor(name="X")
    assert has_session("s3") is True


def test_reset_clears_state() -> None:
    state = get_session("s4")
    state["descriptor"] = ApplicationDescriptor(name="Y")
    reset_session("s4")
    assert has_session("s4") is False
