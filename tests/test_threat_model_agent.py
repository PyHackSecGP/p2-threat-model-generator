"""Smoke tests for ThreatModelAgent."""
from __future__ import annotations
import pytest
from unittest.mock import MagicMock
from agent import ThreatModelAgent
from agent_core.models import AgentResult, StopReason


def test_agent_instantiates_with_mock_provider() -> None:
    provider = MagicMock()
    agent = ThreatModelAgent(provider=provider)
    assert agent is not None


def test_agent_run_builds_goal_string() -> None:
    provider = MagicMock()
    fake_result = AgentResult(
        output="done", stop_reason=StopReason.DONE, iterations=1,
        tool_calls=[], artifacts=[],
    )
    agent = ThreatModelAgent(provider=provider)
    agent._build_agent = MagicMock()
    agent._build_agent.return_value.run.return_value = fake_result
    result = agent.run(session_id="s1", describe="An e-commerce API")
    assert result.stop_reason == StopReason.DONE
    call_args = agent._build_agent.return_value.run.call_args
    goal = call_args[0][0]
    assert "s1" in goal
    assert "e-commerce API" in goal
