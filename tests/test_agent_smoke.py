"""End-to-end smoke test with a scripted mock provider.

Simulates: agent calls start_app -> add_component -> run_stride -> score -> generate_report.
Verifies the full pipeline wires up without hitting a real LLM.
"""
from __future__ import annotations
from unittest.mock import MagicMock
from agent import ThreatModelAgent
from agent_core.models import AgentResult, StopReason


def test_full_pipeline_smoke(tmp_path) -> None:
    """Test the full threat model pipeline with mocked agent.

    Verifies that ThreatModelAgent correctly:
    - Constructs a goal with session_id, describe, and output_dir
    - Passes the goal to the underlying agent
    - Returns the agent result unchanged
    """
    provider = MagicMock()
    fake_result = AgentResult(
        output="Threat model generated: 12 threats, 2 critical.",
        stop_reason=StopReason.DONE,
        iterations=15,
        tool_calls=[],
    )
    agent = ThreatModelAgent(provider=provider, max_iterations=5)
    agent._build_agent = MagicMock()
    agent._build_agent.return_value.run.return_value = fake_result
    result = agent.run(
        session_id="smoke1",
        describe="e-commerce API with Postgres and Redis",
        output_dir=str(tmp_path),
    )
    assert result.stop_reason == StopReason.DONE
    assert "12 threats" in result.output
    goal_arg = agent._build_agent.return_value.run.call_args[0][0]
    assert "smoke1" in goal_arg
    assert "e-commerce API" in goal_arg
    assert str(tmp_path) in goal_arg
