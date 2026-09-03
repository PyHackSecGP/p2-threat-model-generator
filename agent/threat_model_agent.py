"""ThreatModelAgent — wraps agent_core.Agent for interactive threat modelling."""
from __future__ import annotations
import uuid
from agent_core import Agent, ToolRegistry
from agent_core.llm import get_provider
from agent_core.llm.base import LLMProvider
from agent_core.models import AgentResult, ExecutionPolicy
from .tools import (
    ask_user, start_app, set_compliance,
    add_component, add_data_flow,
    list_components, list_flows, get_app,
    run_stride_analysis, enrich_threats,
    score_threats, generate_report,
)

_ALL_TOOLS = [
    ask_user, start_app, set_compliance,
    add_component, add_data_flow,
    list_components, list_flows, get_app,
    run_stride_analysis, enrich_threats,
    score_threats, generate_report,
]

_SYSTEM_PROMPT = """\
You are a senior threat-modelling analyst using STRIDE. Your job is to interview a human
user about their application, extract components + data flows, and produce a threat model
report.

Workflow:
1. Use ask_user to ask the user their application name, purpose, environment, and whether it
   is internet-facing.
2. Call start_app with the answers.
3. Ask about compliance requirements. If any, call set_compliance.
4. Iteratively ask about components. For each: name, type, technology stack, authentication,
   whether it stores PII/credentials, internet exposure, logging, rate limiting. Call
   add_component after each answer.
5. Iteratively ask about data flows between components: source, destination, protocol,
   encryption, authentication, trust-boundary crossing. Call add_data_flow.
6. When the user says they are done adding components/flows (or when you have enough for a
   meaningful model — at least 1 component), call run_stride_analysis.
7. Call score_threats.
8. Call generate_report with format="all" and output_dir="./output".
9. Summarize the results to the user: total threats, severity breakdown, top 3 critical/high.

Rules:
- Ask ONE question per ask_user call. Never batch questions.
- Always pass the session_id you were given, unchanged.
- If a tool returns ok=false, read the error and correct the arguments.
- Do not invent user input — always ask.
- Skip enrich_threats unless the user explicitly requests LLM narratives.
"""


class ThreatModelAgent:
    """Wrap agent_core.Agent with threat-model tools."""

    def __init__(
        self,
        provider: LLMProvider | None = None,
        policy: ExecutionPolicy = ExecutionPolicy.SAFE,
        max_iterations: int = 60,
    ) -> None:
        """Initialise ThreatModelAgent.

        Args:
            provider: LLM provider. Defaults to get_provider() if None.
            policy: Execution policy. Must allow FILESYSTEM for generate_report.
            max_iterations: Max agent-loop iterations. 60 covers ~10 components + flows.
        """
        self._provider = provider or get_provider()
        self._policy = policy
        self._max_iterations = max_iterations

    def _build_agent(self) -> Agent:
        """Construct and return a fresh Agent with all threat-model tools registered.

        Returns:
            Configured Agent instance ready to run.
        """
        return Agent(
            provider=self._provider,
            registry=ToolRegistry(_ALL_TOOLS),
            policy=self._policy,
            max_iterations=self._max_iterations,
            system_prompt=_SYSTEM_PROMPT,
            name="ThreatModelAgent",
        )

    def run(
        self,
        session_id: str = "",
        describe: str = "",
        output_dir: str = "./output",
    ) -> AgentResult:
        """Run the interactive interview + STRIDE pipeline.

        Args:
            session_id: Session identifier; auto-generated if empty.
            describe: Optional seed description; passed into goal so the agent has
                context before asking clarifying questions.
            output_dir: Directory to write final reports into.

        Returns:
            AgentResult from agent_core.
        """
        sid = session_id or str(uuid.uuid4())[:8]
        seed = f"\nSeed description from user: {describe}\n" if describe else ""
        goal = (
            f"Session ID: {sid}\n"
            f"Output directory: {output_dir}\n"
            f"{seed}\n"
            f"Interview the user and produce a STRIDE threat model. "
            f"Pass session_id={sid!r} to every tool. "
            f"Write reports to {output_dir!r}."
        )
        return self._build_agent().run(goal)
