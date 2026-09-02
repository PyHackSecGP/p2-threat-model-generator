"""@tool wrappers exposing threat-model operations to the agent."""
from __future__ import annotations
import json
from agent_core import tool
from agent_core.models import ToolRisk
from models import ApplicationDescriptor
from .session import get_session, has_session

_VALID_ENVS = {"production", "staging", "development"}
_VALID_DATA_CLASS = {"public", "internal", "confidential", "restricted"}
_VALID_FRAMEWORKS = {"gdpr", "pci_dss", "soc2", "hipaa"}


def _err(msg: str) -> str:
    return json.dumps({"ok": False, "error": msg})


def _ok(**kwargs) -> str:
    if "ok" in kwargs:
        raise TypeError("_ok() got reserved kwarg 'ok'")
    return json.dumps({"ok": True, **kwargs})


@tool(description="Initialise the ApplicationDescriptor for a threat-model session. "
                  "Must be called before add_component or add_data_flow. "
                  "environment: production|staging|development. "
                  "data_classification: public|internal|confidential|restricted.",
      risk=ToolRisk.NONE)
def start_app(
    session_id: str, name: str, version: str, description: str, owner: str,
    environment: str, internet_facing: bool, data_classification: str,
) -> str:
    """Initialize application descriptor for the session."""
    if environment not in _VALID_ENVS:
        return _err(f"Invalid environment {environment!r}. Valid: {sorted(_VALID_ENVS)}")
    if data_classification not in _VALID_DATA_CLASS:
        return _err(f"Invalid data_classification {data_classification!r}. "
                    f"Valid: {sorted(_VALID_DATA_CLASS)}")
    state = get_session(session_id)
    state["descriptor"] = ApplicationDescriptor(
        name=name, version=version, description=description, owner=owner,
        environment=environment, internet_facing=internet_facing,
        data_classification=data_classification,
    )
    return _ok(app=name, session_id=session_id)


@tool(description="Set compliance frameworks for the current session. "
                  "Valid frameworks: gdpr, pci_dss, soc2, hipaa. "
                  "Call after start_app.",
      risk=ToolRisk.NONE)
def set_compliance(session_id: str, frameworks: list[str]) -> str:
    """Set compliance frameworks for the application."""
    if not has_session(session_id):
        return _err("No descriptor. Call start_app first.")
    unknown = [f for f in frameworks if f not in _VALID_FRAMEWORKS]
    if unknown:
        return _err(f"Unknown frameworks: {unknown}. Valid: {sorted(_VALID_FRAMEWORKS)}")
    get_session(session_id)["descriptor"].compliance_frameworks = list(frameworks)
    return _ok(frameworks=frameworks)
