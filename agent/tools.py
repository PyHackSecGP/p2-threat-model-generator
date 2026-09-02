"""@tool wrappers exposing threat-model operations to the agent."""
from __future__ import annotations
import json
from agent_core import tool
from agent_core.models import ToolRisk
from models import ApplicationDescriptor, Component, ComponentType, AuthType, DataFlow
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


@tool(description="Add a component to the current session's application. "
                  "type: web_app|api|database|auth_service|message_queue|cache|storage|"
                  "cdn|load_balancer|external_service|mobile_app|worker|generic. "
                  "auth_type: none|api_key|jwt|oauth2|basic|mtls|session.",
      risk=ToolRisk.NONE)
def add_component(
    session_id: str, name: str, type: str, technology: str, auth_type: str,
    stores_pii: bool, stores_credentials: bool, internet_facing: bool,
    has_logging: bool, has_rate_limiting: bool, notes: str,
) -> str:
    """Add a component to the application descriptor."""
    if not has_session(session_id):
        return _err("No descriptor. Call start_app first.")
    valid_types = {ct.value for ct in ComponentType}
    if type not in valid_types:
        return _err(f"Invalid type {type!r}. Valid: {sorted(valid_types)}")
    valid_auth = {at.value for at in AuthType}
    if auth_type not in valid_auth:
        return _err(f"Invalid auth_type {auth_type!r}. Valid: {sorted(valid_auth)}")
    d = get_session(session_id)["descriptor"]
    d.components.append(Component(
        name=name, type=ComponentType(type), technology=technology,
        auth_type=AuthType(auth_type), stores_pii=stores_pii,
        stores_credentials=stores_credentials, internet_facing=internet_facing,
        has_logging=has_logging, has_rate_limiting=has_rate_limiting, notes=notes,
    ))
    return _ok(component_count=len(d.components), name=name)


@tool(description="Add a data flow between two components. "
                  "data_classification: public|internal|confidential|restricted. "
                  "source/destination must reference component names (or Internet/Client/Admin).",
      risk=ToolRisk.NONE)
def add_data_flow(
    session_id: str, name: str, source: str, destination: str,
    encrypted: bool, authenticated: bool, crosses_trust_boundary: bool,
    protocol: str, data_classification: str,
) -> str:
    """Add a data flow between components."""
    if not has_session(session_id):
        return _err("No descriptor. Call start_app first.")
    if data_classification not in _VALID_DATA_CLASS:
        return _err(f"Invalid data_classification {data_classification!r}. "
                    f"Valid: {sorted(_VALID_DATA_CLASS)}")
    d = get_session(session_id)["descriptor"]
    d.data_flows.append(DataFlow(
        name=name, source=source, destination=destination,
        data_classification=data_classification, encrypted=encrypted,
        authenticated=authenticated, crosses_trust_boundary=crosses_trust_boundary,
        protocol=protocol,
    ))
    return _ok(flow_count=len(d.data_flows), name=name)
