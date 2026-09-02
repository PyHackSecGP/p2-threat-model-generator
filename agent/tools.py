"""@tool wrappers exposing threat-model operations to the agent."""
from __future__ import annotations
import json
import os
from agent_core import tool
from agent_core.models import ToolRisk
from models import ApplicationDescriptor, Component, ComponentType, AuthType, DataFlow
from .session import get_session, has_session
from engine.stride import run_stride
from engine.llm import enrich_all
from engine.scorer import build_threat_model
from reporter.json_reporter import generate_json
from reporter.html_reporter import generate_html

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


@tool(description="List all components in the current session's app. "
                  "Use this when you need to review what's been added before running STRIDE.",
      risk=ToolRisk.NONE)
def list_components(session_id: str) -> str:
    """List all components in the application."""
    if not has_session(session_id):
        return _err("No descriptor. Call start_app first.")
    d = get_session(session_id)["descriptor"]
    return _ok(components=[{
        "name": c.name, "type": c.type.value, "technology": c.technology,
        "auth_type": c.auth_type.value, "stores_pii": c.stores_pii,
        "stores_credentials": c.stores_credentials,
        "internet_facing": c.internet_facing,
        "has_logging": c.has_logging, "has_rate_limiting": c.has_rate_limiting,
    } for c in d.components])


@tool(description="List all data flows in the current session's app.",
      risk=ToolRisk.NONE)
def list_flows(session_id: str) -> str:
    """List all data flows in the application."""
    if not has_session(session_id):
        return _err("No descriptor. Call start_app first.")
    d = get_session(session_id)["descriptor"]
    return _ok(flows=[{
        "name": f.name, "source": f.source, "destination": f.destination,
        "encrypted": f.encrypted, "authenticated": f.authenticated,
        "crosses_trust_boundary": f.crosses_trust_boundary,
        "protocol": f.protocol, "data_classification": f.data_classification,
    } for f in d.data_flows])


@tool(description="Summarize the current app: name, env, component_count, flow_count, "
                  "compliance frameworks.",
      risk=ToolRisk.NONE)
def get_app(session_id: str) -> str:
    """Get a summary of the current application."""
    if not has_session(session_id):
        return _err("No descriptor. Call start_app first.")
    d = get_session(session_id)["descriptor"]
    return _ok(
        name=d.name, version=d.version, environment=d.environment,
        internet_facing=d.internet_facing,
        data_classification=d.data_classification,
        component_count=len(d.components), flow_count=len(d.data_flows),
        compliance_frameworks=list(d.compliance_frameworks),
    )


@tool(description="Run the STRIDE rule engine on the current session's app. "
                  "Generates threats for every component + data flow. "
                  "Call this only after start_app + all add_component + add_data_flow calls.",
      risk=ToolRisk.NONE)
def run_stride_analysis(session_id: str) -> str:
    """Run STRIDE analysis on the current application."""
    if not has_session(session_id):
        return _err("No descriptor. Call start_app first.")
    state = get_session(session_id)
    d = state["descriptor"]
    threats = run_stride(d)
    state["threats"] = threats
    counts: dict[str, int] = {}
    for t in threats:
        counts[t.stride_category.value] = counts.get(t.stride_category.value, 0) + 1
    return _ok(threat_count=len(threats), stride_counts=counts)


@tool(description="Enrich the top N highest-scoring threats with LLM-written narratives via "
                  "the Ollama endpoint configured in engine/llm.py. Skips silently if Ollama "
                  "is unreachable. Call after run_stride_analysis.",
      risk=ToolRisk.NONE)
def enrich_threats(session_id: str, max_threats: int) -> str:
    """Enrich threats with LLM-generated narratives."""
    if not has_session(session_id):
        return _err("No descriptor. Call start_app first.")
    threats = get_session(session_id)["threats"]
    if not threats:
        return _err("No threats to enrich. Call run_stride_analysis first.")
    enrich_all(threats, max_threats=max_threats)
    enriched = sum(1 for t in threats if t.llm_narrative)
    return _ok(enriched=enriched, total=len(threats))


@tool(description="Compute risk scores, compliance flags, and overall risk. Builds the final "
                  "ThreatModel from the current threats. Call after run_stride_analysis "
                  "(and optionally enrich_threats).",
      risk=ToolRisk.NONE)
def score_threats(session_id: str) -> str:
    """Score threats and build the final threat model."""
    if not has_session(session_id):
        return _err("No descriptor. Call start_app first.")
    state = get_session(session_id)
    threats = state["threats"]
    if not threats:
        return _err("No threats to score. Call run_stride_analysis first.")
    tm = build_threat_model(state["descriptor"], threats)
    state["model"] = tm
    breakdown = {
        "critical": len(tm.critical_threats),
        "high": len(tm.high_threats),
        "medium": len(tm.medium_threats),
        "low": len(tm.low_threats),
    }
    return _ok(
        overall_risk_score=tm.overall_risk_score,
        severity_breakdown=breakdown,
        threat_count=len(tm.threats),
        compliance_flag_count=len(tm.compliance_flags),
    )


@tool(description="Write threat-model report file(s) to output_dir. "
                  "format: json|html|all. Requires score_threats to have been called first.",
      risk=ToolRisk.FILESYSTEM)
def generate_report(session_id: str, format: str, output_dir: str) -> str:
    """Generate threat-model report in the specified format."""
    if not has_session(session_id):
        return _err("No descriptor. Call start_app first.")
    tm = get_session(session_id)["model"]
    if tm is None:
        return _err("No model. Call score_threats first.")
    os.makedirs(output_dir, exist_ok=True)
    slug = tm.app.name.lower().replace(" ", "-")
    written: list[str] = []
    if format in ("json", "all"):
        path = os.path.join(output_dir, f"{slug}-threat-model.json")
        generate_json(tm, path)
        written.append(path)
    if format in ("html", "all"):
        path = os.path.join(output_dir, f"{slug}-threat-model.html")
        generate_html(tm, path)
        written.append(path)
    if not written:
        return _err(f"Unknown format {format!r}. Valid: json|html|all.")
    return _ok(files=written, format=format)


@tool(description="Ask the human user a single question and return their answer as a string. "
                  "Use this to gather details about their application: name, components, "
                  "authentication, data flows, compliance requirements. Ask ONE question at a "
                  "time; wait for the answer; then decide the next question. Do not batch. "
                  "The response is the raw user string — parse it yourself.",
      risk=ToolRisk.NONE)
def ask_user(question: str) -> str:
    """Ask the user a single question and return their answer."""
    print(f"\n🤖 {question}")
    answer = input("👤 ").strip()
    return _ok(answer=answer)
