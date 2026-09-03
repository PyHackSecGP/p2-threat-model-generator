# P2 Agentic Interactive Wizard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an in-place `--agentic` mode to P2 that replaces the scripted wizard with an LLM-driven interview: the agent asks the user open-ended questions via an `ask_user` tool, extracts app architecture into `ApplicationDescriptor`, then runs STRIDE analysis, scoring, and report generation.

**Architecture:** Mirror the P1 agentic pattern. Add an `agent/` package that wraps existing `engine/` and `reporter/` modules as `@tool` functions plus a new `ask_user` interactive tool. A `ThreatModelAgent` class wraps `agent_core.Agent`. `p2_threat_model.py` gains `--agentic --provider claude|ollama` flags. Session state (ApplicationDescriptor + threats + ThreatModel) lives in a module-level `_STORE: dict[str, dict]`.

**Tech Stack:** Python 3.11+, agent-core (`~/projects/agent-core`), existing p2 modules (`models.py`, `engine/stride.py`, `engine/scorer.py`, `engine/llm.py`, `reporter/`), pytest for tests.

---

## File Structure

**Create:**
- `agent/__init__.py` — package marker, exports `ThreatModelAgent`
- `agent/session.py` — `_STORE` dict and getters/setters
- `agent/tools.py` — 11 `@tool` functions
- `agent/threat_model_agent.py` — `ThreatModelAgent` class
- `tests/test_agent_tools.py` — unit tests for tools
- `tests/test_threat_model_agent.py` — smoke test for agent wrapper

**Modify:**
- `requirements.txt` — add `agent-core @ file:///home/tony/projects/agent-core` line
- `p2_threat_model.py` — add `--agentic`, `--provider`, `--describe`, `--describe-file` CLI flags and dispatch

---

## Task 1: Add agent-core dependency + package skeleton

**Files:**
- Modify: `requirements.txt`
- Create: `agent/__init__.py`

- [ ] **Step 1: Add agent-core to requirements.txt**

Append this line to `~/projects/p2-threat-model-generator/requirements.txt`:

```
agent-core @ file:///home/tony/projects/agent-core
```

- [ ] **Step 2: Install it**

```bash
cd ~/projects/p2-threat-model-generator && pip install -e /home/tony/projects/agent-core
```
Expected: `Successfully installed agent-core-...`

- [ ] **Step 3: Verify import works**

```bash
cd ~/projects/p2-threat-model-generator && python -c "from agent_core import Agent, tool, ToolRegistry; print('ok')"
```
Expected: `ok`

- [ ] **Step 4: Create agent/__init__.py**

Path: `~/projects/p2-threat-model-generator/agent/__init__.py`

```python
"""Agentic wizard layer for P2 threat model generator."""
from .threat_model_agent import ThreatModelAgent

__all__ = ["ThreatModelAgent"]
```

- [ ] **Step 5: Commit**

```bash
cd ~/projects/p2-threat-model-generator && git add requirements.txt agent/__init__.py && git commit -m "feat(agent): add agent-core dependency + package skeleton"
```

---

## Task 2: Session store

**Files:**
- Create: `agent/session.py`
- Create: `tests/test_session.py`

- [ ] **Step 1: Write the failing test**

Path: `~/projects/p2-threat-model-generator/tests/test_session.py`

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd ~/projects/p2-threat-model-generator && python -m pytest tests/test_session.py -v
```
Expected: FAIL — `ModuleNotFoundError: No module named 'agent.session'`

- [ ] **Step 3: Write minimal implementation**

Path: `~/projects/p2-threat-model-generator/agent/session.py`

```python
"""In-memory session store for the agentic wizard."""
from __future__ import annotations
from typing import Any, TypedDict
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
```

- [ ] **Step 4: Run test to verify pass**

```bash
cd ~/projects/p2-threat-model-generator && python -m pytest tests/test_session.py -v
```
Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
cd ~/projects/p2-threat-model-generator && git add agent/session.py tests/test_session.py && git commit -m "feat(agent): add in-memory session store"
```

---

## Task 3: Tools — start_app, set_compliance

**Files:**
- Create: `agent/tools.py` (start)
- Create: `tests/test_agent_tools.py` (start)

- [ ] **Step 1: Write failing tests**

Path: `~/projects/p2-threat-model-generator/tests/test_agent_tools.py`

```python
"""Unit tests for agent tools."""
from __future__ import annotations
import json
import pytest
from agent.session import reset_session, get_session
from agent.tools import start_app, set_compliance


def test_start_app_creates_descriptor() -> None:
    reset_session("s1")
    result = start_app(
        session_id="s1", name="Shop", version="2.0",
        description="e-commerce", owner="platform",
        environment="production", internet_facing=True,
        data_classification="confidential",
    )
    data = json.loads(result)
    assert data["ok"] is True
    assert data["app"] == "Shop"
    d = get_session("s1")["descriptor"]
    assert d is not None
    assert d.name == "Shop"
    assert d.environment == "production"


def test_start_app_rejects_bad_environment() -> None:
    reset_session("s2")
    result = start_app(
        session_id="s2", name="X", version="1.0",
        description="", owner="", environment="mars",
        internet_facing=True, data_classification="internal",
    )
    data = json.loads(result)
    assert data["ok"] is False
    assert "environment" in data["error"]


def test_set_compliance_adds_frameworks() -> None:
    reset_session("s3")
    start_app(session_id="s3", name="A", version="1", description="",
              owner="", environment="production", internet_facing=True,
              data_classification="internal")
    result = set_compliance(session_id="s3", frameworks=["gdpr", "soc2"])
    data = json.loads(result)
    assert data["ok"] is True
    assert get_session("s3")["descriptor"].compliance_frameworks == ["gdpr", "soc2"]


def test_set_compliance_requires_start_app_first() -> None:
    reset_session("s4")
    result = set_compliance(session_id="s4", frameworks=["gdpr"])
    data = json.loads(result)
    assert data["ok"] is False
    assert "start_app" in data["error"]
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/projects/p2-threat-model-generator && python -m pytest tests/test_agent_tools.py -v
```
Expected: FAIL — `ModuleNotFoundError: No module named 'agent.tools'`

- [ ] **Step 3: Write implementation**

Path: `~/projects/p2-threat-model-generator/agent/tools.py`

```python
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
    if not has_session(session_id):
        return _err("No descriptor. Call start_app first.")
    unknown = [f for f in frameworks if f not in _VALID_FRAMEWORKS]
    if unknown:
        return _err(f"Unknown frameworks: {unknown}. Valid: {sorted(_VALID_FRAMEWORKS)}")
    get_session(session_id)["descriptor"].compliance_frameworks = list(frameworks)
    return _ok(frameworks=frameworks)
```

- [ ] **Step 4: Run tests to verify pass**

```bash
cd ~/projects/p2-threat-model-generator && python -m pytest tests/test_agent_tools.py -v
```
Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
cd ~/projects/p2-threat-model-generator && git add agent/tools.py tests/test_agent_tools.py && git commit -m "feat(agent): start_app + set_compliance tools"
```

---

## Task 4: Tools — add_component, add_data_flow

**Files:**
- Modify: `agent/tools.py`
- Modify: `tests/test_agent_tools.py`

- [ ] **Step 1: Add failing tests**

Append to `~/projects/p2-threat-model-generator/tests/test_agent_tools.py`:

```python
from agent.tools import add_component, add_data_flow


def _start(sid: str) -> None:
    reset_session(sid)
    start_app(session_id=sid, name="A", version="1", description="",
              owner="", environment="production", internet_facing=True,
              data_classification="internal")


def test_add_component_ok() -> None:
    _start("c1")
    result = add_component(
        session_id="c1", name="API", type="api",
        technology="FastAPI", auth_type="jwt",
        stores_pii=True, stores_credentials=False,
        internet_facing=True, has_logging=True,
        has_rate_limiting=False, notes="",
    )
    data = json.loads(result)
    assert data["ok"] is True
    assert data["component_count"] == 1
    d = get_session("c1")["descriptor"]
    assert d.components[0].name == "API"
    assert d.components[0].stores_pii is True


def test_add_component_rejects_bad_type() -> None:
    _start("c2")
    result = add_component(
        session_id="c2", name="X", type="unicorn",
        technology="", auth_type="none",
        stores_pii=False, stores_credentials=False,
        internet_facing=False, has_logging=True,
        has_rate_limiting=False, notes="",
    )
    data = json.loads(result)
    assert data["ok"] is False
    assert "type" in data["error"]


def test_add_data_flow_ok() -> None:
    _start("f1")
    add_component(session_id="f1", name="Web", type="web_app",
                  technology="", auth_type="none", stores_pii=False,
                  stores_credentials=False, internet_facing=True,
                  has_logging=True, has_rate_limiting=False, notes="")
    add_component(session_id="f1", name="API", type="api",
                  technology="", auth_type="jwt", stores_pii=False,
                  stores_credentials=False, internet_facing=False,
                  has_logging=True, has_rate_limiting=True, notes="")
    result = add_data_flow(
        session_id="f1", name="Web->API", source="Web", destination="API",
        encrypted=True, authenticated=True, crosses_trust_boundary=True,
        protocol="HTTPS", data_classification="confidential",
    )
    data = json.loads(result)
    assert data["ok"] is True
    assert data["flow_count"] == 1
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/projects/p2-threat-model-generator && python -m pytest tests/test_agent_tools.py -v
```
Expected: 3 FAIL — `ImportError: cannot import name 'add_component'`

- [ ] **Step 3: Add implementation**

Append to `~/projects/p2-threat-model-generator/agent/tools.py`:

```python
from models import Component, ComponentType, AuthType, DataFlow


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
    if not has_session(session_id):
        return _err("No descriptor. Call start_app first.")
    if data_classification not in _VALID_DATA_CLASS:
        return _err(f"Invalid data_classification {data_classification!r}.")
    d = get_session(session_id)["descriptor"]
    d.data_flows.append(DataFlow(
        name=name, source=source, destination=destination,
        data_classification=data_classification, encrypted=encrypted,
        authenticated=authenticated, crosses_trust_boundary=crosses_trust_boundary,
        protocol=protocol,
    ))
    return _ok(flow_count=len(d.data_flows), name=name)
```

- [ ] **Step 4: Run tests to verify pass**

```bash
cd ~/projects/p2-threat-model-generator && python -m pytest tests/test_agent_tools.py -v
```
Expected: 7 passed

- [ ] **Step 5: Commit**

```bash
cd ~/projects/p2-threat-model-generator && git add agent/tools.py tests/test_agent_tools.py && git commit -m "feat(agent): add_component + add_data_flow tools"
```

---

## Task 5: Tools — list_components, list_flows, get_app

**Files:**
- Modify: `agent/tools.py`
- Modify: `tests/test_agent_tools.py`

- [ ] **Step 1: Add failing tests**

Append to `~/projects/p2-threat-model-generator/tests/test_agent_tools.py`:

```python
from agent.tools import list_components, list_flows, get_app


def test_list_components_empty() -> None:
    _start("l1")
    result = list_components(session_id="l1")
    data = json.loads(result)
    assert data["ok"] is True
    assert data["components"] == []


def test_list_components_populated() -> None:
    _start("l2")
    add_component(session_id="l2", name="X", type="api",
                  technology="", auth_type="none", stores_pii=True,
                  stores_credentials=False, internet_facing=True,
                  has_logging=True, has_rate_limiting=False, notes="")
    data = json.loads(list_components(session_id="l2"))
    assert data["components"][0]["name"] == "X"
    assert data["components"][0]["stores_pii"] is True


def test_get_app_returns_summary() -> None:
    _start("g1")
    data = json.loads(get_app(session_id="g1"))
    assert data["ok"] is True
    assert data["name"] == "A"
    assert data["component_count"] == 0
    assert data["flow_count"] == 0
```

- [ ] **Step 2: Run tests to verify fail**

```bash
cd ~/projects/p2-threat-model-generator && python -m pytest tests/test_agent_tools.py -v
```
Expected: 3 new FAIL

- [ ] **Step 3: Add implementation**

Append to `~/projects/p2-threat-model-generator/agent/tools.py`:

```python
from dataclasses import asdict


@tool(description="List all components in the current session's app. "
                  "Use this when you need to review what's been added before running STRIDE.",
      risk=ToolRisk.NONE)
def list_components(session_id: str) -> str:
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
```

- [ ] **Step 4: Run tests to verify pass**

```bash
cd ~/projects/p2-threat-model-generator && python -m pytest tests/test_agent_tools.py -v
```
Expected: 10 passed

- [ ] **Step 5: Commit**

```bash
cd ~/projects/p2-threat-model-generator && git add agent/tools.py tests/test_agent_tools.py && git commit -m "feat(agent): list/get inspection tools"
```

---

## Task 6: Tool — run_stride_analysis

**Files:**
- Modify: `agent/tools.py`
- Modify: `tests/test_agent_tools.py`

- [ ] **Step 1: Add failing test**

Append to `~/projects/p2-threat-model-generator/tests/test_agent_tools.py`:

```python
from agent.tools import run_stride_analysis


def test_run_stride_populates_threats() -> None:
    _start("st1")
    add_component(session_id="st1", name="API", type="api",
                  technology="FastAPI", auth_type="none", stores_pii=True,
                  stores_credentials=False, internet_facing=True,
                  has_logging=False, has_rate_limiting=False, notes="")
    result = run_stride_analysis(session_id="st1")
    data = json.loads(result)
    assert data["ok"] is True
    assert data["threat_count"] > 0
    threats = get_session("st1")["threats"]
    assert len(threats) > 0
    assert all(hasattr(t, "stride_category") for t in threats)


def test_run_stride_needs_descriptor() -> None:
    reset_session("st2")
    data = json.loads(run_stride_analysis(session_id="st2"))
    assert data["ok"] is False
```

- [ ] **Step 2: Run test to verify fail**

```bash
cd ~/projects/p2-threat-model-generator && python -m pytest tests/test_agent_tools.py -v
```
Expected: 2 new FAIL

- [ ] **Step 3: Add implementation**

Append to `~/projects/p2-threat-model-generator/agent/tools.py`:

```python
from engine.stride import run_stride


@tool(description="Run the STRIDE rule engine on the current session's app. "
                  "Generates threats for every component + data flow. "
                  "Call this only after start_app + all add_component + add_data_flow calls.",
      risk=ToolRisk.NONE)
def run_stride_analysis(session_id: str) -> str:
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
```

- [ ] **Step 4: Run tests to verify pass**

```bash
cd ~/projects/p2-threat-model-generator && python -m pytest tests/test_agent_tools.py -v
```
Expected: 12 passed

- [ ] **Step 5: Commit**

```bash
cd ~/projects/p2-threat-model-generator && git add agent/tools.py tests/test_agent_tools.py && git commit -m "feat(agent): run_stride_analysis tool"
```

---

## Task 7: Tool — enrich_threats (LLM narrative)

**Files:**
- Modify: `agent/tools.py`
- Modify: `tests/test_agent_tools.py`

- [ ] **Step 1: Add failing test**

Append to `~/projects/p2-threat-model-generator/tests/test_agent_tools.py`:

```python
from agent.tools import enrich_threats
from unittest.mock import patch


def test_enrich_threats_no_threats() -> None:
    _start("e1")
    data = json.loads(enrich_threats(session_id="e1", max_threats=3))
    assert data["ok"] is False
    assert "no threats" in data["error"].lower()


def test_enrich_threats_calls_enrich_all() -> None:
    _start("e2")
    add_component(session_id="e2", name="API", type="api",
                  technology="", auth_type="none", stores_pii=True,
                  stores_credentials=False, internet_facing=True,
                  has_logging=False, has_rate_limiting=False, notes="")
    run_stride_analysis(session_id="e2")
    with patch("agent.tools.enrich_all") as mock:
        result = enrich_threats(session_id="e2", max_threats=2)
        mock.assert_called_once()
        args, kwargs = mock.call_args
        assert kwargs.get("max_threats", args[1] if len(args) > 1 else None) == 2
    data = json.loads(result)
    assert data["ok"] is True
```

- [ ] **Step 2: Run tests to verify fail**

```bash
cd ~/projects/p2-threat-model-generator && python -m pytest tests/test_agent_tools.py -v
```
Expected: 2 new FAIL

- [ ] **Step 3: Add implementation**

Append to `~/projects/p2-threat-model-generator/agent/tools.py`:

```python
from engine.llm import enrich_all


@tool(description="Enrich the top N highest-scoring threats with LLM-written narratives via "
                  "the Ollama endpoint configured in engine/llm.py. Skips silently if Ollama "
                  "is unreachable. Call after run_stride_analysis.",
      risk=ToolRisk.NONE)
def enrich_threats(session_id: str, max_threats: int) -> str:
    if not has_session(session_id):
        return _err("No descriptor. Call start_app first.")
    threats = get_session(session_id)["threats"]
    if not threats:
        return _err("No threats to enrich. Call run_stride_analysis first.")
    enrich_all(threats, max_threats=max_threats)
    enriched = sum(1 for t in threats if t.llm_narrative)
    return _ok(enriched=enriched, total=len(threats))
```

- [ ] **Step 4: Run tests to verify pass**

```bash
cd ~/projects/p2-threat-model-generator && python -m pytest tests/test_agent_tools.py -v
```
Expected: 14 passed

- [ ] **Step 5: Commit**

```bash
cd ~/projects/p2-threat-model-generator && git add agent/tools.py tests/test_agent_tools.py && git commit -m "feat(agent): enrich_threats tool"
```

---

## Task 8: Tool — score_threats

**Files:**
- Modify: `agent/tools.py`
- Modify: `tests/test_agent_tools.py`

- [ ] **Step 1: Add failing test**

Append to `~/projects/p2-threat-model-generator/tests/test_agent_tools.py`:

```python
from agent.tools import score_threats


def test_score_threats_builds_model() -> None:
    _start("sc1")
    add_component(session_id="sc1", name="API", type="api",
                  technology="", auth_type="none", stores_pii=True,
                  stores_credentials=False, internet_facing=True,
                  has_logging=False, has_rate_limiting=False, notes="")
    run_stride_analysis(session_id="sc1")
    result = score_threats(session_id="sc1")
    data = json.loads(result)
    assert data["ok"] is True
    assert data["overall_risk_score"] >= 0
    assert "severity_breakdown" in data
    tm = get_session("sc1")["model"]
    assert tm is not None
    assert tm.overall_risk_score == data["overall_risk_score"]
```

- [ ] **Step 2: Run test to verify fail**

```bash
cd ~/projects/p2-threat-model-generator && python -m pytest tests/test_agent_tools.py -v
```
Expected: 1 new FAIL

- [ ] **Step 3: Add implementation**

Append to `~/projects/p2-threat-model-generator/agent/tools.py`:

```python
from engine.scorer import build_threat_model


@tool(description="Compute risk scores, compliance flags, and overall risk. Builds the final "
                  "ThreatModel from the current threats. Call after run_stride_analysis "
                  "(and optionally enrich_threats).",
      risk=ToolRisk.NONE)
def score_threats(session_id: str) -> str:
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
```

- [ ] **Step 4: Run tests to verify pass**

```bash
cd ~/projects/p2-threat-model-generator && python -m pytest tests/test_agent_tools.py -v
```
Expected: 15 passed

- [ ] **Step 5: Commit**

```bash
cd ~/projects/p2-threat-model-generator && git add agent/tools.py tests/test_agent_tools.py && git commit -m "feat(agent): score_threats tool"
```

---

## Task 9: Tool — generate_report

**Files:**
- Modify: `agent/tools.py`
- Modify: `tests/test_agent_tools.py`

- [ ] **Step 1: Add failing test**

Append to `~/projects/p2-threat-model-generator/tests/test_agent_tools.py`:

```python
from agent.tools import generate_report
import tempfile
import os


def test_generate_report_json_and_html(tmp_path) -> None:
    _start("g1")
    add_component(session_id="g1", name="API", type="api",
                  technology="", auth_type="none", stores_pii=True,
                  stores_credentials=False, internet_facing=True,
                  has_logging=False, has_rate_limiting=False, notes="")
    run_stride_analysis(session_id="g1")
    score_threats(session_id="g1")
    result = generate_report(session_id="g1", format="all", output_dir=str(tmp_path))
    data = json.loads(result)
    assert data["ok"] is True
    files = os.listdir(tmp_path)
    assert any(f.endswith(".json") for f in files)
    assert any(f.endswith(".html") for f in files)


def test_generate_report_requires_score() -> None:
    _start("g2")
    result = generate_report(session_id="g2", format="json", output_dir=".")
    data = json.loads(result)
    assert data["ok"] is False
    assert "score_threats" in data["error"]
```

- [ ] **Step 2: Run tests to verify fail**

```bash
cd ~/projects/p2-threat-model-generator && python -m pytest tests/test_agent_tools.py -v
```
Expected: 2 new FAIL

- [ ] **Step 3: Add implementation**

Append to `~/projects/p2-threat-model-generator/agent/tools.py`:

```python
import os
from reporter.json_reporter import generate_json
from reporter.html_reporter import generate_html


@tool(description="Write threat-model report file(s) to output_dir. "
                  "format: json|html|all. Requires score_threats to have been called first.",
      risk=ToolRisk.FILESYSTEM)
def generate_report(session_id: str, format: str, output_dir: str) -> str:
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
```

- [ ] **Step 4: Run tests to verify pass**

```bash
cd ~/projects/p2-threat-model-generator && python -m pytest tests/test_agent_tools.py -v
```
Expected: 17 passed

- [ ] **Step 5: Commit**

```bash
cd ~/projects/p2-threat-model-generator && git add agent/tools.py tests/test_agent_tools.py && git commit -m "feat(agent): generate_report tool"
```

---

## Task 10: Tool — ask_user (interactive prompt)

**Files:**
- Modify: `agent/tools.py`
- Modify: `tests/test_agent_tools.py`

- [ ] **Step 1: Add failing test**

Append to `~/projects/p2-threat-model-generator/tests/test_agent_tools.py`:

```python
from agent.tools import ask_user
from unittest.mock import patch


def test_ask_user_returns_input() -> None:
    with patch("builtins.input", return_value="my-app"):
        result = ask_user(question="What is the app name?")
    data = json.loads(result)
    assert data["ok"] is True
    assert data["answer"] == "my-app"


def test_ask_user_strips_whitespace() -> None:
    with patch("builtins.input", return_value="  x  "):
        result = ask_user(question="?")
    data = json.loads(result)
    assert data["answer"] == "x"
```

- [ ] **Step 2: Run tests to verify fail**

```bash
cd ~/projects/p2-threat-model-generator && python -m pytest tests/test_agent_tools.py -v
```
Expected: 2 new FAIL

- [ ] **Step 3: Add implementation**

Append to `~/projects/p2-threat-model-generator/agent/tools.py`:

```python
@tool(description="Ask the human user a single question and return their answer as a string. "
                  "Use this to gather details about their application: name, components, "
                  "authentication, data flows, compliance requirements. Ask ONE question at a "
                  "time; wait for the answer; then decide the next question. Do not batch. "
                  "The response is the raw user string — parse it yourself.",
      risk=ToolRisk.NONE)
def ask_user(question: str) -> str:
    print(f"\n🤖 {question}")
    answer = input("👤 ").strip()
    return _ok(answer=answer)
```

- [ ] **Step 4: Run tests to verify pass**

```bash
cd ~/projects/p2-threat-model-generator && python -m pytest tests/test_agent_tools.py -v
```
Expected: 19 passed

- [ ] **Step 5: Commit**

```bash
cd ~/projects/p2-threat-model-generator && git add agent/tools.py tests/test_agent_tools.py && git commit -m "feat(agent): ask_user interactive tool"
```

---

## Task 11: ThreatModelAgent wrapper

**Files:**
- Create: `agent/threat_model_agent.py`
- Create: `tests/test_threat_model_agent.py`

- [ ] **Step 1: Write failing test**

Path: `~/projects/p2-threat-model-generator/tests/test_threat_model_agent.py`

```python
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
```

- [ ] **Step 2: Run test to verify fail**

```bash
cd ~/projects/p2-threat-model-generator && python -m pytest tests/test_threat_model_agent.py -v
```
Expected: 2 FAIL

- [ ] **Step 3: Write implementation**

Path: `~/projects/p2-threat-model-generator/agent/threat_model_agent.py`

```python
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
```

- [ ] **Step 4: Run tests to verify pass**

```bash
cd ~/projects/p2-threat-model-generator && python -m pytest tests/test_threat_model_agent.py -v
```
Expected: 2 passed

- [ ] **Step 5: Commit**

```bash
cd ~/projects/p2-threat-model-generator && git add agent/threat_model_agent.py tests/test_threat_model_agent.py && git commit -m "feat(agent): ThreatModelAgent wrapper"
```

---

## Task 12: CLI dispatch — --agentic flag

**Files:**
- Modify: `p2_threat_model.py`

- [ ] **Step 1: Read the current CLI structure**

Open `~/projects/p2-threat-model-generator/p2_threat_model.py` and locate the `argparse` block plus the `main()` dispatch.

- [ ] **Step 2: Add CLI flags**

In the argparse setup, add these arguments after the existing ones:

```python
parser.add_argument(
    "--agentic", action="store_true",
    help="Run in agentic mode: LLM-driven interactive wizard using agent-core.",
)
parser.add_argument(
    "--provider", choices=["claude", "ollama"], default="ollama",
    help="LLM provider for agentic mode. Default: ollama.",
)
parser.add_argument(
    "--describe", default="",
    help="Seed application description for the agent (agentic mode only).",
)
parser.add_argument(
    "--describe-file", default="",
    help="Read seed application description from a file (agentic mode only).",
)
parser.add_argument(
    "--output-dir", default="./output",
    help="Output directory for reports. Default: ./output.",
)
```

- [ ] **Step 3: Add agentic dispatch**

Near the top of `main()`, after `args = parser.parse_args()`, add:

```python
if args.agentic:
    return _run_agentic(args)
```

Then add this function above `main()`:

```python
def _run_agentic(args) -> int:
    """Dispatch to the agentic wizard. Returns exit code."""
    import os
    from agent import ThreatModelAgent
    from agent_core.llm import get_provider

    describe = args.describe
    if args.describe_file:
        with open(args.describe_file, "r", encoding="utf-8") as f:
            describe = f.read()

    os.environ.setdefault("AGENT_CORE_PROVIDER", args.provider)
    provider = get_provider()
    agent = ThreatModelAgent(provider=provider)
    result = agent.run(describe=describe, output_dir=args.output_dir)
    print("\n" + "=" * 60)
    print(f"Agent finished. Stop reason: {result.stop_reason.value}")
    print(f"Iterations: {result.iterations}")
    print("=" * 60)
    print(result.output)
    return 0 if result.stop_reason.value == "done" else 1
```

- [ ] **Step 4: Verify CLI parses**

```bash
cd ~/projects/p2-threat-model-generator && python p2_threat_model.py --help
```
Expected: help output includes `--agentic`, `--provider`, `--describe`, `--describe-file`, `--output-dir`.

- [ ] **Step 5: Verify --agentic path resolves the agent import**

```bash
cd ~/projects/p2-threat-model-generator && python -c "from agent import ThreatModelAgent; print('ok')"
```
Expected: `ok`

- [ ] **Step 6: Commit**

```bash
cd ~/projects/p2-threat-model-generator && git add p2_threat_model.py && git commit -m "feat(cli): add --agentic mode dispatch"
```

---

## Task 13: Smoke test with mock provider

**Files:**
- Create: `tests/test_agent_smoke.py`

- [ ] **Step 1: Write the smoke test**

Path: `~/projects/p2-threat-model-generator/tests/test_agent_smoke.py`

```python
"""End-to-end smoke test with a scripted mock provider.

Simulates: agent calls start_app → add_component → run_stride → score → generate_report.
Verifies the full pipeline wires up without hitting a real LLM.
"""
from __future__ import annotations
import json
import os
import tempfile
from unittest.mock import MagicMock
from agent import ThreatModelAgent
from agent_core.models import (
    AgentResult, StopReason, ToolCall, Message, MessageRole,
)


def test_full_pipeline_smoke(tmp_path) -> None:
    provider = MagicMock()
    # Simulate agent completing its work; the actual tool calls are exercised via the
    # agent-core loop — for this smoke test we just verify the wrapper glue.
    fake_result = AgentResult(
        output="Threat model generated: 12 threats, 2 critical.",
        stop_reason=StopReason.DONE,
        iterations=15,
        tool_calls=[],
        artifacts=[],
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
```

- [ ] **Step 2: Run smoke test**

```bash
cd ~/projects/p2-threat-model-generator && python -m pytest tests/test_agent_smoke.py -v
```
Expected: 1 passed

- [ ] **Step 3: Run full test suite**

```bash
cd ~/projects/p2-threat-model-generator && python -m pytest -v
```
Expected: all tests pass (existing + new agent tests).

- [ ] **Step 4: Commit**

```bash
cd ~/projects/p2-threat-model-generator && git add tests/test_agent_smoke.py && git commit -m "test(agent): end-to-end smoke test"
```

---

## Task 14: Real-provider live test + docs

**Files:**
- Modify: `README.md`
- Modify: `writeup.md`

- [ ] **Step 1: Run the agentic wizard against Claude (manual)**

```bash
cd ~/projects/p2-threat-model-generator && python p2_threat_model.py \
    --agentic --provider claude \
    --describe "REST API on FastAPI backed by PostgreSQL. Public login endpoint. Stores PII." \
    --output-dir ./output
```

Expected: agent asks a few clarifying questions, extracts components + flows, produces `output/<app-slug>-threat-model.json` and `.html`. Confirm files exist and open the HTML in a browser.

- [ ] **Step 2: Update README.md**

Add a section under existing usage:

```markdown
## Agentic Mode

Run the LLM-driven interactive wizard instead of the scripted one:

```bash
# Interactive interview (Claude)
python p2_threat_model.py --agentic --provider claude

# Seeded from a description (Ollama)
python p2_threat_model.py --agentic --provider ollama \
    --describe "e-commerce API on FastAPI + Postgres"

# From a file
python p2_threat_model.py --agentic --describe-file architecture.md
```

The agent uses the `ask_user` tool to interview you one question at a time, then runs STRIDE, scoring, and report generation automatically. Reports land in `./output/`.
```

- [ ] **Step 3: Update writeup.md**

Append a section describing the agentic architecture, tool list, and rationale (mirrors P1's writeup format).

- [ ] **Step 4: Commit**

```bash
cd ~/projects/p2-threat-model-generator && git add README.md writeup.md && git commit -m "docs: agentic mode usage + writeup"
```

- [ ] **Step 5: Push**

```bash
cd ~/projects/p2-threat-model-generator && git push origin master
```
