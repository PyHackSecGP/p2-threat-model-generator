"""Unit tests for agent tools."""
from __future__ import annotations
import json
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
