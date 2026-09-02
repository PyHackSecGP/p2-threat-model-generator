"""Unit tests for agent tools."""
from __future__ import annotations
import json
import os
from unittest.mock import patch
from agent.session import reset_session, get_session
from agent.tools import (
    start_app, set_compliance, add_component, add_data_flow,
    list_components, list_flows, get_app, run_stride_analysis,
    enrich_threats, score_threats, generate_report,
)


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
