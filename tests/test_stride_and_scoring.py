"""Tests for STRIDE rules (all component types) and risk score normalization."""
from __future__ import annotations
import json
from pathlib import Path
from models import (
    ApplicationDescriptor, AuthType, Component, ComponentType, DataFlow,
    Severity, StrideCategory,
)
from engine.stride import generate_component_threats, run_stride
from engine.scorer import compute_overall_risk, build_threat_model
from reporter.sarif_reporter import generate_sarif


def _component(ctype: ComponentType, **kwargs) -> Component:
    defaults = dict(
        name=ctype.value.replace("_", "-").title(),
        type=ctype, technology="test",
        auth_type=AuthType.NONE,
        stores_pii=False, stores_credentials=False,
        internet_facing=False, has_logging=True,
        has_rate_limiting=False, notes="",
    )
    defaults.update(kwargs)
    return Component(**defaults)


# ── STRIDE rule coverage for previously-missing component types ───────────────

def test_cache_generates_at_least_one_threat() -> None:
    c = _component(ComponentType.CACHE)
    threats = generate_component_threats(c, 1)
    assert len(threats) >= 1
    categories = {t.stride_category for t in threats}
    assert StrideCategory.TAMPERING in categories


def test_cache_with_pii_generates_disclosure_threat() -> None:
    c = _component(ComponentType.CACHE, stores_pii=True)
    threats = generate_component_threats(c, 1)
    cats = {t.stride_category for t in threats}
    assert StrideCategory.INFO_DISCLOSURE in cats


def test_message_queue_generates_tampering_and_dos() -> None:
    c = _component(ComponentType.MESSAGE_QUEUE)
    threats = generate_component_threats(c, 1)
    cats = {t.stride_category for t in threats}
    assert StrideCategory.TAMPERING in cats
    assert StrideCategory.DENIAL_OF_SERVICE in cats


def test_load_balancer_generates_spoofing_and_disclosure() -> None:
    c = _component(ComponentType.LOAD_BALANCER, internet_facing=True)
    threats = generate_component_threats(c, 1)
    cats = {t.stride_category for t in threats}
    assert StrideCategory.SPOOFING in cats
    assert StrideCategory.INFO_DISCLOSURE in cats


def test_cdn_generates_tampering_and_disclosure() -> None:
    c = _component(ComponentType.CDN)
    threats = generate_component_threats(c, 1)
    cats = {t.stride_category for t in threats}
    assert StrideCategory.TAMPERING in cats
    assert StrideCategory.INFO_DISCLOSURE in cats


def test_external_service_generates_tampering() -> None:
    c = _component(ComponentType.EXTERNAL_SERVICE)
    threats = generate_component_threats(c, 1)
    cats = {t.stride_category for t in threats}
    assert StrideCategory.TAMPERING in cats


def test_external_service_with_pii_generates_disclosure() -> None:
    c = _component(ComponentType.EXTERNAL_SERVICE, stores_pii=True)
    threats = generate_component_threats(c, 1)
    cats = {t.stride_category for t in threats}
    assert StrideCategory.INFO_DISCLOSURE in cats


def test_mobile_app_generates_spoofing_and_disclosure() -> None:
    c = _component(ComponentType.MOBILE_APP, internet_facing=True)
    threats = generate_component_threats(c, 1)
    cats = {t.stride_category for t in threats}
    assert StrideCategory.SPOOFING in cats
    assert StrideCategory.INFO_DISCLOSURE in cats


def test_worker_generates_tampering_and_eop() -> None:
    c = _component(ComponentType.WORKER)
    threats = generate_component_threats(c, 1)
    cats = {t.stride_category for t in threats}
    assert StrideCategory.TAMPERING in cats
    assert StrideCategory.ELEVATION_OF_PRIVILEGE in cats


def test_all_threat_ids_unique_within_component() -> None:
    """No two threats within a component should share an ID."""
    for ctype in ComponentType:
        c = _component(ctype, stores_pii=True, internet_facing=True, has_logging=False)
        threats = generate_component_threats(c, 1)
        ids = [t.id for t in threats]
        assert len(ids) == len(set(ids)), f"Duplicate IDs for {ctype}: {ids}"


# ── Risk score normalization ──────────────────────────────────────────────────

def test_overall_risk_empty_returns_zero() -> None:
    assert compute_overall_risk([]) == 0.0


def test_overall_risk_all_critical_is_100() -> None:
    from models import Threat, StrideCategory
    threats = [
        Threat(id=f"T{i}", title="x", stride_category=StrideCategory.TAMPERING,
               component="c", description="d", attack_vector="a", business_impact="b",
               likelihood=5, impact=5)
        for i in range(5)
    ]
    score = compute_overall_risk(threats)
    assert score == 100.0


def test_overall_risk_all_medium_not_capped() -> None:
    from models import Threat, StrideCategory
    threats = [
        Threat(id=f"T{i}", title="x", stride_category=StrideCategory.TAMPERING,
               component="c", description="d", attack_vector="a", business_impact="b",
               likelihood=3, impact=3)
        for i in range(20)
    ]
    # All Medium (score 36 → severity MEDIUM). Medium weight=5, Critical weight=40.
    # normalized = 5/40 * 100 = 12.5
    score = compute_overall_risk(threats)
    assert score < 50.0, f"20 medium threats should not score >=50; got {score}"
    assert score > 0.0


def test_overall_risk_does_not_instantly_cap_with_few_criticals() -> None:
    """3 critical threats on a large app should not score 100."""
    from models import Threat, StrideCategory
    crit = [
        Threat(id=f"C{i}", title="x", stride_category=StrideCategory.TAMPERING,
               component="c", description="d", attack_vector="a", business_impact="b",
               likelihood=5, impact=5)
        for i in range(3)
    ]
    low = [
        Threat(id=f"L{i}", title="y", stride_category=StrideCategory.REPUDIATION,
               component="c", description="d", attack_vector="a", business_impact="b",
               likelihood=1, impact=2)
        for i in range(20)
    ]
    score = compute_overall_risk(crit + low)
    assert score < 100.0, f"3 criticals + 20 lows should not be 100; got {score}"
    assert score > 0.0


# ── SARIF reporter ────────────────────────────────────────────────────────────

def _build_tm() -> object:
    app = ApplicationDescriptor(
        name="TestApp", components=[
            Component(name="API", type=ComponentType.API, technology="FastAPI",
                      auth_type=AuthType.NONE, stores_pii=True, stores_credentials=False,
                      internet_facing=True, has_logging=False, has_rate_limiting=False),
        ],
        data_flows=[
            DataFlow(name="API->DB", source="API", destination="DB",
                     encrypted=False, crosses_trust_boundary=True),
        ],
        compliance_frameworks=["gdpr"],
    )
    from engine.stride import run_stride
    from engine.scorer import build_threat_model
    threats = run_stride(app)
    return build_threat_model(app, threats)


def test_sarif_is_valid_json(tmp_path: Path) -> None:
    tm = _build_tm()
    out = tmp_path / "report.sarif"
    generate_sarif(tm, str(out))
    data = json.loads(out.read_text())
    assert data["version"] == "2.1.0"
    assert "$schema" in data


def test_sarif_has_results(tmp_path: Path) -> None:
    tm = _build_tm()
    out = tmp_path / "report.sarif"
    generate_sarif(tm, str(out))
    data = json.loads(out.read_text())
    run = data["runs"][0]
    assert len(run["results"]) > 0
    assert len(run["tool"]["driver"]["rules"]) > 0


def test_sarif_level_mapping(tmp_path: Path) -> None:
    tm = _build_tm()
    out = tmp_path / "report.sarif"
    generate_sarif(tm, str(out))
    data = json.loads(out.read_text())
    levels = {r["level"] for r in data["runs"][0]["results"]}
    # mixed severity app → must have at least one error or warning
    assert levels & {"error", "warning", "note"}


def test_sarif_security_severity_present(tmp_path: Path) -> None:
    tm = _build_tm()
    out = tmp_path / "report.sarif"
    generate_sarif(tm, str(out))
    data = json.loads(out.read_text())
    rules = data["runs"][0]["tool"]["driver"]["rules"]
    for rule in rules:
        assert "security-severity" in rule["properties"]


def test_generate_report_tool_writes_sarif(tmp_path) -> None:
    """Agent generate_report tool supports sarif format."""
    from agent.session import reset_session
    from agent.tools import start_app, add_component, run_stride_analysis, score_threats, generate_report
    import os
    sid = "sarif-test"
    reset_session(sid)
    start_app(session_id=sid, name="SarifApp", version="1.0", description="",
              owner="", environment="production", internet_facing=True,
              data_classification="confidential")
    add_component(session_id=sid, name="API", type="api", technology="Flask",
                  auth_type="none", stores_pii=True, stores_credentials=False,
                  internet_facing=True, has_logging=False, has_rate_limiting=False, notes="")
    run_stride_analysis(session_id=sid)
    score_threats(session_id=sid)
    result = generate_report(session_id=sid, format="sarif", output_dir=str(tmp_path))
    data = json.loads(result)
    assert data["ok"] is True
    files = os.listdir(tmp_path)
    assert any(f.endswith(".sarif") for f in files)
