"""Compute overall application risk score and compliance flags."""
from __future__ import annotations
from models import ApplicationDescriptor, ComplianceFlag, Severity, Threat, ThreatModel
import datetime


_COMPLIANCE_RULES: list[dict] = [
    {
        "framework": "GDPR",
        "trigger": lambda app, t: app.data_classification in ("confidential", "restricted") and t.severity in (Severity.CRITICAL, Severity.HIGH),
        "requirement": "Art. 32 — Security of Processing",
        "description": "GDPR requires appropriate technical measures to protect personal data. Critical/High threats against systems processing personal data require immediate remediation.",
    },
    {
        "framework": "GDPR",
        "trigger": lambda app, t: not any(c.has_logging for c in app.components) and t.stride_category.value == "Repudiation",
        "requirement": "Art. 30 — Records of Processing Activities",
        "description": "GDPR mandates records of all data processing. Missing audit logging violates accountability requirements.",
    },
    {
        "framework": "PCI-DSS",
        "trigger": lambda app, t: "pci_dss" in app.compliance_frameworks and t.severity in (Severity.CRITICAL, Severity.HIGH),
        "requirement": "PCI-DSS v4.0 Req. 6 — Develop and Maintain Secure Systems",
        "description": "PCI-DSS requires all Critical/High vulnerabilities to be remediated within 1 month.",
    },
    {
        "framework": "SOC 2",
        "trigger": lambda app, t: "soc2" in app.compliance_frameworks and t.stride_category.value in ("Repudiation", "Information Disclosure"),
        "requirement": "CC7 — System Monitoring",
        "description": "SOC 2 CC7 requires continuous monitoring and logging of security events.",
    },
    {
        "framework": "HIPAA",
        "trigger": lambda app, t: "hipaa" in app.compliance_frameworks and t.severity in (Severity.CRITICAL, Severity.HIGH),
        "requirement": "§ 164.312 — Technical Safeguards",
        "description": "HIPAA requires technical safeguards to control access to ePHI.",
    },
]


def compute_compliance_flags(app: ApplicationDescriptor, threats: list[Threat]) -> list[ComplianceFlag]:
    """Map threats to compliance violations."""
    framework_threats: dict[tuple[str, str], list[str]] = {}

    for rule in _COMPLIANCE_RULES:
        for threat in threats:
            try:
                if rule["trigger"](app, threat):
                    key = (rule["framework"], rule["requirement"])
                    framework_threats.setdefault(key, [])
                    if threat.id not in framework_threats[key]:
                        framework_threats[key].append(threat.id)
            except Exception:
                pass

    flags: list[ComplianceFlag] = []
    for (framework, requirement), threat_ids in framework_threats.items():
        rule = next(r for r in _COMPLIANCE_RULES
                    if r["framework"] == framework and r["requirement"] == requirement)
        flags.append(ComplianceFlag(
            framework=framework,
            requirement=requirement,
            threat_ids=threat_ids,
            description=rule["description"],
        ))
    return flags


def compute_overall_risk(threats: list[Threat]) -> float:
    """
    Overall risk score 0-100.
    Weighted sum: Critical=40pts, High=20pts, Medium=5pts, Low=1pt,
    capped at 100.
    """
    weights = {Severity.CRITICAL: 40, Severity.HIGH: 20, Severity.MEDIUM: 5, Severity.LOW: 1, Severity.INFO: 0}
    raw = sum(weights[t.severity] for t in threats)
    return min(100.0, round(raw, 1))


def build_threat_model(app: ApplicationDescriptor, threats: list[Threat]) -> ThreatModel:
    compliance_flags = compute_compliance_flags(app, threats)
    overall_risk = compute_overall_risk(threats)
    return ThreatModel(
        app=app,
        threats=sorted(threats, key=lambda t: t.risk_score, reverse=True),
        compliance_flags=compliance_flags,
        overall_risk_score=overall_risk,
        generated_at=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )
