"""Generate SARIF 2.1.0 threat model report for GitHub Security tab / DefectDojo."""
from __future__ import annotations
import json
from pathlib import Path
from models import Severity, ThreatModel

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH:     "error",
    Severity.MEDIUM:   "warning",
    Severity.LOW:      "note",
    Severity.INFO:     "none",
}

_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH:     "7.5",
    Severity.MEDIUM:   "5.0",
    Severity.LOW:      "2.5",
    Severity.INFO:     "0.0",
}


def _component_uri(name: str) -> str:
    return f"components/{name.lower().replace(' ', '-')}"


def generate_sarif(tm: ThreatModel, output_path: str) -> None:
    """Write SARIF 2.1.0 — compatible with GitHub Security tab and DefectDojo."""
    rules = []
    seen: set[str] = set()
    for t in tm.threats:
        if t.id in seen:
            continue
        seen.add(t.id)
        tags = (
            [m.technique_id for m in t.mitre_mappings]
            + [o.category_id for o in t.owasp_mappings]
            + [n.control_id for n in t.nist_controls]
        )
        rules.append({
            "id": t.id,
            "name": t.title.replace(" ", "").replace("—", "").replace("/", ""),
            "shortDescription": {"text": t.title},
            "fullDescription": {"text": t.description},
            "helpUri": t.mitre_mappings[0].url if t.mitre_mappings else "",
            "help": {
                "text": (
                    f"Attack Vector: {t.attack_vector}\n\n"
                    f"Business Impact: {t.business_impact}\n\n"
                    f"Mitigations:\n" + "\n".join(f"- {m}" for m in t.mitigations)
                ),
                "markdown": (
                    f"**Attack Vector:** {t.attack_vector}\n\n"
                    f"**Business Impact:** {t.business_impact}\n\n"
                    f"**Mitigations:**\n" + "\n".join(f"- {m}" for m in t.mitigations)
                ),
            },
            "properties": {
                "security-severity": _SECURITY_SEVERITY[t.severity],
                "stride-category": t.stride_category.value,
                "remediation-effort": t.remediation_effort,
                "tags": tags,
            },
        })

    results = []
    for t in tm.threats:
        uri = _component_uri(t.component)
        message_text = (
            f"{t.description}\n\n"
            f"Attack Vector: {t.attack_vector}\n\n"
            f"Business Impact: {t.business_impact}\n\n"
            f"Mitigations:\n" + "\n".join(f"- {m}" for m in t.mitigations)
        )
        if t.llm_narrative:
            message_text += f"\n\nExecutive Summary: {t.llm_narrative}"

        result: dict = {
            "ruleId": t.id,
            "level": _SARIF_LEVEL[t.severity],
            "message": {"text": message_text},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": uri,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {"startLine": 1},
                },
                "logicalLocations": [{
                    "name": t.component,
                    "kind": "component",
                }],
            }],
            "properties": {
                "risk-score": t.risk_score,
                "likelihood": t.likelihood,
                "impact": t.impact,
                "sprint-priority": t.sprint_priority,
                "mitre-attack": [m.technique_id for m in t.mitre_mappings],
                "owasp-2021": [o.category_id for o in t.owasp_mappings],
                "nist-800-53": [n.control_id for n in t.nist_controls],
            },
        }
        if t.mitre_mappings:
            result["relatedLocations"] = [{
                "id": i,
                "message": {"text": f"{m.technique_id}: {m.technique_name} ({m.tactic})"},
                "physicalLocation": {
                    "artifactLocation": {"uri": m.url},
                },
            } for i, m in enumerate(t.mitre_mappings)]

        results.append(result)

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "P2 Threat Model Generator",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/PyHackSecGP/p2-threat-model-generator",
                    "rules": rules,
                }
            },
            "results": results,
            "properties": {
                "application": tm.app.name,
                "environment": tm.app.environment,
                "overall-risk-score": tm.overall_risk_score,
                "generated-at": tm.generated_at,
                "compliance-frameworks": list(tm.app.compliance_frameworks),
            },
        }],
    }

    Path(output_path).write_text(json.dumps(sarif, indent=2), encoding="utf-8")
