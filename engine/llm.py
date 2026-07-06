"""LLM narrative generation via Ollama (on-prem, no data leaves network)."""
from __future__ import annotations
import json
import os
import requests
from models import Threat

OLLAMA_BASE = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
MODEL = os.environ.get("THREAT_MODEL", "hermes3:70b")
TIMEOUT = 120


def _prompt(threat: Threat) -> str:
    return f"""You are a senior cybersecurity consultant writing a threat assessment for a corporate security report.

Threat: {threat.title}
STRIDE Category: {threat.stride_category.value}
Component: {threat.component}
Severity: {threat.severity.value}
Risk Score: {threat.risk_score}/100

Description: {threat.description}
Attack Vector: {threat.attack_vector}
Business Impact: {threat.business_impact}

Write a 3-4 sentence executive-style narrative for this threat. Write for a technical director or CISO audience.
Requirements:
- Lead with the business risk, not the technical detail
- Name the specific attack technique briefly
- State the consequence if exploited (data loss, downtime, regulatory fine, etc.)
- End with a single prioritisation statement

Return only the narrative paragraph. No headings, no bullet points, no markdown."""


def enrich_threat_with_narrative(threat: Threat) -> None:
    """Add LLM-generated narrative to threat in-place. Silently skips on failure."""
    try:
        resp = requests.post(
            f"{OLLAMA_BASE}/api/generate",
            json={"model": MODEL, "prompt": _prompt(threat), "stream": False},
            timeout=TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        threat.llm_narrative = data.get("response", "").strip()
    except Exception:
        threat.llm_narrative = ""


def enrich_all(threats: list[Threat], max_threats: int = 10) -> None:
    """Enrich top threats by risk score with LLM narratives."""
    top = sorted(threats, key=lambda t: t.risk_score, reverse=True)[:max_threats]
    for threat in top:
        enrich_threat_with_narrative(threat)


def is_ollama_available() -> bool:
    try:
        r = requests.get(f"{OLLAMA_BASE}/api/tags", timeout=5)
        return r.status_code == 200
    except Exception:
        return False
