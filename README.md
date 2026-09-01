# P2 — Threat Model Generator

**Role:** Security Analyst / Security Engineer portfolio project  
**Stack:** Python 3.11 · STRIDE · MITRE ATT&CK · OWASP 2021 · NIST 800-53 · Ollama (on-prem LLM) · Chart.js

---

## Why I Built This Instead of Using an Existing Tool

Tools like **IriusRisk**, **ThreatModeler**, and **Microsoft Threat Modeling Tool** already exist and are used in production security programs. I didn't build this to replace them — I built it to *understand* them deeply enough to configure, evaluate, and extend them in a real security program.

Before I can tell a team whether a $50k/year threat modelling SaaS is worth buying, or before I can customise its rule sets for a specific compliance framework, I need to know what's happening under the hood:

- How do you translate "this component stores PII" into a specific, scored threat?
- How do you maintain scoring consistency across 40 components without a human making judgment calls?
- Where does MITRE ATT&CK fit in threat modelling vs. incident response vs. detection engineering?
- What does a GDPR compliance flag *mean* at the architecture level, and which NIST control addresses it?

Building this from scratch forced me to answer every one of those questions. I can now sit in a threat modelling session, run one of those commercial tools, and immediately understand *why* it flagged something — not just that it did. That's a different level of competence than knowing how to click through a UI.

---

## What It Does

Given an application descriptor — YAML, OpenAPI spec, Dockerfile, docker-compose, or Kubernetes manifest — the pipeline:

1. **Parses** the architecture into components, data flows, trust boundaries, and auth types
2. **Runs STRIDE** — evaluates every component against all six threat categories using attribute-based heuristics
3. **Scores each threat** using `risk_score = likelihood × impact × 4` → Critical / High / Medium / Low
4. **Maps to MITRE ATT&CK** — every threat gets a technique ID so it can connect to detection and response work
5. **Flags compliance exposure** — GDPR, PCI-DSS, SOC2, HIPAA with specific NIST 800-53 control references
6. **Enriches with LLM narratives** — top threats get executive-language explanations via on-prem Ollama (no data leaves the network)
7. **Outputs** a self-contained HTML report with Chart.js visuals and machine-readable JSON for CI/CD

---

## Concrete Scenario: Fintech Startup Pre-Launch

A fintech startup is launching a payment API. A developer opens a PR with a new `docker-compose.yml`. Instead of waiting for a dedicated threat model session that may never get scheduled, the CI pipeline runs on every PR:

```bash
python p2_threat_model.py --input docker-compose.yml --output output/
```

**Output, 2 minutes later:**
```
[+] Application: Payment Service | Components: 4 | Data flows: 6
[+] Generated 31 threats
[+] Overall risk score: 84/100
[+] Critical: 4 | High: 9 | Medium: 13 | Low: 5
[+] Compliance flags: GDPR, PCI-DSS

── Top Findings ───────────────────────────────────────────
  [Critical]  92.0  Postgres — PII stored, no encryption at rest (CWE-312)
  [Critical]  88.0  Payment API — No rate limiting on /charge endpoint (T1499)
  [Critical]  80.0  Redis — No auth, internet-accessible port (T1078.001)
  [High    ]  68.0  JWT secret hardcoded in environment variable (CWE-798)
```

The PR gets a risk summary comment automatically. The developer fixes Redis auth and the rate limiting gap before the PR merges. The startup avoids an exposure that would have triggered a PCI-DSS audit finding.

This is why threat modelling needs to be in the pipeline, not a quarterly workshop. Moving it left means catching design flaws before they become code, and catching code flaws before they become incidents.

---

## STRIDE Implementation — What I Had to Actually Learn

STRIDE is simple in concept. Operationalising it is where the real work is. What component attributes trigger which threat, and why?

**Example: Spoofing**

```python
# engine/stride.py — simplified
if component.auth_type == AuthType.NONE and component.internet_facing:
    threats.append(Threat(
        category=STRIDE.SPOOFING,
        title=f"No Authentication — {component.name}",
        likelihood=5,          # internet-facing + no auth = near-certain
        impact=4,              # attacker acts as any user
        mitre_technique="T1078",    # Valid Accounts
        nist_control="IA-2",        # Identification and Authentication
        cwe="CWE-306",              # Missing Authentication for Critical Function
    ))
```

Every one of the ~30 STRIDE rules required understanding the *security reasoning* behind it — not just the category name. That understanding transfers directly to configuring commercial tools, writing detection rules, and doing manual threat model reviews.

---

## Kubernetes Parser — Why It Was the Hardest Input Format

Kubernetes threat modelling is architecturally different from application-level modelling. The threats aren't about what the application does — they're about how the container runtime, network policies, and secret management interact.

Key things the parser had to reason about:

- **`NetworkPolicy` as trust boundary** — absence of one means all pods in a namespace can reach each other
- **Secrets in env vars vs. volume mounts** — both expose secrets, but env var injection is visible to child processes and often logged
- **`LoadBalancer` vs `ClusterIP` Services** — one is internet-facing, the other isn't; the parser promotes a workload to internet-facing when a LoadBalancer Service selects it
- **`privileged: true` and `runAsUser: 0`** — these are effectively container escapes waiting for a CVE; the parser flags them as high-severity notes on the component

Commercial K8s security tools like Checkov and Trivy check similar things. Building this parser gave me the foundation to read their output, understand why a specific finding matters, and extend their rule sets for custom environments.

---

## LLM Integration — Deliberate Design Decisions

**Why on-prem Ollama only?** Application descriptors contain component names, data classifications, and architecture topology. Sending that to a cloud API is itself an information disclosure finding. All LLM calls route to a local Ollama instance on the homelab GPU server.

**Why only top N threats get enriched?** LLM calls take ~8 seconds each. For a 40-threat model, enriching everything takes 5 minutes and produces redundant output. The top 10 by risk score are where the narrative value is — executives need to understand *why* the top finding matters, not all 40.

**Why not let the LLM generate the threats?** LLMs hallucinate. A rule-based STRIDE engine correctly flags "no auth on internet-facing component" every time. The LLM adds *explanation quality* to machine-detected findings — it doesn't replace the detection logic. This is the same design used by commercial tools that bolt AI onto deterministic rule engines.

---

## Architecture

```
Input file (auto-detected)
    │
    ▼
parsers/
  yaml_parser     → explicit application descriptor
  openapi_parser  → API endpoint inventory + auth schemes
  docker_parser   → compose topology + Dockerfile posture
  k8s_parser      → cluster architecture, network policy, ingress
  wizard          → interactive CLI
    │
    ▼
engine/stride.py      attribute-based heuristics → RawThreat list
    │
    ▼
engine/scorer.py      risk_score, severity, MITRE, OWASP, NIST, compliance
    │
    ▼
engine/llm.py         Ollama enrichment (optional, on-prem, top N only)
    │
    ▼
reporter/
  html_reporter   → self-contained HTML + Chart.js
  json_reporter   → machine-readable JSON for CI/CD
```

---

## CI/CD Integration

`.github/workflows/threat-model.yml` triggers on every PR touching application descriptors:
- Runs the rule engine (no LLM — deterministic, fast, no external dependencies)
- Uploads HTML + JSON artifacts
- Posts a risk summary comment on the PR with severity breakdown and compliance flags

This is the same pattern commercial tools use for pipeline integration. Building it myself means I understand exactly what data is flowing, what the latency tradeoffs are, and how to extend it.

---

## Quick Start

```bash
git clone https://git.greenbladesec.com/gpsingh/p2-threat-model-generator
cd p2-threat-model-generator
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python p2_threat_model.py --input examples/webapp.yaml --output output/
python p2_threat_model.py --input examples/k8s-webapp.yaml --output output/
python p2_threat_model.py --input docker-compose.yml --no-llm --output output/
python p2_threat_model.py --wizard
```
