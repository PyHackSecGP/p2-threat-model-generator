# P2 — Threat Model Generator

AI-assisted STRIDE threat modelling tool that produces executive-quality security reports from application descriptors, OpenAPI specs, Dockerfiles, or docker-compose files.

## Features

- **STRIDE analysis** — full threat coverage across all 6 categories
- **Risk scoring** — likelihood × impact × 4, mapped to Critical/High/Medium/Low
- **MITRE ATT&CK mapping** — every threat linked to real techniques
- **OWASP 2021 + NIST 800-53** — compliance control references
- **Compliance flagging** — automatic GDPR, PCI-DSS, SOC2, HIPAA exposure detection
- **LLM narratives** — on-prem Ollama enriches top threats with executive-language paragraphs (no data leaves the network)
- **Visual HTML report** — Chart.js charts, risk heat bars, sprint remediation table, full threat inventory
- **JSON export** — machine-readable, CI/CD-ready

## Input Types (auto-detected)

| Input | Command |
|---|---|
| YAML/JSON descriptor | `python p2_threat_model.py --input app.yaml` |
| OpenAPI / Swagger spec | `python p2_threat_model.py --input openapi.yaml` |
| docker-compose.yml | `python p2_threat_model.py --input docker-compose.yml` |
| Dockerfile | `python p2_threat_model.py --input Dockerfile` |
| Interactive wizard | `python p2_threat_model.py --wizard` |

## Quick Start

```bash
git clone https://github.com/PyHackSecGP/p2-threat-model-generator
cd p2-threat-model-generator
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Run on sample e-commerce app
python p2_threat_model.py --input examples/webapp.yaml --output output/

# Skip LLM if Ollama is not running
python p2_threat_model.py --input examples/webapp.yaml --no-llm
```

Open `output/<app_name>_threat_model.html` in a browser.

## YAML Descriptor Format

```yaml
application:
  name: "My App"
  version: "1.0"
  environment: production
  internet_facing: true
  data_classification: confidential  # public | internal | confidential | restricted
  compliance_frameworks: [gdpr, pci_dss]

  components:
    - name: "API"
      type: api                # web_app | api | database | auth_service | cache | message_queue | storage | worker
      technology: "FastAPI"
      auth_type: jwt           # none | api_key | jwt | oauth2 | basic | mtls | session
      stores_pii: true
      internet_facing: true
      has_logging: true
      has_rate_limiting: false

  data_flows:
    - name: "Browser to API"
      source: Browser
      destination: API
      encrypted: true
      authenticated: true
      crosses_trust_boundary: true
      data_classification: confidential
      protocol: HTTPS
```

## Output

```
output/
  <app_name>_threat_model.html   ← self-contained HTML report (open in browser)
  <app_name>_threat_model.json   ← full threat data as JSON
```

## Report Sections

1. **Executive Summary** — overall risk score, top business risks, remediation timeline
2. **Risk Overview** — STRIDE distribution chart, severity breakdown, top 5 risk bar chart
3. **Sprint 1 Remediation** — immediate action table with effort estimates
4. **Compliance Exposure** — GDPR/PCI-DSS/SOC2/HIPAA violations mapped to threats
5. **Full Threat Inventory** — every threat with description, attack vector, business impact, mitigations, MITRE/OWASP/NIST references, LLM narrative

## LLM Configuration

Ollama endpoint: `http://100.126.22.55:11434` (on-prem, no data leaves network)
Model: `hermes3:70b`

```bash
# Disable LLM
python p2_threat_model.py --input app.yaml --no-llm

# Limit LLM to top 5 threats
python p2_threat_model.py --input app.yaml --llm-max 5
```

## Stack

- Python 3.11+
- PyYAML
- Requests (Ollama API)
- Chart.js (embedded in report, CDN)
