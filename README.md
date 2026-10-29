# P2 — Threat Model Generator

**Turn the files developers already write (Dockerfiles, k8s manifests, OpenAPI, Terraform) into a scored STRIDE threat model with MITRE ATT&CK mappings, compliance flags, and a SARIF 2.1.0 export — in under two minutes, on every PR.**

![tests](https://img.shields.io/badge/tests-54%20passing-brightgreen) ![python](https://img.shields.io/badge/python-3.11%2B-blue) ![methodology](https://img.shields.io/badge/methodology-STRIDE-informational) ![output](https://img.shields.io/badge/output-SARIF%202.1.0-orange) ![llm](https://img.shields.io/badge/LLM-Ollama%20%7C%20Claude-purple)

---

## 60-Second Overview

**What is STRIDE?** A threat-modelling framework from Microsoft. For every component in your architecture, you check six categories:

- **S**poofing — can an attacker pretend to be someone they're not?
- **T**ampering — can data be modified in transit or at rest?
- **R**epudiation — can an action be denied with no audit trail?
- **I**nformation Disclosure — can secrets leak?
- **D**enial of Service — can the system be knocked over?
- **E**levation of Privilege — can a user gain more access than intended?

Historically STRIDE lives in a 2-hour whiteboard workshop that happens once a quarter — if at all.

**What this automates.** You point it at a config file your team already maintains (Dockerfile, `docker-compose.yml`, k8s manifests, OpenAPI spec, Terraform, or a short YAML descriptor). It:

1. Parses the file into a component graph with trust boundaries and data flows.
2. Runs a deterministic STRIDE rule engine (~30 rules) against each component.
3. Scores every threat `likelihood × impact × 4` on a 0–100 scale.
4. Attaches MITRE ATT&CK techniques, OWASP Top 10 refs, NIST 800-53 controls.
5. Flags findings against **GDPR, PCI-DSS, SOC 2, HIPAA**.
6. Optionally has an LLM (local Ollama by default, Claude optional) write executive narratives for the top-N findings.
7. Writes an HTML dashboard (Chart.js inlined, zero CDN calls), a JSON export, and a SARIF 2.1.0 file for GitHub Security / DefectDojo ingest.

**Who benefits.**
- **Developers**: get a threat model from a PR, not a meeting.
- **Security engineers**: a repeatable baseline instead of a bespoke workshop per app.
- **Compliance**: GDPR/PCI/SOC2/HIPAA mappings printed next to each finding, with a NIST 800-53 control cited.
- **Leadership**: an executive risk score that moves measurably as architecture changes.

---

## For Interviewers

### Problem Statement

Manual STRIDE workshops don't scale. They happen quarterly (if at all), require a security engineer in every meeting, produce inconsistent output per facilitator, and the artefacts rot the moment the architecture changes. By the time a diagram is drawn on a whiteboard, the real system has already moved on.

Meanwhile the inputs needed to *do* a threat model — the auth model, the data flows, the trust boundaries — are already present in files developers maintain daily: Dockerfiles, docker-compose, k8s manifests, OpenAPI specs, Terraform. Those files are the ground truth of the architecture.

**This tool reads that ground truth and emits a scored threat inventory every time it changes.** Threat modelling becomes a CI step, not a workshop. Same gating pattern as SAST or test failures, but for architectural risk posture.

### Skills Demonstrated

| Skill | Where it shows up |
|---|---|
| **Parser design** | 6 input-format parsers (`parsers/*.py`) feeding a single intermediate `ApplicationDescriptor` model — classic parser → IR → analyser separation |
| **Rule-engine architecture** | `engine/stride.py` — deterministic rules per component type, likelihood/impact boosts composed from component attributes |
| **STRIDE methodology** | All six STRIDE categories implemented with concrete, auditable triggers (not just labels) |
| **Compliance mapping** | GDPR, PCI-DSS, SOC 2, HIPAA framework flags computed from component attributes + data classifications |
| **Standards fluency** | OWASP Top 10 2021, NIST 800-53 controls, MITRE ATT&CK technique IDs attached to every finding |
| **SARIF spec** | SARIF 2.1.0 writer in `reporter/sarif_reporter.py` — the industry-standard format for GitHub Security / DefectDojo / vuln management ingest |
| **Agentic LLM** | `--agentic` mode uses an `agent-core` harness orchestrating 12 tools over Claude or Ollama to drive an interview-style descriptor build |
| **HCL / Terraform parsing** | `parsers/terraform_parser.py` — primary path uses `python-hcl2`, with a regex stdlib fallback so the module works without the dependency |
| **CI integration** | `.github/workflows/threat-model.yml` runs rule-only mode on PRs, uploads HTML + JSON + SARIF artefacts |
| **Testing** | 54 pytest cases across STRIDE rules, scorer, parsers, agent tools, sessions |

### Architecture

```
                       input files (ground truth of the architecture)
     ┌───────────────────────────────────────────────────────────────────┐
     │  Dockerfile   docker-compose.yml   k8s manifests   OpenAPI.yaml   │
     │  main.tf      descriptor.yaml      (or --agentic interview)       │
     └───────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
                     ┌─────────────────────────────┐
                     │  _detect_input_type()       │ sniff by filename, ext,
                     │  p2_threat_model.py L23-41  │ and first-1KB content
                     └─────────────────────────────┘
                                     │
                                     ▼
          ┌──────────────────────────────────────────────────────┐
          │  parser dispatch — one of:                           │
          │    parsers/yaml_parser.py                            │
          │    parsers/openapi_parser.py                         │
          │    parsers/docker_parser.py   (Dockerfile + compose) │
          │    parsers/k8s_parser.py                             │
          │    parsers/terraform_parser.py  (hcl2 or regex)      │
          └──────────────────────────────────────────────────────┘
                                     │
                                     ▼
                        ┌──────────────────────┐
                        │ ApplicationDescriptor│   components, data flows,
                        │   (models.py)        │   trust boundaries,
                        └──────────────────────┘   compliance frameworks
                                     │
                                     ▼
                       ┌──────────────────────────┐
                       │  engine/stride.py        │   per-component +
                       │  run_stride(app)         │   per-flow rules →
                       │  ~30 deterministic rules │   list[Threat]
                       └──────────────────────────┘
                                     │
                                     ▼
                       ┌──────────────────────────┐
                       │  engine/scorer.py        │   likelihood × impact
                       │  build_threat_model()    │   × 4; severity bucket;
                       │                          │   compliance flags
                       └──────────────────────────┘
                                     │
                                     ▼
                       ┌──────────────────────────┐
                       │  engine/llm.py           │   OPTIONAL — Ollama/
                       │  enrich_all(top_N)       │   Claude narrative for
                       │                          │   top-10 only
                       └──────────────────────────┘
                                     │
             ┌───────────────────────┼────────────────────────┐
             ▼                       ▼                        ▼
   ┌──────────────────┐   ┌───────────────────┐   ┌──────────────────────┐
   │ reporter/        │   │ reporter/         │   │ reporter/            │
   │ html_reporter.py │   │ json_reporter.py  │   │ sarif_reporter.py    │
   │ (Chart.js        │   │ (full export,     │   │ (SARIF 2.1.0 →       │
   │  inlined,        │   │  diff-friendly)   │   │  GitHub Security /   │
   │  no CDN)         │   │                   │   │  DefectDojo)         │
   └──────────────────┘   └───────────────────┘   └──────────────────────┘
```

Everything downstream of `ApplicationDescriptor` is parser-agnostic. Adding a new input format is one file in `parsers/`; the engine and reporters don't change.

### Design Decisions & Trade-offs

**Rule engine, not LLM-only.** LLMs hallucinate. A deterministic rule that fires "no auth on internet-facing component" every time is auditable, reproducible, and defensible in an audit. The LLM only *explains* machine-detected findings — it never decides whether one exists. Same split Snyk / Semgrep use when they bolt AI narratives onto deterministic engines.

**Ollama default, Claude optional.** Application descriptors contain architecture details, component names, data classifications. Sending that to a cloud LLM *is itself a finding* — you're disclosing system design to a third party. Local Ollama (configurable via `OLLAMA_HOST`) keeps everything on-prem. Claude is available for one-off runs where that trade-off is acceptable.

**SARIF 2.1.0 as the primary machine output.** SARIF is the ecosystem's lingua franca: GitHub Security tab, DefectDojo, Semgrep, CodeQL, most SAST vendors all speak it. Emitting SARIF means threat-model findings land in the same triage queue as SAST and dependency scans — one dashboard, one SLA, one review workflow.

**`python-hcl2` with a regex fallback.** Terraform's HCL is non-trivial to parse — nested dynamic blocks, locals, interpolations. `python-hcl2` handles it correctly. But forcing a C-extension dependency on every CI runner is friction. So the parser imports `hcl2` if present and falls back to a regex that covers the ~4 attributes our rules care about (`resource` blocks, `ingress.cidr_blocks`, `storage_encrypted`, `acl`). Tests pass on both paths. Marked with a `ponytail:` comment naming the upgrade path.

**LLM enriches top-N only.** Enriching 40 threats serially at ~8s per Ollama call is 5+ minutes. Executives read the top 10. Everyone else reads the JSON. Default `--llm-max 10`.

**Rule engine ships ~30 rules, not 300.** The rules are the ones with specific, defensible security rationales (CVE / breach / compliance precedents). More rules = more false positives = engineers ignore the output. Lazy wins over complete.

### Metrics / Scale

| Dimension | Count |
|---|---|
| Input formats | **6** (YAML descriptor, OpenAPI, Dockerfile, docker-compose, Kubernetes, Terraform/HCL) |
| STRIDE categories | **6** |
| STRIDE rules | **~30**, per-component-type + per-flow |
| MITRE ATT&CK techniques referenced | **19** |
| OWASP Top 10 2021 categories mapped | **10 / 10** |
| NIST 800-53 controls referenced | **13** |
| Compliance frameworks | **4** (GDPR, PCI-DSS, SOC 2, HIPAA) |
| Output formats | **3** (HTML with inline Chart.js, JSON, SARIF 2.1.0) |
| Tests (pytest) | **54** |
| Typical runtime | <2s rules-only; ~90s with LLM enrichment on 10 threats |

---

## Quick Start

```bash
git clone https://github.com/PyHackSecGP/p2-threat-model-generator.git
cd p2-threat-model-generator
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

Three one-liners against the bundled examples:

```bash
# YAML descriptor — the canonical e-commerce example
python p2_threat_model.py --input examples/webapp.yaml --no-llm

# Dockerfile — infer the component from a container image definition
echo -e 'FROM python:3.11\nEXPOSE 8080\nENV API_KEY=hunter2\nUSER root' > Dockerfile
python p2_threat_model.py --input Dockerfile --no-llm

# Terraform — intentionally misconfigured AWS stack
python p2_threat_model.py --input examples/terraform-aws.tf --no-llm \
    --sarif output/terraform.sarif
```

Reports land in `./output/` by default. Open the HTML file in a browser — the Chart.js dashboard is self-contained (no network).

---

## Supported Inputs

| Input | Auto-detect trigger | What's extracted | STRIDE rules that fire |
|---|---|---|---|
| **YAML descriptor** | `.yaml` / `.yml` / `.json` not matching OpenAPI or k8s | components, data flows, trust boundaries, compliance frameworks | All component-type rules + flow rules |
| **OpenAPI / Swagger** | `openapi:` or `swagger:` in first 1 KB | API component, auth scheme, PII in schemas, tag-based data flows | Spoofing (weak auth), Tampering (injection), Info Disclosure (verbose errors), DoS (missing rate limit), EoP (broken access control) |
| **Dockerfile** | filename `Dockerfile` | base image, `EXPOSE`, `ENV` secrets, `USER` directive | WEB_APP rules + secrets-in-env flag |
| **docker-compose** | filename `docker-compose.yml` / `compose.yml` | services, images, ports, env secrets, `depends_on` flows | Per-service rules; cross-service flows generate flow threats |
| **Kubernetes** | `kind: Deployment` / `kind: Service` / etc. in content | Deployments, Services, Ingress, NetworkPolicy, Secrets, Namespaces | Standard rules + k8s-specific: `privileged: true`, `runAsUser: 0`, missing probes, cross-boundary Ingress without TLS |
| **Terraform / HCL** | `.tf` extension or directory containing `.tf` | `resource`, `data`, `provider` blocks across AWS/GCP/Azure | Standard rules + Terraform-specific: public S3 (Info Disclosure), IAM `*` (Elevation of Privilege), unencrypted RDS (Info Disclosure), SG `0.0.0.0/0` ingress (Tampering) |
| **Agentic wizard** | `--agentic` flag | LLM-driven interview populates descriptor incrementally | All rules — same engine downstream |

Override with `--input-type` if the sniffer gets it wrong.

---

## Examples

### Example 1 — YAML descriptor (e-commerce platform)

Input (`examples/webapp.yaml`, excerpt):

```yaml
application:
  name: "E-Commerce Platform"
  internet_facing: true
  data_classification: confidential
  compliance_frameworks: [gdpr, pci_dss]

  components:
    - name: "PostgreSQL Database"
      type: database
      auth_type: basic
      stores_pii: true
      stores_credentials: true
      has_logging: false         # <-- triggers Repudiation finding
      trust_boundary: Internal
```

Run:

```bash
python p2_threat_model.py --input examples/webapp.yaml --no-llm
```

Sample finding (JSON, trimmed):

```json
{
  "id": "T006-03",
  "title": "Missing Audit Trail — PostgreSQL Database",
  "stride_category": "Repudiation",
  "severity": "High",
  "risk_score": 60.0,
  "likelihood": 3,
  "impact": 4,
  "component": "PostgreSQL Database",
  "description": "PostgreSQL Database does not log critical operations, allowing an attacker (or insider) to perform actions that cannot be attributed or reconstructed.",
  "business_impact": "Incident response is blind. Regulatory fines for inadequate audit trails (GDPR Art. 30, SOC2 CC7). Legal liability if breach cannot be scoped.",
  "mitre_mappings": [
    { "technique_id": "T1562", "name": "Impair Defenses" },
    { "technique_id": "T1070", "name": "Indicator Removal" }
  ],
  "owasp_mappings": [{ "id": "A09:2021", "name": "Security Logging and Monitoring Failures" }],
  "nist_controls": ["AU-2", "AU-9"],
  "mitigations": [
    "Implement structured logging (JSON) for all state-changing operations.",
    "Ship logs to centralised SIEM (Splunk/ELK) with tamper-evident storage.",
    "Include user ID, IP, timestamp, action, and resource in every log event.",
    "Set log retention minimum 90 days hot, 1 year cold."
  ]
}
```

### Example 2 — Dockerfile with a secret in `ENV`

Input (`Dockerfile`):

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
ENV DATABASE_PASSWORD=super-secret-prod-password
ENV API_KEY=sk_live_abc123
EXPOSE 8080
USER root
CMD ["python", "app.py"]
```

Run:

```bash
python p2_threat_model.py --input Dockerfile --no-llm
```

Sample finding (console summary):

```
── Top 5 Threats ──────────────────────────────
  [Critical] ████████░░  80.0  Identity Spoofing — app
  [High    ] ███████░░░  70.0  Secrets in Environment Variables — app
  [High    ] ██████░░░░  60.0  Injection Attack — app
  [High    ] █████░░░░░  50.0  Container Running as Root — app
  [Medium  ] ████░░░░░░  40.0  Application-Layer DoS — app
```

The `ENV DATABASE_PASSWORD=...` and `ENV API_KEY=...` lines fire the secrets-in-env rule, which maps to **MITRE T1552.001 (Unsecured Credentials: Credentials in Files)**, **OWASP A05:2021 (Security Misconfiguration)**, and **NIST IA-5 (Authenticator Management)**. `USER root` escalates the container-escape posture.

### Example 3 — Terraform (intentionally misconfigured AWS)

Input (`examples/terraform-aws.tf`, excerpt — real intentional misconfigs):

```hcl
provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "public_assets" {
  bucket = "example-public-assets"
  acl    = "public-read"                       # <-- public S3 bucket
}

resource "aws_iam_policy" "full_access" {
  name   = "example-full-access"
  policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"
                                                # <-- IAM wildcard
}

resource "aws_db_instance" "legacy" {
  identifier        = "example-legacy-db"
  engine            = "postgres"
  storage_encrypted = false                     # <-- unencrypted RDS
}

resource "aws_security_group" "web_open" {
  name = "example-web-open"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]                 # <-- SSH open to world
  }
}
```

Run:

```bash
python p2_threat_model.py --input examples/terraform-aws.tf --no-llm \
    --sarif output/terraform.sarif
```

Sample Terraform-specific finding (SARIF, trimmed):

```json
{
  "ruleId": "TF-S3-PUBLIC-READ",
  "level": "error",
  "message": {
    "text": "S3 bucket 'example-public-assets' has acl=public-read. Any object placed in this bucket is readable by the entire internet."
  },
  "locations": [{
    "physicalLocation": {
      "artifactLocation": { "uri": "examples/terraform-aws.tf" },
      "region": { "startLine": 12 }
    }
  }],
  "properties": {
    "stride": "Information Disclosure",
    "severity": "Critical",
    "risk_score": 90,
    "mitre": ["T1530"],
    "owasp": ["A01:2021"],
    "nist_controls": ["AC-6", "SC-28"],
    "compliance": ["GDPR Art. 32", "PCI-DSS 3.4"]
  }
}
```

Drop that SARIF into the GitHub Security tab and the finding appears next to CodeQL and Dependabot alerts, in the same triage queue.

---

## Technical Reference

### Install / Dependencies

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

- **Required**: PyYAML, Jinja2 (HTML templating)
- **Optional**: `python-hcl2` for proper Terraform parsing. The Terraform parser falls back to a regex-based reader if `hcl2` is not installed — tests pass on both paths.
- **Optional**: `anthropic` (for `--provider claude` in agentic mode)
- **Runtime**: Python 3.11+ (uses `|` type unions and `tomllib` idioms)

### CLI

```
python p2_threat_model.py [--input FILE | --wizard | --agentic] [options]

  --input, -i FILE          Input descriptor / config file
  --input-type TYPE         Override auto-detect: yaml | openapi | docker_compose
                            | dockerfile | k8s | terraform
  --output, -o DIR          Output directory (default: ./output)
  --wizard                  Scripted interactive wizard (deterministic Q&A)
  --agentic                 LLM-driven interview using agent-core
  --provider PROVIDER       claude | ollama (agentic only; default: $AGENT_PROVIDER or ollama)
  --describe TEXT           Seed description for the agent
  --describe-file FILE      Read seed description from a file
  --no-llm                  Skip LLM narrative generation (fast, deterministic)
  --llm-max N               Max threats to enrich with LLM narratives (default: 10)
  --sarif FILE              Also write a SARIF 2.1.0 report to FILE
```

### Output Formats

| Format | File | Audience | Notes |
|---|---|---|---|
| **HTML** | `output/<app>_threat_model.html` | humans | Chart.js inlined — no CDN, no network calls, opens offline |
| **JSON** | `output/<app>_threat_model.json` | tools, diffing | Full threat inventory; stable keys; diff two runs to review architecture-change risk |
| **SARIF 2.1.0** | wherever `--sarif FILE` points | GitHub Security / DefectDojo / vuln management | SARIF rules, locations with file+line where available (Terraform), severity levels per spec |

### LLM Configuration

**Ollama (default, on-prem)**

```bash
export OLLAMA_HOST="http://localhost:11434"   # default
export THREAT_MODEL="llama3.1"                # override model
python p2_threat_model.py --input app.yaml --llm-max 10
```

**Claude (agentic mode only)**

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
python p2_threat_model.py --agentic --provider claude \
    --describe "FastAPI backend with Postgres and public login"
```

Narrative generation is additive — the deterministic rule engine always runs first. `--no-llm` is a hard bypass for CI (fast, zero network).

### Agentic Mode

The scripted flow assumes a machine-readable config exists. Real threat-modelling conversations start on a whiteboard with a developer describing what the system *is*. The agentic wizard replaces the scripted `parsers/wizard.py` with an LLM orchestrating 12 tools:

| Tool | Purpose |
|---|---|
| `ask_user` | Ask the user one question; read answer from stdin |
| `start_app` | Initialise the `ApplicationDescriptor` |
| `set_compliance` | Attach GDPR / PCI / SOC 2 / HIPAA flags |
| `add_component` / `add_data_flow` | Build the model incrementally |
| `list_components` / `list_flows` / `get_app` | Inspection so the agent can review its own progress |
| `run_stride_analysis` | Same STRIDE engine as the scripted path |
| `enrich_threats` | Optional Ollama narrative pass |
| `score_threats` | Same scorer + compliance mapping |
| `generate_report` | Same JSON + HTML + SARIF reporters |

The engine, scorer, and reporters are **shared** between scripted and agentic paths — the agentic layer is purely a different way to populate the descriptor.

### Testing

```bash
pytest -q
```

**54 tests** across six files:

- `tests/test_stride_and_scoring.py` — STRIDE rule firing + scorer bucketing
- `tests/test_terraform_parser.py` — HCL + regex fallback paths
- `tests/test_agent_tools.py` — each agentic tool in isolation
- `tests/test_threat_model_agent.py` — end-to-end agent run
- `tests/test_agent_smoke.py` — minimum-happy-path smoke
- `tests/test_session.py` — session persistence

### Extending

**Add a new input parser.**

1. Create `parsers/myformat_parser.py` exporting `parse_myformat(path) -> ApplicationDescriptor`.
2. Add an auto-detect clause in `_detect_input_type()` in `p2_threat_model.py`.
3. Add a dispatch clause in `_load_app()`.
4. Add a test in `tests/`.
No engine or reporter changes needed — the descriptor IR isolates them.

**Add a new STRIDE rule.**

1. Edit `engine/stride.py`. Add a block to `generate_component_threats()` or `generate_dataflow_threats()` gated on the trigger attribute.
2. Attach MITRE / OWASP / NIST mappings from the existing constants (`MITRE`, `OWASP`, `NIST`) at the top of the file.
3. Keep `likelihood` and `impact` on a 1–5 scale; the scorer multiplies by 4.

**Add a new compliance framework.**

1. Add the framework constant in `models.py`.
2. Add mapping logic in `engine/scorer.py` — which (STRIDE category, component attribute) tuples trigger a flag for the framework.
3. Add it to the enum in the YAML descriptor so users can declare they're subject to it.

---

## Why This Was Built

Threat modelling has the same problem SAST and DAST had 10 years ago: it's a workshop activity gated by human availability. The industry solved that for SAST (Semgrep, CodeQL in CI), for dependencies (Dependabot, Snyk), and for secrets (truffleHog, GitHub secret scanning). Threat modelling is the last one still stuck in a conference room.

This project is the lazy senior's answer: the inputs you need to produce a threat model already exist as code. Parse them. Run deterministic STRIDE rules. Emit SARIF so the finding joins the existing triage queue. Ship it on every PR instead of every quarter.

**Career angle**: this is the project I built to understand what IriusRisk / ThreatModeler / Microsoft Threat Modeling Tool are doing under the hood — not to replace them. Before I can evaluate a $50k/year commercial tool or extend its rule sets, I need to know how the engine, scorer, and compliance mapping actually work. Building it means I can sit next to any commercial tool in an audit and defend every finding — my own or theirs.

---

## FAQ

**Q: Why not just let an LLM generate the threats?**
LLMs hallucinate. A rule engine that fires "no auth on internet-facing component" every time is auditable and defensible. The LLM only writes narratives for machine-detected findings. Deterministic engines detect; LLMs explain. Same split Snyk, Semgrep, and the commercial threat-modelling tools adopt when they add AI features.

**Q: Why Ollama local instead of a cloud LLM?**
Descriptors contain architecture details and component names. Sending that to a third-party API is itself a finding — you're disclosing system design. Local Ollama keeps it on-prem.

**Q: What does the risk score mean?**
`risk_score = likelihood × impact × 4`, with likelihood and impact each on a 1–5 scale, giving a 0–100 bucket. Critical: 80–100. High: 50–79. Medium: 25–49. Low: 0–24. The ×4 is a scaling factor to spread scores across the full 0–100 range so the dashboard renders cleanly.

**Q: Why MITRE ATT&CK and not just OWASP?**
OWASP tells you the vulnerability class. MITRE ATT&CK tells you the technique an attacker uses. If the threat model flags T1078 (Valid Accounts), the detection team can go verify they have a SIEM rule for it. ATT&CK is the shared vocabulary between threat modelling and detection engineering.

**Q: Does it support something other than STRIDE (PASTA, LINDDUN, VAST)?**
Not currently. STRIDE is the most widely adopted and maps cleanly to a rule engine. LINDDUN (privacy-focused) is a plausible second methodology — would reuse the same descriptor IR, add rules in `engine/linddun.py`, same reporters.

**Q: What happens if `python-hcl2` isn't installed?**
The Terraform parser logs that it's using the regex fallback. The fallback covers the ~4 attributes our rules care about (`resource` blocks, `ingress.cidr_blocks`, `storage_encrypted`, `acl`). All 54 tests pass on both paths. Install `python-hcl2` for configs with dynamic blocks, locals, or modules.

**Q: How do I gate CI on risk score?**
The JSON output includes `overall_risk_score`. In `.github/workflows/threat-model.yml`, parse that value and fail the job above a threshold:

```yaml
- run: |
    score=$(jq '.overall_risk_score' output/*.json)
    if (( $(echo "$score > 75" | bc -l) )); then
      echo "::error::Threat model score $score exceeds threshold 75"
      exit 1
    fi
```

**Q: Why SARIF instead of a custom format?**
SARIF is the ecosystem lingua franca — GitHub Security, DefectDojo, Semgrep, CodeQL, most SAST vendors all speak it. Emit SARIF and the finding joins the existing triage queue instead of inventing a new one.

---

## License / Credits

MIT. See `LICENSE`.

**Methodology credits.** STRIDE: Microsoft (Loren Kohnfelder & Praerit Garg, 1999). MITRE ATT&CK: MITRE Corporation. OWASP Top 10: OWASP Foundation (2021 edition). NIST 800-53: NIST. SARIF 2.1.0: OASIS.

**Built on.** Python 3.11+, PyYAML, Jinja2, `python-hcl2` (optional), Ollama (optional), Anthropic SDK (optional, agentic mode).

**Author.** GP Singh — [github.com/PyHackSecGP](https://github.com/PyHackSecGP). Part of the P-series security engineering portfolio (P1 SAST/DAST triage, **P2 threat model generator**, P3 log anomaly detection, P4 pentest report assistant, P5 ATLAS autonomous HTB).
