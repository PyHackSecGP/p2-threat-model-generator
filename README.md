# P2 — Threat Model Generator: Interview Prep Notes

---

## 30-Second Pitch (memorise this)

"I built a threat modelling tool that reads files developers already write — docker-compose, Kubernetes manifests, OpenAPI specs — and produces a scored threat inventory with MITRE ATT&CK mappings, compliance flags, and AI-generated remediation suggestions. The whole thing runs in 2 minutes and integrates into a CI pipeline so threat modelling happens on every PR instead of in a quarterly workshop."

---

## Q: Why did you build this instead of using IriusRisk / ThreatModeler / Microsoft TMT?

Those tools exist and I've looked at them. I built this to understand what they're doing under the hood — not to replace them. Before I can configure one, evaluate whether it's worth the $50k/year, or extend its rule sets, I need to know how a threat modelling engine actually works.

Specifically I needed to answer:
- How do you translate "this component stores PII" into a specific, scored threat?
- What component attributes actually drive each STRIDE category?
- How does MITRE ATT&CK connect to threat modelling vs. detection engineering?
- What does a GDPR compliance flag mean at architecture level, and which NIST 800-53 control addresses it?

Building it forced me to answer all of those. Now I can sit next to a commercial tool and understand every finding it produces.

---

## Q: What is STRIDE? Walk me through it.

STRIDE is a threat modelling framework. Each letter is a threat category:

| Letter | Threat | What it means |
|---|---|---|
| S | Spoofing | Attacker pretends to be someone they're not |
| T | Tampering | Attacker modifies data in transit or at rest |
| R | Repudiation | User denies doing something, no audit trail to prove otherwise |
| I | Information Disclosure | Data exposed that shouldn't be |
| D | Denial of Service | System made unavailable |
| E | Elevation of Privilege | User gains more access than they should have |

In the engine, I evaluate every component against every category. The triggers come from component attributes — if a component is internet-facing with no auth, that fires Spoofing. If a data flow crosses a trust boundary without encryption, that fires Information Disclosure.

---

## Q: How does the risk scoring work?

```
risk_score = likelihood × impact × 4
```

Likelihood and impact are both 1-5. Max score is 100.

- Critical: 80-100
- High: 50-79
- Medium: 25-49
- Low: 0-24

Likelihood factors: is it internet-facing? does it have no auth? does it store sensitive data?  
Impact factors: PII involved? payment data? core infrastructure?

The `× 4` is a scaling factor to spread scores across the full 0-100 range.

---

## Q: How does MITRE ATT&CK fit into this?

ATT&CK is the taxonomy. Every threat generated gets mapped to a technique ID — for example:
- No auth on internet-facing component → T1078 (Valid Accounts)
- No rate limiting → T1499 (Endpoint Denial of Service)
- Secrets in env vars → T1552.001 (Unsecured Credentials: Credentials in Files)

The reason: threat modelling findings should connect directly to what detection engineers are writing rules for. If the threat model says T1078 is a risk, the detection team can verify they have coverage for it.

---

## Q: How does the Kubernetes parser work? What was hard about it?

K8s manifests are multi-document YAML. The parser reads all of them and builds the application model:

- `Deployment` / `StatefulSet` → Component with attributes inferred from container spec
- `Service` type `LoadBalancer` or `NodePort` → marks the workload as internet-facing
- `Ingress` → creates data flows from Internet to backend, checks for TLS
- `Secret` → flags the workload as storing credentials, triggers GDPR flag
- `NetworkPolicy` → creates a trust boundary

The hard part: the relationship between objects. A `LoadBalancer` Service makes a `Deployment` internet-facing — but you only know that if you cross-reference the Service's `selector` labels against the Deployment's `labels`. Had to parse all documents first, then resolve relationships in a second pass.

Also: K8s-specific risks like `privileged: true` and `runAsUser: 0` are effectively container escape pre-conditions. Those needed specific detection logic separate from the standard STRIDE rules.

---

## Q: Why does the LLM only enrich the top N threats?

Two reasons:

1. **Speed** — each Ollama call takes ~8 seconds. For a 40-threat report, enriching all of them takes 5+ minutes. Top 10 is enough for executive communication.

2. **Value** — executives and developers need to understand the *top* findings in plain language. The bottom 30 are tracked in JSON for completeness; they don't need narrative.

---

## Q: Why local Ollama instead of a cloud LLM?

Application descriptors contain architecture details, component names, data classifications. Sending that to OpenAI or Anthropic is itself a finding — you're disclosing your system design to a third party. On-prem Ollama on the homelab keeps all data on the network.

Same reason commercial tools with "AI narratives" often let you bring your own LLM endpoint.

---

## Q: Why not let the LLM generate the threats?

LLMs hallucinate. A rule-based STRIDE engine will correctly flag "no auth on internet-facing component" every time — deterministic, reproducible, auditable. The LLM adds *explanation quality* to machine-detected findings. It doesn't replace the detection logic.

This is the right split: deterministic engines detect, LLMs explain. Same pattern used by Snyk, Semgrep, and the commercial threat modelling tools when they add AI features.

---

## Q: How does it integrate into CI?

GitHub Actions workflow (`.github/workflows/threat-model.yml`):
- Triggers on PRs that touch application config files
- Runs the rule engine (no LLM — fast, no external deps)
- Uploads HTML + JSON as build artifacts
- Posts risk score + severity counts as a PR comment

Teams can gate PRs on risk score threshold. Same as gating on test failures, but for security posture.

---

## Key technical facts to have ready

- **Input formats**: YAML descriptor, OpenAPI/Swagger, Dockerfile, docker-compose, Kubernetes manifests — auto-detected
- **STRIDE categories**: 6 — Spoofing, Tampering, Repudiation, Information Disclosure, DoS, Elevation of Privilege
- **Compliance frameworks checked**: GDPR, PCI-DSS, SOC2, HIPAA
- **Standards referenced**: OWASP Top 10 2021, NIST 800-53
- **LLM**: Ollama (local), model configurable via `THREAT_MODEL` env var, `OLLAMA_HOST` for endpoint
- **Output**: self-contained HTML (Chart.js, no CDN calls), JSON export
- **Commercial equivalents**: IriusRisk, ThreatModeler, Microsoft Threat Modeling Tool, OWASP Threat Dragon

---

## Q: You mentioned an agentic mode — what's the difference from the scripted pipeline?

The scripted flow assumes I have a machine-readable input file — docker-compose, OpenAPI, k8s manifests. Real threat-modelling conversations don't start with those files. They start with a whiteboard and a developer explaining what the system is.

The agentic mode replaces the scripted `parsers/wizard.py` with an LLM-driven interviewer. Under the hood it's `agent-core` — a small Anthropic/Ollama harness — orchestrating 12 tools:

| Tool | Purpose |
|---|---|
| `ask_user` | Ask the user one question and read the answer from stdin |
| `start_app` | Initialise the `ApplicationDescriptor` |
| `set_compliance` | Attach GDPR/PCI/SOC2/HIPAA flags |
| `add_component` / `add_data_flow` | Build up the model incrementally |
| `list_components` / `list_flows` / `get_app` | Inspection so the agent can review its own progress |
| `run_stride_analysis` | Same STRIDE engine as the scripted path |
| `enrich_threats` | Optional Ollama narrative pass |
| `score_threats` | Same scorer + compliance mapping |
| `generate_report` | Same JSON + HTML reporters |

The engine, scorer, and reporters are shared between both modes — the agentic layer is purely a different way of *populating* the descriptor.

**Why bother:** it lets a non-security-engineer answer plain questions ("what does the service store?") and get a scored threat model without ever touching YAML. It also lets me test how well a general-purpose LLM can drive a domain-specific STRIDE workflow when the reasoning is offloaded to deterministic tools.

Run it:

```bash
# Interactive Claude interview
python p2_threat_model.py --agentic --provider claude

# Seeded with a description
python p2_threat_model.py --agentic --provider claude \
    --describe "FastAPI backend, Postgres, public login endpoint, stores PII"

# From a file
python p2_threat_model.py --agentic --describe-file architecture.md
```

Reports land in `./output/` (or whatever `--output` you pass).

---

## Q: What would you improve or add next?

- **Terraform / HCL parser** — model cloud infrastructure (IAM policies, S3 bucket ACLs, security groups) — this is where most real cloud risk lives
- **DefectDojo push** — send findings via API directly to vuln management so they get triaged and tracked with SLAs
- **SARIF output** — import into GitHub Security tab alongside SAST findings
- **Diff mode** — compare two threat models and show what changed between versions — useful for PR reviews of architecture changes

---

## What I'd say if asked "what was the hardest part?"

Operationalising STRIDE. The framework sounds simple — six categories, apply to each component. But the hard part is deciding *what specific attributes* of a component trigger each threat category, and at what severity. That required reading through real vulnerability databases and CVEs to calibrate what "likely" and "high impact" actually mean for each combination of component type, auth type, and exposure. The rule engine has ~30 rules, each one backed by a specific security rationale.
