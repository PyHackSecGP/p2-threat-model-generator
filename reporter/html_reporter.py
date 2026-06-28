"""Generate self-contained HTML threat model report."""
from __future__ import annotations
import json
from pathlib import Path
from models import Severity, StrideCategory, ThreatModel

_SEVERITY_COLOR = {
    Severity.CRITICAL: "#ff4444",
    Severity.HIGH:     "#ff8800",
    Severity.MEDIUM:   "#ffcc00",
    Severity.LOW:      "#44bb44",
    Severity.INFO:     "#888888",
}

_SEVERITY_BG = {
    Severity.CRITICAL: "#2a0a0a",
    Severity.HIGH:     "#2a1500",
    Severity.MEDIUM:   "#2a2200",
    Severity.LOW:      "#0a1f0a",
    Severity.INFO:     "#1a1a1a",
}

_STRIDE_COLOR = {
    StrideCategory.SPOOFING:               "#ff6b9d",
    StrideCategory.TAMPERING:              "#ff8800",
    StrideCategory.REPUDIATION:            "#a78bfa",
    StrideCategory.INFO_DISCLOSURE:        "#38bdf8",
    StrideCategory.DENIAL_OF_SERVICE:      "#fb7185",
    StrideCategory.ELEVATION_OF_PRIVILEGE: "#34d399",
}


def _risk_bar(score: float) -> str:
    pct = min(100, score)
    color = "#ff4444" if pct >= 80 else "#ff8800" if pct >= 50 else "#ffcc00" if pct >= 25 else "#44bb44"
    return (
        f'<div class="risk-bar-wrap">'
        f'<div class="risk-bar-fill" style="width:{pct}%;background:{color}"></div>'
        f'<span class="risk-bar-label">{score:.0f}</span>'
        f'</div>'
    )


def _sprint_badge(priority: int) -> str:
    labels = {1: ("SPRINT 1", "#ff4444"), 2: ("Q1 BACKLOG", "#ff8800"), 3: ("BACKLOG", "#555")}
    label, color = labels.get(priority, ("BACKLOG", "#555"))
    return f'<span class="sprint-badge" style="background:{color}">{label}</span>'


def _severity_badge(severity: Severity) -> str:
    color = _SEVERITY_COLOR[severity]
    bg = _SEVERITY_BG[severity]
    return f'<span class="sev-badge" style="color:{color};background:{bg};border:1px solid {color}">{severity.value}</span>'


def _stride_chip(cat: StrideCategory) -> str:
    color = _STRIDE_COLOR[cat]
    return f'<span class="stride-chip" style="color:{color};border-color:{color}">{cat.value}</span>'


def _mitre_links(mappings: list) -> str:
    if not mappings:
        return '<span style="color:#555">—</span>'
    links = []
    for m in mappings:
        url = m.url or f"https://attack.mitre.org/techniques/{m.technique_id}/"
        links.append(f'<a href="{url}" target="_blank" class="mitre-link">{m.technique_id}</a>')
    return " ".join(links)


def _chart_js_data(tm: ThreatModel) -> str:
    stride_counts = tm.stride_counts
    stride_labels = json.dumps(list(stride_counts.keys()))
    stride_data = json.dumps(list(stride_counts.values()))
    stride_colors = json.dumps([_STRIDE_COLOR[StrideCategory(k)] for k in stride_counts.keys()])

    sev_counts = {
        "Critical": len(tm.critical_threats),
        "High": len(tm.high_threats),
        "Medium": len(tm.medium_threats),
        "Low": len(tm.low_threats),
    }
    sev_labels = json.dumps(list(sev_counts.keys()))
    sev_data = json.dumps(list(sev_counts.values()))
    sev_colors = json.dumps(["#ff4444", "#ff8800", "#ffcc00", "#44bb44"])

    top5 = sorted(tm.threats, key=lambda t: t.risk_score, reverse=True)[:5]
    top5_labels = json.dumps([t.title[:35] + "…" if len(t.title) > 35 else t.title for t in top5])
    top5_data = json.dumps([t.risk_score for t in top5])
    top5_colors = json.dumps([_SEVERITY_COLOR[t.severity] for t in top5])

    return f"""
    const strideCtx = document.getElementById('strideChart').getContext('2d');
    new Chart(strideCtx, {{
        type: 'doughnut',
        data: {{
            labels: {stride_labels},
            datasets: [{{ data: {stride_data}, backgroundColor: {stride_colors}, borderWidth: 2, borderColor: '#111' }}]
        }},
        options: {{
            responsive: true, maintainAspectRatio: false,
            plugins: {{
                legend: {{ labels: {{ color: '#ccc', font: {{ size: 11 }} }} }},
                tooltip: {{ callbacks: {{ label: ctx => ` ${{ctx.label}}: ${{ctx.raw}} threat(s)` }} }}
            }}
        }}
    }});

    const sevCtx = document.getElementById('sevChart').getContext('2d');
    new Chart(sevCtx, {{
        type: 'bar',
        data: {{
            labels: {sev_labels},
            datasets: [{{ data: {sev_data}, backgroundColor: {sev_colors}, borderRadius: 4 }}]
        }},
        options: {{
            responsive: true, maintainAspectRatio: false,
            plugins: {{ legend: {{ display: false }} }},
            scales: {{
                x: {{ ticks: {{ color: '#999' }}, grid: {{ color: '#222' }} }},
                y: {{ ticks: {{ color: '#999', stepSize: 1 }}, grid: {{ color: '#222' }}, beginAtZero: true }}
            }}
        }}
    }});

    const top5Ctx = document.getElementById('top5Chart').getContext('2d');
    new Chart(top5Ctx, {{
        type: 'bar',
        data: {{
            labels: {top5_labels},
            datasets: [{{ data: {top5_data}, backgroundColor: {top5_colors}, borderRadius: 4 }}]
        }},
        options: {{
            indexAxis: 'y',
            responsive: true, maintainAspectRatio: false,
            plugins: {{ legend: {{ display: false }} }},
            scales: {{
                x: {{ max: 100, ticks: {{ color: '#999' }}, grid: {{ color: '#222' }} }},
                y: {{ ticks: {{ color: '#ccc', font: {{ size: 11 }} }}, grid: {{ display: false }} }}
            }}
        }}
    }});
    """


def generate_html(tm: ThreatModel, output_path: str) -> None:
    app = tm.app
    total = len(tm.threats)
    crit = len(tm.critical_threats)
    high = len(tm.high_threats)
    med = len(tm.medium_threats)
    low = len(tm.low_threats)

    overall_color = "#ff4444" if tm.overall_risk_score >= 75 else "#ff8800" if tm.overall_risk_score >= 50 else "#ffcc00" if tm.overall_risk_score >= 25 else "#44bb44"
    overall_label = "CRITICAL" if tm.overall_risk_score >= 75 else "HIGH" if tm.overall_risk_score >= 50 else "MEDIUM" if tm.overall_risk_score >= 25 else "LOW"

    # Compliance section
    compliance_html = ""
    if tm.compliance_flags:
        rows = ""
        for flag in tm.compliance_flags:
            rows += f"""
            <tr>
                <td><span class="fw-badge">{flag.framework}</span></td>
                <td>{flag.requirement}</td>
                <td>{flag.description}</td>
                <td>{len(flag.threat_ids)} threat(s)</td>
            </tr>"""
        compliance_html = f"""
        <section class="section">
            <h2 class="section-title">⚖️ Compliance Exposure</h2>
            <table class="threat-table">
                <thead><tr><th>Framework</th><th>Requirement</th><th>Description</th><th>Affected</th></tr></thead>
                <tbody>{rows}</tbody>
            </table>
        </section>"""

    # Sprint 1 remediation table
    sprint1 = tm.sprint1_threats
    sprint1_rows = ""
    for t in sprint1:
        sprint1_rows += f"""
        <tr>
            <td style="font-family:monospace;color:#888;font-size:12px">{t.id}</td>
            <td>{t.title}</td>
            <td>{t.component}</td>
            <td>{_severity_badge(t.severity)}</td>
            <td><span class="effort-badge effort-{t.remediation_effort.lower()}">{t.remediation_effort}</span></td>
            <td style="font-size:12px;color:#aaa">{t.mitigations[0] if t.mitigations else '—'}</td>
        </tr>"""

    # Full threat table
    threat_rows = ""
    for t in tm.threats:
        mitigations_html = "".join(f"<li>{m}</li>" for m in t.mitigations)
        nist_ids = ", ".join(n.control_id for n in t.nist_controls) or "—"
        owasp_ids = ", ".join(o.category_id for o in t.owasp_mappings) or "—"

        narrative_html = ""
        if t.llm_narrative:
            narrative_html = f'<div class="llm-narrative">🤖 {t.llm_narrative}</div>'

        threat_rows += f"""
        <div class="threat-card" style="border-left:3px solid {_SEVERITY_COLOR[t.severity]}">
            <div class="threat-card-header">
                <div>
                    <span class="threat-id">{t.id}</span>
                    <span class="threat-title">{t.title}</span>
                </div>
                <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
                    {_severity_badge(t.severity)}
                    {_stride_chip(t.stride_category)}
                    {_sprint_badge(t.sprint_priority)}
                </div>
            </div>
            <div class="threat-meta">Component: <strong>{t.component}</strong> &nbsp;|&nbsp; Risk Score: <strong style="color:{_SEVERITY_COLOR[t.severity]}">{t.risk_score:.0f}/100</strong> &nbsp;|&nbsp; Likelihood: {t.likelihood}/5 &nbsp;|&nbsp; Impact: {t.impact}/5</div>
            {_risk_bar(t.risk_score)}
            <div class="threat-grid">
                <div>
                    <div class="field-label">Description</div>
                    <div class="field-val">{t.description}</div>
                    <div class="field-label" style="margin-top:12px">Attack Vector</div>
                    <div class="field-val">{t.attack_vector}</div>
                    <div class="field-label" style="margin-top:12px">Business Impact</div>
                    <div class="field-val impact-text">{t.business_impact}</div>
                </div>
                <div>
                    <div class="field-label">Mitigations</div>
                    <ul class="mitigation-list">{mitigations_html}</ul>
                    <div class="field-label" style="margin-top:12px">MITRE ATT&CK</div>
                    <div>{_mitre_links(t.mitre_mappings)}</div>
                    <div class="field-label" style="margin-top:8px">OWASP 2021</div>
                    <div style="font-size:12px;color:#aaa">{owasp_ids}</div>
                    <div class="field-label" style="margin-top:8px">NIST 800-53</div>
                    <div style="font-size:12px;color:#aaa">{nist_ids}</div>
                    <div class="field-label" style="margin-top:8px">Remediation Effort</div>
                    <span class="effort-badge effort-{t.remediation_effort.lower()}">{t.remediation_effort}</span>
                </div>
            </div>
            {narrative_html}
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Threat Model — {app.name}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  :root {{
    --bg: #0d0d0d; --bg2: #141414; --bg3: #1a1a1a;
    --text1: #f0f0f0; --text2: #b0b0b0; --text3: #666;
    --accent: #00ffb2; --border: #222; --font: 'Segoe UI', system-ui, sans-serif;
    --mono: 'JetBrains Mono', 'Fira Code', monospace;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text1); font-family: var(--font); font-size: 14px; line-height: 1.6; }}
  a {{ color: var(--accent); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}

  /* Header */
  .report-header {{ background: linear-gradient(135deg, #0a1a15 0%, #0d0d0d 60%); border-bottom: 1px solid var(--border); padding: 40px 48px; }}
  .report-header .label {{ font-family: var(--mono); font-size: 11px; color: var(--accent); letter-spacing: 2px; text-transform: uppercase; margin-bottom: 8px; }}
  .report-header h1 {{ font-size: 32px; font-weight: 700; margin-bottom: 4px; }}
  .report-header .meta {{ color: var(--text3); font-size: 13px; margin-top: 8px; }}
  .report-header .meta strong {{ color: var(--text2); }}

  /* Overall risk */
  .risk-hero {{ display: flex; align-items: center; gap: 24px; margin-top: 24px; padding: 20px 24px; background: var(--bg3); border-radius: 12px; border: 1px solid var(--border); max-width: 480px; }}
  .risk-score-big {{ font-size: 56px; font-weight: 800; line-height: 1; }}
  .risk-label {{ font-size: 11px; font-family: var(--mono); text-transform: uppercase; letter-spacing: 1px; color: var(--text3); margin-top: 4px; }}
  .risk-status {{ font-size: 18px; font-weight: 700; margin-bottom: 4px; }}

  /* Summary cards */
  .summary-cards {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; padding: 32px 48px; background: var(--bg2); border-bottom: 1px solid var(--border); }}
  .sum-card {{ background: var(--bg3); border: 1px solid var(--border); border-radius: 10px; padding: 20px; text-align: center; }}
  .sum-card .val {{ font-size: 36px; font-weight: 800; }}
  .sum-card .lbl {{ font-size: 12px; color: var(--text3); text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }}

  /* Sections */
  .section {{ padding: 40px 48px; border-bottom: 1px solid var(--border); }}
  .section-title {{ font-size: 20px; font-weight: 700; margin-bottom: 24px; color: var(--text1); }}

  /* Charts */
  .charts-grid {{ display: grid; grid-template-columns: 260px 1fr 1fr; gap: 24px; }}
  .chart-box {{ background: var(--bg3); border: 1px solid var(--border); border-radius: 10px; padding: 20px; }}
  .chart-box h3 {{ font-size: 13px; color: var(--text3); text-transform: uppercase; letter-spacing: 1px; margin-bottom: 16px; }}
  .chart-box canvas {{ height: 200px !important; }}

  /* Threat cards */
  .threat-card {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 10px; padding: 24px; margin-bottom: 16px; }}
  .threat-card-header {{ display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; margin-bottom: 12px; flex-wrap: wrap; }}
  .threat-id {{ font-family: var(--mono); font-size: 11px; color: var(--text3); margin-right: 10px; }}
  .threat-title {{ font-size: 16px; font-weight: 600; }}
  .threat-meta {{ font-size: 12px; color: var(--text3); margin-bottom: 10px; }}
  .threat-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-top: 16px; }}

  /* Risk bar */
  .risk-bar-wrap {{ background: #1e1e1e; border-radius: 4px; height: 6px; position: relative; margin: 8px 0 16px; }}
  .risk-bar-fill {{ height: 100%; border-radius: 4px; transition: width .3s; }}
  .risk-bar-label {{ position: absolute; right: 0; top: -18px; font-size: 11px; color: #888; font-family: var(--mono); }}

  /* Badges */
  .sev-badge {{ font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 4px; font-family: var(--mono); letter-spacing: .5px; }}
  .stride-chip {{ font-size: 11px; padding: 2px 8px; border-radius: 4px; border: 1px solid; background: transparent; }}
  .sprint-badge {{ font-size: 10px; font-weight: 700; padding: 2px 8px; border-radius: 4px; color: #fff; letter-spacing: .5px; font-family: var(--mono); }}
  .effort-badge {{ font-size: 11px; padding: 2px 8px; border-radius: 4px; font-weight: 600; }}
  .effort-low {{ background: #0a2a0a; color: #44bb44; border: 1px solid #44bb44; }}
  .effort-medium {{ background: #2a2200; color: #ffcc00; border: 1px solid #ffcc00; }}
  .effort-high {{ background: #2a0a0a; color: #ff4444; border: 1px solid #ff4444; }}
  .fw-badge {{ background: #1a1a2e; color: #a78bfa; border: 1px solid #a78bfa; font-size: 11px; padding: 2px 8px; border-radius: 4px; font-weight: 700; }}

  /* Fields */
  .field-label {{ font-size: 10px; text-transform: uppercase; letter-spacing: 1.5px; color: var(--text3); margin-bottom: 6px; }}
  .field-val {{ font-size: 13px; color: var(--text2); line-height: 1.6; }}
  .impact-text {{ color: #ffb347; font-size: 13px; }}
  .mitigation-list {{ list-style: none; padding: 0; }}
  .mitigation-list li {{ font-size: 12px; color: #aaa; padding: 3px 0 3px 16px; position: relative; line-height: 1.5; }}
  .mitigation-list li::before {{ content: "→"; position: absolute; left: 0; color: var(--accent); }}

  /* MITRE */
  .mitre-link {{ background: #0a1e14; border: 1px solid #00ffb240; color: var(--accent); padding: 1px 7px; border-radius: 4px; font-family: var(--mono); font-size: 11px; }}
  .mitre-link:hover {{ background: #00ffb220; }}

  /* LLM narrative */
  .llm-narrative {{ margin-top: 16px; padding: 14px 16px; background: #0f1f18; border: 1px solid #00ffb230; border-radius: 8px; font-size: 13px; color: #b0c9be; line-height: 1.7; font-style: italic; }}

  /* Sprint table */
  .threat-table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  .threat-table th {{ text-align: left; padding: 10px 12px; background: var(--bg3); color: var(--text3); font-size: 11px; text-transform: uppercase; letter-spacing: 1px; border-bottom: 1px solid var(--border); }}
  .threat-table td {{ padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; color: var(--text2); }}
  .threat-table tr:hover td {{ background: var(--bg3); }}

  /* Exec summary */
  .exec-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }}
  .exec-box {{ background: var(--bg3); border: 1px solid var(--border); border-radius: 10px; padding: 20px; }}
  .exec-box h3 {{ font-size: 13px; color: var(--text3); text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px; }}

  /* Footer */
  .report-footer {{ padding: 24px 48px; color: var(--text3); font-size: 12px; border-top: 1px solid var(--border); display: flex; justify-content: space-between; }}

  @media (max-width: 900px) {{
    .summary-cards {{ grid-template-columns: repeat(2,1fr); }}
    .charts-grid {{ grid-template-columns: 1fr; }}
    .threat-grid {{ grid-template-columns: 1fr; }}
    .exec-grid {{ grid-template-columns: 1fr; }}
    .section {{ padding: 24px 20px; }}
    .report-header {{ padding: 24px 20px; }}
  }}
</style>
</head>
<body>

<!-- ── HEADER ── -->
<div class="report-header">
  <div class="label">// threat model report</div>
  <h1>{app.name}</h1>
  <div class="meta">
    <strong>Version:</strong> {app.version} &nbsp;·&nbsp;
    <strong>Environment:</strong> {app.environment.title()} &nbsp;·&nbsp;
    <strong>Owner:</strong> {app.owner or 'N/A'} &nbsp;·&nbsp;
    <strong>Generated:</strong> {tm.generated_at} &nbsp;·&nbsp;
    <strong>Analyst:</strong> {tm.analyst}
  </div>
  <div class="meta" style="margin-top:6px">
    <strong>Data Classification:</strong> {app.data_classification.title()} &nbsp;·&nbsp;
    <strong>Internet-Facing:</strong> {'Yes' if app.internet_facing else 'No'} &nbsp;·&nbsp;
    <strong>Compliance:</strong> {', '.join(f.upper() for f in app.compliance_frameworks) or 'None specified'}
  </div>
  <div class="risk-hero">
    <div>
      <div class="risk-score-big" style="color:{overall_color}">{tm.overall_risk_score:.0f}</div>
      <div class="risk-label">Overall Risk Score / 100</div>
    </div>
    <div>
      <div class="risk-status" style="color:{overall_color}">{overall_label} RISK</div>
      <div style="color:var(--text3);font-size:12px">{total} threats identified across {len(app.components)} component(s)</div>
    </div>
  </div>
</div>

<!-- ── SUMMARY CARDS ── -->
<div class="summary-cards">
  <div class="sum-card"><div class="val" style="color:#ff4444">{crit}</div><div class="lbl">Critical</div></div>
  <div class="sum-card"><div class="val" style="color:#ff8800">{high}</div><div class="lbl">High</div></div>
  <div class="sum-card"><div class="val" style="color:#ffcc00">{med}</div><div class="lbl">Medium</div></div>
  <div class="sum-card"><div class="val" style="color:#44bb44">{low}</div><div class="lbl">Low / Info</div></div>
</div>

<!-- ── CHARTS ── -->
<section class="section">
  <h2 class="section-title">📊 Risk Overview</h2>
  <div class="charts-grid">
    <div class="chart-box">
      <h3>STRIDE Distribution</h3>
      <canvas id="strideChart"></canvas>
    </div>
    <div class="chart-box">
      <h3>Severity Breakdown</h3>
      <canvas id="sevChart"></canvas>
    </div>
    <div class="chart-box">
      <h3>Top 5 Threats by Risk Score</h3>
      <canvas id="top5Chart"></canvas>
    </div>
  </div>
</section>

<!-- ── EXECUTIVE SUMMARY ── -->
<section class="section" style="background:var(--bg2)">
  <h2 class="section-title">📋 Executive Summary</h2>
  <div class="exec-grid">
    <div class="exec-box">
      <h3>Key Findings</h3>
      <p style="color:var(--text2);font-size:13px;line-height:1.7">
        Threat model analysis of <strong>{app.name}</strong> identified <strong>{total} threats</strong>
        across {len(app.components)} system component(s).
        {'<span style="color:#ff4444"><strong>' + str(crit) + ' Critical threat(s)</strong></span> require immediate remediation before any production deployment or release. ' if crit > 0 else ''}
        {'<span style="color:#ff8800"><strong>' + str(high) + ' High threat(s)</strong></span> must be resolved within the current sprint. ' if high > 0 else ''}
        The overall application risk score is <strong style="color:{overall_color}">{tm.overall_risk_score:.0f}/100 ({overall_label})</strong>.
      </p>
    </div>
    <div class="exec-box">
      <h3>Top 3 Business Risks</h3>
      {"".join(f'<div style="margin-bottom:12px;padding-bottom:12px;border-bottom:1px solid var(--border)"><div style="font-size:13px;font-weight:600;color:var(--text1)">{t.title}</div><div style="font-size:12px;color:#ffb347;margin-top:3px">{t.business_impact[:140]}{"…" if len(t.business_impact) > 140 else ""}</div></div>' for t in sorted(tm.threats, key=lambda x: x.risk_score, reverse=True)[:3])}
    </div>
    <div class="exec-box">
      <h3>Remediation Timeline</h3>
      <div style="font-size:13px;color:var(--text2);line-height:1.8">
        🔴 <strong>Immediate (Sprint 1):</strong> {len(tm.sprint1_threats)} threat(s)<br>
        🟡 <strong>This Quarter:</strong> {len([t for t in tm.threats if t.sprint_priority == 2])} threat(s)<br>
        🟢 <strong>Backlog:</strong> {len([t for t in tm.threats if t.sprint_priority == 3])} threat(s)
      </div>
    </div>
    <div class="exec-box">
      <h3>STRIDE Coverage</h3>
      {"".join(f'<div style="display:flex;justify-content:space-between;font-size:12px;padding:3px 0"><span style="color:{_STRIDE_COLOR[StrideCategory(k)]}">{k}</span><span style="color:var(--text2)">{v} threat(s)</span></div>' for k, v in tm.stride_counts.items())}
    </div>
  </div>
</section>

<!-- ── SPRINT 1 TABLE ── -->
{f'''<section class="section">
  <h2 class="section-title">🔴 Immediate Remediation — Sprint 1 ({len(sprint1)} items)</h2>
  <table class="threat-table">
    <thead><tr><th>ID</th><th>Threat</th><th>Component</th><th>Severity</th><th>Effort</th><th>First Mitigation</th></tr></thead>
    <tbody>{sprint1_rows}</tbody>
  </table>
</section>''' if sprint1 else ''}

<!-- ── COMPLIANCE ── -->
{compliance_html}

<!-- ── ALL THREATS ── -->
<section class="section">
  <h2 class="section-title">🛡️ Full Threat Inventory ({total} threats)</h2>
  {threat_rows}
</section>

<!-- ── FOOTER ── -->
<div class="report-footer">
  <span>Generated by P2 Threat Model Generator · {tm.generated_at}</span>
  <span>Methodology: STRIDE · Frameworks: MITRE ATT&CK, OWASP 2021, NIST 800-53</span>
</div>

<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<script>
{_chart_js_data(tm)}
</script>
</body>
</html>"""

    Path(output_path).write_text(html, encoding="utf-8")
