#!/usr/bin/env python3
"""
P2 — Threat Model Generator
Generates STRIDE-based threat models with risk scoring, MITRE ATT&CK mapping,
compliance flagging, and an executive-quality HTML report.
"""
from __future__ import annotations
import argparse
import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from engine.stride import run_stride
from engine.scorer import build_threat_model
from engine.llm import enrich_all, is_ollama_available
from reporter.html_reporter import generate_html
from reporter.json_reporter import generate_json


def _detect_input_type(path: str) -> str:
    p = Path(path)
    name = p.name.lower()
    if name in ("dockerfile",):
        return "dockerfile"
    if name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
        return "docker_compose"
    suffix = p.suffix.lower()
    if suffix in (".yaml", ".yml", ".json"):
        content = p.read_text()[:512].lower()
        if "openapi" in content or "swagger" in content:
            return "openapi"
        return "yaml"
    return "yaml"


def _load_app(args):
    if args.wizard:
        from parsers.wizard import run_wizard
        return run_wizard()

    if not args.input:
        print("Error: provide --input <file> or use --wizard", file=sys.stderr)
        sys.exit(1)

    itype = args.input_type or _detect_input_type(args.input)
    print(f"[*] Detected input type: {itype}")

    if itype == "yaml":
        from parsers.yaml_parser import parse_yaml
        return parse_yaml(args.input)
    elif itype == "openapi":
        from parsers.openapi_parser import parse_openapi
        return parse_openapi(args.input)
    elif itype == "docker_compose":
        from parsers.docker_parser import parse_docker_compose
        return parse_docker_compose(args.input)
    elif itype == "dockerfile":
        from parsers.docker_parser import parse_dockerfile
        return parse_dockerfile(args.input)
    else:
        print(f"Error: unknown input type '{itype}'", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="P2 — Threat Model Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Input types (auto-detected):
  YAML/JSON descriptor   python p2_threat_model.py --input app.yaml
  OpenAPI / Swagger      python p2_threat_model.py --input openapi.yaml
  docker-compose.yml     python p2_threat_model.py --input docker-compose.yml
  Dockerfile             python p2_threat_model.py --input Dockerfile
  Interactive wizard     python p2_threat_model.py --wizard

Examples:
  python p2_threat_model.py --input examples/webapp.yaml --output output/
  python p2_threat_model.py --input openapi.json --no-llm
  python p2_threat_model.py --wizard --output ./reports/
        """,
    )
    parser.add_argument("--input", "-i", help="Input file path")
    parser.add_argument("--input-type", choices=["yaml", "openapi", "docker_compose", "dockerfile"],
                        help="Override auto-detection of input type")
    parser.add_argument("--output", "-o", default="output", help="Output directory (default: ./output)")
    parser.add_argument("--wizard", action="store_true", help="Run interactive wizard instead of file input")
    parser.add_argument("--no-llm", action="store_true", help="Skip LLM narrative generation")
    parser.add_argument("--llm-max", type=int, default=10, help="Max threats to enrich with LLM (default: 10)")
    args = parser.parse_args()

    # Load application descriptor
    print("[*] Loading application descriptor...")
    app = _load_app(args)
    print(f"[+] Application: {app.name} | Components: {len(app.components)} | Data flows: {len(app.data_flows)}")

    # Run STRIDE engine
    print("[*] Running STRIDE analysis...")
    threats = run_stride(app)
    print(f"[+] Generated {len(threats)} threats")

    # LLM enrichment
    if not args.no_llm:
        if is_ollama_available():
            print(f"[*] Enriching top {args.llm_max} threats with LLM narratives (Ollama on-prem)...")
            enrich_all(threats, max_threats=args.llm_max)
            enriched = sum(1 for t in threats if t.llm_narrative)
            print(f"[+] {enriched} threats enriched with LLM narratives")
        else:
            print("[!] Ollama not reachable — skipping LLM enrichment (use --no-llm to suppress this)")

    # Build threat model + compliance
    print("[*] Computing risk scores and compliance flags...")
    tm = build_threat_model(app, threats)
    print(f"[+] Overall risk score: {tm.overall_risk_score:.0f}/100")
    print(f"[+] Critical: {len(tm.critical_threats)} | High: {len(tm.high_threats)} | "
          f"Medium: {len(tm.medium_threats)} | Low: {len(tm.low_threats)}")
    if tm.compliance_flags:
        frameworks = set(f.framework for f in tm.compliance_flags)
        print(f"[+] Compliance flags: {', '.join(frameworks)}")

    # Write outputs
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    safe_name = app.name.lower().replace(" ", "_").replace("/", "_")
    html_path = out_dir / f"{safe_name}_threat_model.html"
    json_path = out_dir / f"{safe_name}_threat_model.json"

    print(f"[*] Writing HTML report → {html_path}")
    generate_html(tm, str(html_path))

    print(f"[*] Writing JSON export → {json_path}")
    generate_json(tm, str(json_path))

    print(f"\n[✓] Done.")
    print(f"    HTML report : {html_path.resolve()}")
    print(f"    JSON export : {json_path.resolve()}")

    # Print top threats summary
    print(f"\n── Top 5 Threats ──────────────────────────────")
    for t in sorted(tm.threats, key=lambda x: x.risk_score, reverse=True)[:5]:
        bar = "█" * int(t.risk_score / 10) + "░" * (10 - int(t.risk_score / 10))
        print(f"  [{t.severity.value:8}] {bar} {t.risk_score:5.1f}  {t.title}")


if __name__ == "__main__":
    main()
