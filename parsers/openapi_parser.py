"""Parse OpenAPI 3.x / Swagger 2.x spec into ApplicationDescriptor."""
from __future__ import annotations
import json
import yaml
from pathlib import Path
from models import ApplicationDescriptor, AuthType, Component, ComponentType, DataFlow


def _detect_auth(security_schemes: dict) -> AuthType:
    if not security_schemes:
        return AuthType.NONE
    for scheme in security_schemes.values():
        t = scheme.get("type", "")
        if t == "oauth2":
            return AuthType.OAUTH2
        if t == "http" and scheme.get("scheme") == "bearer":
            return AuthType.JWT
        if t == "apiKey":
            return AuthType.API_KEY
        if t == "http" and scheme.get("scheme") == "basic":
            return AuthType.BASIC
        if t == "mutualTLS":
            return AuthType.MTLS
    return AuthType.NONE


def parse_openapi(path: str) -> ApplicationDescriptor:
    """Parse an OpenAPI/Swagger spec and extract security-relevant structure."""
    p = Path(path)
    raw = p.read_text()
    spec: dict = yaml.safe_load(raw) if p.suffix in (".yaml", ".yml") else json.loads(raw)

    # Support both OAS3 and Swagger 2
    is_oas3 = "openapi" in spec
    info = spec.get("info", {})
    app_name = info.get("title", p.stem)
    version = info.get("version", "1.0")

    # Base URL / host
    if is_oas3:
        servers = spec.get("servers", [{}])
        base_url = servers[0].get("url", "") if servers else ""
    else:
        base_url = f"{spec.get('host', ''}{spec.get('basePath', '')}"

    # Auth detection
    security_schemes = {}
    if is_oas3:
        security_schemes = spec.get("components", {}).get("securitySchemes", {})
    else:
        security_schemes = spec.get("securityDefinitions", {})
    auth_type = _detect_auth(security_schemes)

    # Detect PII exposure from response schemas
    pii_keywords = {"email", "phone", "ssn", "dob", "address", "password", "credit_card", "token"}
    response_bodies = json.dumps(spec).lower()
    stores_pii = any(kw in response_bodies for kw in pii_keywords)

    # Build one API component
    paths = spec.get("paths", {})
    internet_facing = True

    api_component = Component(
        name=f"{app_name} API",
        type=ComponentType.API,
        description=info.get("description", ""),
        technology=f"OpenAPI {spec.get('openapi', spec.get('swagger', '2.0'))}",
        auth_type=auth_type,
        stores_pii=stores_pii,
        internet_facing=internet_facing,
        has_logging=False,  # unknown from spec — flag as risky
        has_rate_limiting=False,  # unknown
        notes=f"{len(paths)} endpoints. Base: {base_url}",
    )

    # Build data flows for each unique tag group
    tags: set[str] = set()
    for path_item in paths.values():
        for op in path_item.values():
            if isinstance(op, dict):
                for tag in op.get("tags", ["default"]):
                    tags.add(tag)

    data_flows = [
        DataFlow(
            name=f"Client → {tag} endpoints",
            source="Client",
            destination=f"{app_name} API ({tag})",
            data_classification="confidential" if stores_pii else "internal",
            encrypted="https" in base_url.lower() or not base_url,
            authenticated=auth_type != AuthType.NONE,
            crosses_trust_boundary=True,
            protocol="HTTPS" if "https" in base_url.lower() else "HTTP",
        )
        for tag in (tags or {"default"})
    ]

    return ApplicationDescriptor(
        name=app_name,
        version=version,
        description=info.get("description", ""),
        internet_facing=True,
        data_classification="confidential" if stores_pii else "internal",
        components=[api_component],
        data_flows=data_flows,
        compliance_frameworks=["gdpr"] if stores_pii else [],
    )
