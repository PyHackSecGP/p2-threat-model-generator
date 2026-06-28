"""Parse YAML/JSON application descriptor into ApplicationDescriptor."""
from __future__ import annotations
import json
import yaml
from pathlib import Path
from models import (
    ApplicationDescriptor, AuthType, Component, ComponentType,
    DataFlow, TrustBoundary,
)


def _component_from_dict(d: dict) -> Component:
    return Component(
        name=d["name"],
        type=ComponentType(d.get("type", "generic")),
        description=d.get("description", ""),
        technology=d.get("technology", ""),
        auth_type=AuthType(d.get("auth_type", "none")),
        stores_pii=d.get("stores_pii", False),
        stores_credentials=d.get("stores_credentials", False),
        internet_facing=d.get("internet_facing", False),
        has_logging=d.get("has_logging", True),
        has_rate_limiting=d.get("has_rate_limiting", False),
        trust_boundary=d.get("trust_boundary", ""),
        notes=d.get("notes", ""),
    )


def _dataflow_from_dict(d: dict) -> DataFlow:
    return DataFlow(
        name=d["name"],
        source=d["source"],
        destination=d["destination"],
        data_classification=d.get("data_classification", "internal"),
        encrypted=d.get("encrypted", True),
        authenticated=d.get("authenticated", True),
        crosses_trust_boundary=d.get("crosses_trust_boundary", False),
        protocol=d.get("protocol", "HTTPS"),
        notes=d.get("notes", ""),
    )


def _boundary_from_dict(d: dict) -> TrustBoundary:
    return TrustBoundary(
        name=d["name"],
        components=d.get("components", []),
        description=d.get("description", ""),
    )


def parse_yaml(path: str) -> ApplicationDescriptor:
    """Parse a YAML or JSON file into ApplicationDescriptor."""
    p = Path(path)
    raw = p.read_text()
    data: dict = yaml.safe_load(raw) if p.suffix in (".yaml", ".yml") else json.loads(raw)

    app = data.get("application", data)
    return ApplicationDescriptor(
        name=app["name"],
        version=app.get("version", "1.0"),
        description=app.get("description", ""),
        owner=app.get("owner", ""),
        team=app.get("team", ""),
        environment=app.get("environment", "production"),
        internet_facing=app.get("internet_facing", True),
        data_classification=app.get("data_classification", "confidential"),
        components=[_component_from_dict(c) for c in app.get("components", [])],
        data_flows=[_dataflow_from_dict(f) for f in app.get("data_flows", [])],
        trust_boundaries=[_boundary_from_dict(b) for b in app.get("trust_boundaries", [])],
        compliance_frameworks=app.get("compliance_frameworks", []),
    )
