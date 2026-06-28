"""Parse Dockerfile / docker-compose.yml into ApplicationDescriptor."""
from __future__ import annotations
import re
import yaml
from pathlib import Path
from models import ApplicationDescriptor, AuthType, Component, ComponentType, DataFlow


_DB_IMAGES = {"postgres", "mysql", "mariadb", "mongo", "mongodb", "redis", "elasticsearch"}
_CACHE_IMAGES = {"redis", "memcached"}
_QUEUE_IMAGES = {"rabbitmq", "kafka", "nats"}
_PII_ENVS = {"database_url", "db_url", "secret_key", "jwt_secret", "password", "passwd",
             "api_key", "aws_secret", "stripe_key", "sendgrid_key"}


def _image_to_type(image: str) -> ComponentType:
    name = image.split(":")[0].lower().split("/")[-1]
    if name in _DB_IMAGES:
        return ComponentType.DATABASE
    if name in _CACHE_IMAGES:
        return ComponentType.CACHE
    if name in _QUEUE_IMAGES:
        return ComponentType.MESSAGE_QUEUE
    return ComponentType.WEB_APP


def _has_sensitive_env(env_vars: list | dict | None) -> bool:
    if not env_vars:
        return False
    keys: list[str] = []
    if isinstance(env_vars, dict):
        keys = list(env_vars.keys())
    elif isinstance(env_vars, list):
        keys = [e.split("=")[0] for e in env_vars if isinstance(e, str)]
    return any(k.lower() in _PII_ENVS for k in keys)


def parse_docker_compose(path: str) -> ApplicationDescriptor:
    p = Path(path)
    data: dict = yaml.safe_load(p.read_text())
    services: dict = data.get("services", {})
    app_name = p.parent.name or "Docker Application"

    components: list[Component] = []
    data_flows: list[DataFlow] = []
    stores_pii = False

    for svc_name, svc in services.items():
        image = svc.get("image", svc_name)
        ports = svc.get("ports", [])
        env = svc.get("environment", svc.get("env_file"))
        internet_facing = bool(ports)
        has_sensitive = _has_sensitive_env(env if isinstance(env, (list, dict)) else None)
        stores_creds = has_sensitive
        if has_sensitive:
            stores_pii = True

        ctype = _image_to_type(image)
        components.append(Component(
            name=svc_name,
            type=ctype,
            technology=image,
            internet_facing=internet_facing,
            stores_credentials=stores_creds,
            has_logging=False,  # unknown without compose logging config
            has_rate_limiting=False,
            notes=f"Ports: {ports}" if ports else "",
        ))

    # Add data flows from 'depends_on' and 'links'
    for svc_name, svc in services.items():
        depends = svc.get("depends_on", [])
        if isinstance(depends, dict):
            depends = list(depends.keys())
        for dep in depends:
            data_flows.append(DataFlow(
                name=f"{svc_name} → {dep}",
                source=svc_name,
                destination=dep,
                encrypted=False,  # docker internal networks are unencrypted by default
                authenticated=False,
                crosses_trust_boundary=False,
                protocol="TCP",
            ))

    return ApplicationDescriptor(
        name=app_name,
        description=f"Parsed from {p.name}",
        internet_facing=any(c.internet_facing for c in components),
        data_classification="confidential" if stores_pii else "internal",
        components=components,
        data_flows=data_flows,
        compliance_frameworks=["gdpr"] if stores_pii else [],
    )


def parse_dockerfile(path: str) -> ApplicationDescriptor:
    """Parse a single Dockerfile."""
    p = Path(path)
    content = p.read_text()
    app_name = p.parent.name or "Containerised App"

    expose_ports = re.findall(r"^EXPOSE\s+(\d+)", content, re.MULTILINE)
    env_vars = re.findall(r"^ENV\s+(\w+)", content, re.MULTILINE)
    has_sensitive = any(e.lower() in _PII_ENVS for e in env_vars)
    from_image = re.search(r"^FROM\s+(\S+)", content, re.MULTILINE)
    base_image = from_image.group(1) if from_image else "unknown"

    user_lines = re.findall(r"^USER\s+(\S+)", content, re.MULTILINE)
    runs_as_root = not user_lines or user_lines[-1] in ("root", "0")

    component = Component(
        name=app_name,
        type=_image_to_type(base_image),
        technology=base_image,
        internet_facing=bool(expose_ports),
        stores_credentials=has_sensitive,
        has_logging=False,
        notes=f"Runs as root: {runs_as_root}. Exposed ports: {expose_ports}",
    )

    return ApplicationDescriptor(
        name=app_name,
        description=f"Parsed from {p.name}. Base image: {base_image}",
        internet_facing=bool(expose_ports),
        data_classification="confidential" if has_sensitive else "internal",
        components=[component],
        compliance_frameworks=["gdpr"] if has_sensitive else [],
    )
