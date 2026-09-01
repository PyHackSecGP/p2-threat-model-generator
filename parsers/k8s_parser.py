"""Parse Kubernetes manifests (Deployment, Service, Ingress, etc.) into ApplicationDescriptor."""
from __future__ import annotations
import yaml
from pathlib import Path
from models import ApplicationDescriptor, AuthType, Component, ComponentType, DataFlow, TrustBoundary

_DB_IMAGES = {"postgres", "mysql", "mariadb", "mongo", "mongodb", "redis",
              "elasticsearch", "cassandra", "cockroachdb", "etcd"}
_CACHE_IMAGES = {"redis", "memcached", "hazelcast"}
_QUEUE_IMAGES = {"rabbitmq", "kafka", "nats", "activemq", "pulsar"}
_AUTH_IMAGES = {"keycloak", "dex", "ory", "vault", "authelia"}
_SENSITIVE_ENV = {"password", "passwd", "secret", "key", "token", "credential",
                  "api_key", "private", "cert", "tls", "jwt", "database_url", "db_url"}
_SENSITIVE_ANNOTATIONS = {"kubernetes.io/tls", "cert-manager.io"}


def _image_to_type(image: str) -> ComponentType:
    name = image.split(":")[0].lower().split("/")[-1]
    if name in _DB_IMAGES:
        return ComponentType.DATABASE
    if name in _CACHE_IMAGES:
        return ComponentType.CACHE
    if name in _QUEUE_IMAGES:
        return ComponentType.MESSAGE_QUEUE
    if name in _AUTH_IMAGES:
        return ComponentType.AUTH_SERVICE
    return ComponentType.WEB_APP


def _env_has_secrets(containers: list) -> bool:
    for c in containers:
        for env in c.get("env", []):
            name = env.get("name", "").lower()
            if any(s in name for s in _SENSITIVE_ENV):
                return True
            if "valueFrom" in env and ("secretKeyRef" in env["valueFrom"] or
                                        "configMapKeyRef" in env["valueFrom"]):
                return True
        for envFrom in c.get("envFrom", []):
            if "secretRef" in envFrom:
                return True
    return False


def _has_volume_secrets(volumes: list) -> bool:
    for v in volumes:
        if "secret" in v or "projected" in v:
            return True
    return False


def parse_k8s(path: str) -> ApplicationDescriptor:
    """Parse a Kubernetes manifest file (single or multi-document YAML)."""
    p = Path(path)
    raw = p.read_text()
    docs = list(yaml.safe_load_all(raw))
    docs = [d for d in docs if d]  # drop empty docs

    components: list[Component] = []
    data_flows: list[DataFlow] = []
    trust_boundaries: list[TrustBoundary] = []
    has_ingress = False
    has_secrets = False
    namespaces: dict[str, list[str]] = {}
    services: dict[str, dict] = {}
    workloads: dict[str, Component] = {}
    compliance_frameworks: list[str] = []

    for doc in docs:
        kind = doc.get("kind", "")
        meta = doc.get("metadata", {})
        name = meta.get("name", "unnamed")
        namespace = meta.get("namespace", "default")
        annotations = meta.get("annotations", {})

        if kind in ("Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"):
            spec = doc.get("spec", {})
            template = spec.get("template", spec)  # CronJob nests deeper
            if kind == "CronJob":
                template = spec.get("jobTemplate", {}).get("spec", {}).get("template", {})
            pod_spec = template.get("spec", {})
            containers = pod_spec.get("containers", []) + pod_spec.get("initContainers", [])
            volumes = pod_spec.get("volumes", [])

            stores_creds = _env_has_secrets(containers) or _has_volume_secrets(volumes)
            if stores_creds:
                has_secrets = True

            # Infer type from primary container image
            primary_image = containers[0].get("image", "") if containers else ""
            ctype = _image_to_type(primary_image)
            if kind == "StatefulSet":
                ctype = ComponentType.DATABASE

            has_probes = any(
                "livenessProbe" in c or "readinessProbe" in c for c in containers
            )
            privileged = any(
                c.get("securityContext", {}).get("privileged", False) for c in containers
            )
            runs_as_root = any(
                c.get("securityContext", {}).get("runAsUser", 0) == 0 for c in containers
            )

            notes_parts = []
            if privileged:
                notes_parts.append("privileged=true")
            if runs_as_root:
                notes_parts.append("runAsUser=0")
            if not has_probes:
                notes_parts.append("no health probes")

            comp = Component(
                name=name,
                type=ctype,
                technology=primary_image.split(":")[0] if primary_image else kind,
                internet_facing=False,  # updated when we see Services/Ingress
                stores_credentials=stores_creds,
                has_logging=True,  # assume K8s clusters have log aggregation
                has_rate_limiting=False,
                notes=", ".join(notes_parts),
            )
            components.append(comp)
            workloads[name] = comp
            namespaces.setdefault(namespace, []).append(name)

        elif kind == "Service":
            svc_type = doc.get("spec", {}).get("type", "ClusterIP")
            port_list = [str(p.get("port", "")) for p in doc.get("spec", {}).get("ports", [])]
            services[name] = {"type": svc_type, "ports": port_list, "namespace": namespace}

            if svc_type in ("LoadBalancer", "NodePort"):
                selector = doc.get("spec", {}).get("selector", {})
                app_label = selector.get("app", selector.get("name", name))
                if app_label in workloads:
                    workloads[app_label].internet_facing = True

        elif kind == "Ingress":
            has_ingress = True
            rules = doc.get("spec", {}).get("rules", [])
            tls = doc.get("spec", {}).get("tls", [])
            encrypted = bool(tls)

            for rule in rules:
                host = rule.get("host", "*")
                paths = rule.get("http", {}).get("paths", [])
                for path_entry in paths:
                    backend = path_entry.get("backend", {})
                    svc_name = (backend.get("service", {}).get("name") or
                                backend.get("serviceName", ""))
                    if svc_name in workloads:
                        workloads[svc_name].internet_facing = True
                    data_flows.append(DataFlow(
                        name=f"Internet → {svc_name or 'backend'} ({host}{path_entry.get('path','/')})",
                        source="Internet",
                        destination=svc_name or "backend",
                        encrypted=encrypted,
                        authenticated=False,
                        crosses_trust_boundary=True,
                        protocol="HTTPS" if encrypted else "HTTP",
                        data_classification="public",
                    ))

        elif kind == "Secret":
            has_secrets = True
            compliance_frameworks.append("gdpr")

        elif kind == "NetworkPolicy":
            spec = doc.get("spec", {})
            pod_selector = spec.get("podSelector", {})
            namespace_parts = []
            if pod_selector:
                namespace_parts = list(pod_selector.get("matchLabels", {}).values())
            description = (f"Restricts ingress/egress for pods matching "
                           f"{pod_selector.get('matchLabels', {})}")
            trust_boundaries.append(TrustBoundary(
                name=f"NetworkPolicy:{name}",
                components=namespace_parts,
                description=description,
            ))

        elif kind == "ServiceAccount":
            pass  # captured as privilege notes on workloads if needed

    # Create namespace trust boundaries
    for ns, members in namespaces.items():
        trust_boundaries.append(TrustBoundary(
            name=f"Namespace:{ns}",
            components=members,
            description=f"Kubernetes namespace isolation for: {', '.join(members)}",
        ))

    # Add inter-service data flows from service→workload relationships
    for svc_name, svc_info in services.items():
        if svc_name in workloads:
            for other_name in workloads:
                if other_name != svc_name:
                    data_flows.append(DataFlow(
                        name=f"{other_name} → {svc_name} (svc:{svc_info['type']})",
                        source=other_name,
                        destination=svc_name,
                        encrypted=False,
                        authenticated=False,
                        crosses_trust_boundary=False,
                        protocol="TCP",
                    ))
            break  # Only add one round to avoid N² explosion on large clusters

    app_name = p.stem.replace("-", " ").replace("_", " ").title() or "Kubernetes Application"
    stores_pii = has_secrets

    if "gdpr" not in compliance_frameworks and stores_pii:
        compliance_frameworks.append("gdpr")

    return ApplicationDescriptor(
        name=app_name,
        description=f"Parsed from {p.name}. {len(docs)} manifest(s). Ingress: {has_ingress}.",
        environment="production",
        internet_facing=has_ingress or any(c.internet_facing for c in components),
        data_classification="confidential" if stores_pii else "internal",
        components=components,
        data_flows=data_flows,
        trust_boundaries=trust_boundaries,
        compliance_frameworks=list(set(compliance_frameworks)),
    )
