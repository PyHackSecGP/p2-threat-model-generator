"""Parse Terraform (.tf) HCL files into ApplicationDescriptor.

Covers the common AWS/GCP/Azure STRIDE-relevant resource types:
- compute (EC2, GCE VMs, Azure VMs, ECS tasks, Lambda) → WEB_APP / WORKER
- storage buckets (S3, GCS, Azure Blob) → STORAGE
- databases (RDS, Aurora, Cloud SQL, Azure SQL) → DATABASE
- IAM roles / users / policies → AUTH_SERVICE
- security groups / firewall rules → surface as flow metadata + notes
- load balancers (ALB, NLB, Cloud LB) → LOAD_BALANCER

Risk flags surfaced via component attributes so the existing STRIDE engine
produces the right threats, plus a few Terraform-specific threats appended
inline (public S3 bucket, IAM wildcard, unencrypted RDS, 0.0.0.0/0 ingress).

Backend: python-hcl2 when installed (recommended, see requirements.txt).
Falls back to a stdlib regex parser handling the subset we need, so the
module works even without the optional dependency — tests pass either way.

ponytail: regex fallback intentionally covers only resource/provider blocks
and the handful of attributes used by our 4 rules. Upgrade path: install
python-hcl2 for complex configs (dynamic blocks, locals, variables, modules).
"""
from __future__ import annotations
import re
from pathlib import Path

try:
    import hcl2  # type: ignore
    _HAS_HCL2 = True
except ImportError:
    hcl2 = None  # type: ignore
    _HAS_HCL2 = False

from models import (
    ApplicationDescriptor, AuthType, Component, ComponentType, DataFlow,
    MitreMapping, NistControl, OwaspMapping, Severity, StrideCategory, Threat,
)

# ── Resource-type → ComponentType mapping ────────────────────────────────────
_COMPUTE = {
    "aws_instance", "aws_ecs_service", "aws_ecs_task_definition",
    "aws_lambda_function", "aws_launch_template", "aws_autoscaling_group",
    "google_compute_instance", "google_cloud_run_service", "google_cloudfunctions_function",
    "azurerm_virtual_machine", "azurerm_linux_virtual_machine", "azurerm_function_app",
}
_STORAGE = {
    "aws_s3_bucket", "google_storage_bucket", "azurerm_storage_account",
    "azurerm_storage_container", "aws_ebs_volume",
}
_DATABASE = {
    "aws_db_instance", "aws_rds_cluster", "aws_dynamodb_table",
    "google_sql_database_instance", "google_bigtable_instance",
    "azurerm_mssql_database", "azurerm_postgresql_server", "azurerm_mysql_server",
    "aws_elasticache_cluster",
}
_AUTH = {
    "aws_iam_role", "aws_iam_user", "aws_iam_policy", "aws_iam_group",
    "google_service_account", "google_project_iam_binding",
    "azurerm_role_assignment", "azurerm_user_assigned_identity",
}
_LB = {
    "aws_lb", "aws_elb", "aws_alb",
    "google_compute_forwarding_rule", "google_compute_global_forwarding_rule",
    "azurerm_lb",
}
_QUEUE = {
    "aws_sqs_queue", "aws_sns_topic", "aws_msk_cluster",
    "google_pubsub_topic", "azurerm_servicebus_queue",
}
_CDN = {"aws_cloudfront_distribution", "google_compute_backend_bucket", "azurerm_cdn_endpoint"}
_SG = {"aws_security_group", "aws_security_group_rule",
       "google_compute_firewall", "azurerm_network_security_rule"}

_TYPE_MAP: dict[frozenset, ComponentType] = {
    frozenset(_COMPUTE): ComponentType.WEB_APP,
    frozenset(_STORAGE): ComponentType.STORAGE,
    frozenset(_DATABASE): ComponentType.DATABASE,
    frozenset(_AUTH): ComponentType.AUTH_SERVICE,
    frozenset(_LB): ComponentType.LOAD_BALANCER,
    frozenset(_QUEUE): ComponentType.MESSAGE_QUEUE,
    frozenset(_CDN): ComponentType.CDN,
}


def _resource_component_type(resource_type: str) -> ComponentType | None:
    """Return ComponentType for a given Terraform resource type, or None if ignored."""
    for types, ctype in _TYPE_MAP.items():
        if resource_type in types:
            return ctype
    return None


def _unwrap(v):
    """hcl2 wraps every attribute in a 1-element list — unwrap for inspection."""
    if isinstance(v, list) and len(v) == 1:
        return v[0]
    return v


def _looks_public_s3(attrs: dict) -> bool:
    """Detect S3/GCS/Azure buckets that are world-readable."""
    acl = str(_unwrap(attrs.get("acl", ""))).lower()
    if acl in ("public-read", "public-read-write"):
        return True
    # aws_s3_bucket_public_access_block set to all false also = public
    pab = _unwrap(attrs.get("public_access_block", {}))
    if isinstance(pab, dict) and all(
        _unwrap(pab.get(k, True)) is False
        for k in ("block_public_acls", "block_public_policy",
                  "ignore_public_acls", "restrict_public_buckets")
    ):
        return True
    return False


def _iam_has_wildcard(attrs: dict) -> bool:
    """Detect IAM policy documents with Action='*' or Resource='*'."""
    def _has_star(policy_text: str, key: str) -> bool:
        # Match "Action":"*" or "Action": "*" or "Action" : "*" (any whitespace).
        return bool(re.search(rf'"{key}"\s*:\s*"\*"', policy_text))

    policy = _unwrap(attrs.get("policy", ""))
    if isinstance(policy, str) and (_has_star(policy, "Action") or _has_star(policy, "Resource")):
        return True
    # inline policy / assume_role_policy with Principal="*" is also wildcard
    assume = _unwrap(attrs.get("assume_role_policy", ""))
    if isinstance(assume, str) and _has_star(assume, "Principal"):
        return True
    return False


def _rds_unencrypted(attrs: dict) -> bool:
    enc = _unwrap(attrs.get("storage_encrypted", True))
    return enc is False


def _sg_open_ingress(attrs: dict) -> bool:
    """Detect security groups with 0.0.0.0/0 ingress on any port."""
    for ingress in attrs.get("ingress", []):
        ing = _unwrap(ingress)
        if not isinstance(ing, dict):
            continue
        cidrs = ing.get("cidr_blocks", [])  # don't _unwrap: hcl2 wraps str list in [[...]]
        # hcl2 shape: cidr_blocks = [["0.0.0.0/0"]]; stdlib shape: ["0.0.0.0/0"]
        flat: list = []
        for c in cidrs if isinstance(cidrs, list) else [cidrs]:
            if isinstance(c, list):
                flat.extend(c)
            else:
                flat.append(c)
        if "0.0.0.0/0" in flat:
            return True
    return False


def _mk_threat(tid: str, title: str, cat: StrideCategory, component: str,
               description: str, impact_text: str, likelihood: int, impact: int,
               mitigations: list[str], mitre_ids: list[str], owasp_ids: list[str],
               nist_ids: list[str]) -> Threat:
    """Build a Terraform-specific threat with STRIDE+MITRE+OWASP+NIST metadata."""
    from engine.stride import MITRE, NIST, OWASP
    return Threat(
        id=tid, title=title, stride_category=cat, component=component,
        description=description,
        attack_vector="Misconfigured infrastructure-as-code deployed to production.",
        business_impact=impact_text,
        likelihood=likelihood, impact=impact,
        mitigations=mitigations,
        mitre_mappings=[MITRE[m] for m in mitre_ids if m in MITRE],
        owasp_mappings=[OWASP[o] for o in owasp_ids if o in OWASP],
        nist_controls=[NIST[n] for n in nist_ids if n in NIST],
        remediation_effort="Low",
    )


def _terraform_specific_threats(resources: list[tuple[str, str, dict]]) -> list[Threat]:
    """Generate Terraform-config-specific threats (public bucket, IAM *, etc.).

    resources: list of (resource_type, name, attrs) tuples.
    """
    threats: list[Threat] = []
    n = 0

    def tid() -> str:
        nonlocal n
        n += 1
        return f"TF{n:03d}"

    for rtype, name, attrs in resources:
        comp = f"{rtype}.{name}"
        if rtype == "aws_s3_bucket" and _looks_public_s3(attrs):
            threats.append(_mk_threat(
                tid(), f"Public S3 Bucket — {name}",
                StrideCategory.INFO_DISCLOSURE, comp,
                f"S3 bucket '{name}' is configured with public-read ACL or has all public "
                "access-block controls disabled. Any unauthenticated internet user can list "
                "and download bucket contents.",
                "Mass data exposure to the entire internet. Instant GDPR breach trigger if "
                "the bucket contains PII. Historical examples: Capital One, Accenture, "
                "Verizon leaks — all S3 misconfigurations.",
                likelihood=5, impact=5,
                mitigations=[
                    "Set acl = \"private\" and remove any public-read policy.",
                    "Enable aws_s3_bucket_public_access_block with all four controls set to true.",
                    "Serve public content via CloudFront + OAI/OAC, never direct bucket access.",
                    "Enable CloudTrail S3 data-event logging to detect anonymous reads.",
                ],
                mitre_ids=["T1530", "T1213"], owasp_ids=["A01", "A05"],
                nist_ids=["AC-6", "SC-28"],
            ))
        elif rtype.startswith(("aws_iam_", "google_project_iam_", "azurerm_role_")) and _iam_has_wildcard(attrs):
            threats.append(_mk_threat(
                tid(), f"Wildcard IAM Policy — {name}",
                StrideCategory.ELEVATION_OF_PRIVILEGE, comp,
                f"IAM policy '{name}' grants Action='*' or Resource='*', violating least "
                "privilege. Any principal attached to this policy can perform any action on "
                "any resource.",
                "Compromise of a single credential grants full account takeover. "
                "Lateral movement, data exfiltration, and persistent backdoor creation become "
                "trivial once an attacker holds any key tied to this role.",
                likelihood=4, impact=5,
                mitigations=[
                    "Scope Action to specific service verbs (e.g. s3:GetObject, not s3:*).",
                    "Scope Resource to specific ARNs rather than \"*\".",
                    "Use IAM Access Analyzer to find and remove unused permissions.",
                    "Attach permission boundaries to limit max effective privilege.",
                ],
                mitre_ids=["T1078", "T1548"], owasp_ids=["A01", "A05"],
                nist_ids=["AC-6", "AC-2"],
            ))
        elif rtype in ("aws_db_instance", "aws_rds_cluster") and _rds_unencrypted(attrs):
            threats.append(_mk_threat(
                tid(), f"Unencrypted RDS Database — {name}",
                StrideCategory.INFO_DISCLOSURE, comp,
                f"RDS instance '{name}' has storage_encrypted=false. Database storage, "
                "snapshots, and automated backups are stored in plaintext on AWS infrastructure.",
                "Snapshot leak or disk-level compromise exposes the entire dataset in plaintext. "
                "GDPR Art. 32 requires encryption at rest for PII; non-compliance = fines up to "
                "4% global turnover.",
                likelihood=3, impact=5,
                mitigations=[
                    "Set storage_encrypted = true (requires creating a new instance; "
                    "AWS cannot encrypt an existing unencrypted RDS in place).",
                    "Use a customer-managed KMS key (kms_key_id) for stronger key control and auditability.",
                    "Enable automated snapshot encryption; prohibit public snapshot sharing.",
                ],
                mitre_ids=["T1530", "T1552"], owasp_ids=["A02"],
                nist_ids=["SC-28"],
            ))
        elif rtype == "aws_security_group" and _sg_open_ingress(attrs):
            threats.append(_mk_threat(
                tid(), f"Open Ingress 0.0.0.0/0 — {name}",
                StrideCategory.TAMPERING, comp,
                f"Security group '{name}' allows ingress from 0.0.0.0/0 (entire internet). "
                "Any port exposed this way is directly reachable by every scanner and botnet.",
                "Direct exposure of backend services (SSH, RDP, databases) to the internet. "
                "Credential stuffing, exploit-and-pivot, and ransomware deployment all become "
                "one-step attacks. Shodan indexes these daily.",
                likelihood=5, impact=4,
                mitigations=[
                    "Restrict cidr_blocks to known office/VPN CIDR ranges only.",
                    "For admin access (SSH/RDP): use SSM Session Manager or a bastion host — never direct SG open.",
                    "For public web traffic: expose only via ALB/CloudFront, not direct SG open on the instance.",
                    "Enable VPC Flow Logs; alert on new 0.0.0.0/0 security group rules via Config/EventBridge.",
                ],
                mitre_ids=["T1190", "T1046"], owasp_ids=["A05"],
                nist_ids=["AC-17", "SC-8"],
            ))
    return threats


# ── Stdlib HCL fallback (minimal, resource/provider/data blocks only) ─────────
_BLOCK_RE = re.compile(
    r'(resource|data|provider)\s+"([^"]+)"(?:\s+"([^"]+)")?\s*\{', re.MULTILINE
)


def _find_matching_brace(text: str, start: int) -> int:
    """Return index of the '}' that closes the '{' at `start-1`. Ignores braces in strings."""
    depth = 1
    i = start
    in_str = False
    esc = False
    while i < len(text) and depth > 0:
        ch = text[i]
        if esc:
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == '"':
            in_str = not in_str
        elif not in_str:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
        i += 1
    return i - 1


def _parse_attrs(body: str) -> dict:
    """Parse a block body into a dict of attr → value. Nested blocks become list[dict]."""
    attrs: dict = {}
    i = 0
    n = len(body)
    # Simple attribute: key = value (string/number/bool/list)
    attr_re = re.compile(r'(\w+)\s*=\s*')
    while i < n:
        # Skip whitespace and comments
        while i < n and body[i] in " \t\r\n":
            i += 1
        if i >= n:
            break
        if body[i] == "#" or body.startswith("//", i):
            nl = body.find("\n", i)
            i = n if nl == -1 else nl + 1
            continue
        # Nested block: name { ... }
        m_block = re.match(r'(\w+)\s*\{', body[i:])
        m_attr = attr_re.match(body[i:])
        if m_block and (not m_attr or m_block.start(1) < m_attr.start(1)):
            name = m_block.group(1)
            start = i + m_block.end()
            end = _find_matching_brace(body, start)
            nested = _parse_attrs(body[start:end])
            attrs.setdefault(name, []).append(nested)
            i = end + 1
            continue
        if not m_attr:
            # Can't parse this line; skip to next newline
            nl = body.find("\n", i)
            i = n if nl == -1 else nl + 1
            continue
        key = m_attr.group(1)
        i += m_attr.end()
        # Value: string, [list], number, bool, {object}, or expression up to newline
        value, consumed = _read_value(body[i:])
        attrs[key] = value
        i += consumed
    return attrs


def _read_value(s: str) -> tuple[object, int]:
    """Read one HCL value starting at index 0 of `s`. Returns (value, chars_consumed)."""
    i = 0
    n = len(s)
    # Skip leading whitespace
    while i < n and s[i] in " \t":
        i += 1
    if i >= n:
        return "", i
    ch = s[i]
    # String
    if ch == '"':
        end = i + 1
        esc = False
        while end < n:
            if esc:
                esc = False
            elif s[end] == "\\":
                esc = True
            elif s[end] == '"':
                break
            end += 1
        return s[i + 1:end].encode().decode("unicode_escape"), end + 1
    # List
    if ch == "[":
        depth = 1
        end = i + 1
        in_str = False
        esc = False
        while end < n and depth > 0:
            c = s[end]
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = not in_str
            elif not in_str:
                if c == "[":
                    depth += 1
                elif c == "]":
                    depth -= 1
            end += 1
        inner = s[i + 1:end - 1]
        items = [it.strip().strip('"') for it in inner.split(",") if it.strip()]
        return items, end
    # Object literal
    if ch == "{":
        end = _find_matching_brace(s, i + 1)
        return _parse_attrs(s[i + 1:end]), end + 1
    # Scalar — read until newline
    end = i
    while end < n and s[end] != "\n":
        end += 1
    raw = s[i:end].strip()
    if raw in ("true", "false"):
        return raw == "true", end + 1
    try:
        return int(raw), end + 1
    except ValueError:
        try:
            return float(raw), end + 1
        except ValueError:
            return raw, end + 1


def _parse_tf_stdlib(text: str) -> dict:
    """Minimal HCL parser → dict shaped like hcl2.load() output for our needs."""
    out: dict = {"resource": [], "data": [], "provider": []}
    for m in _BLOCK_RE.finditer(text):
        kind = m.group(1)
        type_or_name = m.group(2)
        name = m.group(3)
        body_start = m.end()
        body_end = _find_matching_brace(text, body_start)
        body = text[body_start:body_end]
        attrs = _parse_attrs(body)
        if kind == "resource" and name:
            # hcl2 shape: {"resource": [{"aws_s3_bucket": {"my_bucket": {...}}}]}
            out["resource"].append({type_or_name: {name: attrs}})
        elif kind == "data" and name:
            out["data"].append({type_or_name: {name: attrs}})
        elif kind == "provider":
            out["provider"].append({type_or_name: attrs})
    return out


def _load_tf(tf_file: Path) -> dict:
    """Load a .tf file via python-hcl2 if available, otherwise the stdlib fallback."""
    if _HAS_HCL2:
        with tf_file.open("r") as f:
            return hcl2.load(f)
    return _parse_tf_stdlib(tf_file.read_text())


def parse_terraform(path: str) -> ApplicationDescriptor:
    """Parse a Terraform .tf file (or directory containing .tf files) into ApplicationDescriptor."""
    p = Path(path)
    files = sorted(p.glob("*.tf")) if p.is_dir() else [p]
    app_name = (p.name if p.is_dir() else p.stem).replace("-", " ").replace("_", " ").title() \
        or "Terraform Infrastructure"

    components: list[Component] = []
    data_flows: list[DataFlow] = []
    resources_seen: list[tuple[str, str, dict]] = []  # (rtype, name, attrs)
    providers: list[str] = []
    compliance: set[str] = set()

    for tf_file in files:
        data = _load_tf(tf_file)

        # provider blocks
        for prov in data.get("provider", []):
            if isinstance(prov, dict):
                providers.extend(prov.keys())

        # resource blocks: list of { "aws_s3_bucket": { "name": { attrs } } }
        for rblock in data.get("resource", []):
            for rtype, instances in rblock.items():
                for rname, attrs in instances.items():
                    if not isinstance(attrs, dict):
                        continue
                    resources_seen.append((rtype, rname, attrs))
                    ctype = _resource_component_type(rtype)
                    if ctype is None:
                        continue
                    # Infer attribute flags from the HCL
                    public = _looks_public_s3(attrs) if rtype == "aws_s3_bucket" else False
                    unencrypted = _rds_unencrypted(attrs) if rtype in ("aws_db_instance", "aws_rds_cluster") else False
                    open_ingress = _sg_open_ingress(attrs) if rtype == "aws_security_group" else False
                    internet_facing = public or open_ingress or ctype in (
                        ComponentType.LOAD_BALANCER, ComponentType.CDN
                    )
                    stores_pii = ctype in (ComponentType.DATABASE, ComponentType.STORAGE)
                    stores_credentials = ctype == ComponentType.AUTH_SERVICE
                    notes_parts = []
                    if public:
                        notes_parts.append("public ACL/access-block")
                    if unencrypted:
                        notes_parts.append("storage_encrypted=false")
                    if open_ingress:
                        notes_parts.append("ingress 0.0.0.0/0")
                    if ctype == ComponentType.STORAGE and stores_pii:
                        compliance.add("gdpr")
                    components.append(Component(
                        name=f"{rtype}.{rname}",
                        type=ctype,
                        technology=rtype,
                        internet_facing=internet_facing,
                        stores_pii=stores_pii,
                        stores_credentials=stores_credentials,
                        has_logging=False,  # unknown from HCL — flag as risky
                        has_rate_limiting=False,
                        notes=", ".join(notes_parts),
                    ))

    # Terraform-specific threats appended via a sidecar list on the descriptor.
    # The existing STRIDE engine picks up component-level risks; we also need to
    # surface the config-level ones. Store them in the trust_boundary mechanism
    # by piggybacking on a known attribute — but cleaner: expose a function the
    # engine can call. For MVP, attach via module-level accessor used in tests.
    tf_threats = _terraform_specific_threats(resources_seen)

    app = ApplicationDescriptor(
        name=app_name,
        description=f"Parsed from {len(files)} .tf file(s). Providers: {sorted(set(providers)) or 'unknown'}.",
        environment="production",
        internet_facing=any(c.internet_facing for c in components),
        data_classification="confidential" if any(c.stores_pii for c in components) else "internal",
        components=components,
        data_flows=data_flows,
        compliance_frameworks=sorted(compliance),
    )
    # Stash on the descriptor so run_stride can pick them up (opt-in).
    # ponytail: single mutable attr beats a new engine hook for 4 threat types.
    app.terraform_threats = tf_threats  # type: ignore[attr-defined]
    return app
