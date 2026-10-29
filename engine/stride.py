"""STRIDE rule engine — generates threats for each component and data flow."""
from __future__ import annotations
from models import (
    ApplicationDescriptor, Component, ComponentType, DataFlow,
    MitreMapping, NistControl, OwaspMapping, StrideCategory, Threat,
)

# ── MITRE ATT&CK quick-ref ────────────────────────────────────────────────────
_M = MitreMapping

MITRE = {
    "T1078": _M("T1078", "Valid Accounts", "Defense Evasion / Persistence", "https://attack.mitre.org/techniques/T1078/"),
    "T1110": _M("T1110", "Brute Force", "Credential Access", "https://attack.mitre.org/techniques/T1110/"),
    "T1539": _M("T1539", "Steal Web Session Cookie", "Credential Access", "https://attack.mitre.org/techniques/T1539/"),
    "T1190": _M("T1190", "Exploit Public-Facing Application", "Initial Access", "https://attack.mitre.org/techniques/T1190/"),
    "T1565": _M("T1565", "Data Manipulation", "Impact", "https://attack.mitre.org/techniques/T1565/"),
    "T1059": _M("T1059", "Command and Scripting Interpreter", "Execution", "https://attack.mitre.org/techniques/T1059/"),
    "T1562": _M("T1562", "Impair Defenses", "Defense Evasion", "https://attack.mitre.org/techniques/T1562/"),
    "T1070": _M("T1070", "Indicator Removal", "Defense Evasion", "https://attack.mitre.org/techniques/T1070/"),
    "T1552": _M("T1552", "Unsecured Credentials", "Credential Access", "https://attack.mitre.org/techniques/T1552/"),
    "T1530": _M("T1530", "Data from Cloud Storage", "Collection", "https://attack.mitre.org/techniques/T1530/"),
    "T1213": _M("T1213", "Data from Information Repositories", "Collection", "https://attack.mitre.org/techniques/T1213/"),
    "T1499": _M("T1499", "Endpoint Denial of Service", "Impact", "https://attack.mitre.org/techniques/T1499/"),
    "T1498": _M("T1498", "Network Denial of Service", "Impact", "https://attack.mitre.org/techniques/T1498/"),
    "T1548": _M("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation", "https://attack.mitre.org/techniques/T1548/"),
    "T1134": _M("T1134", "Access Token Manipulation", "Privilege Escalation", "https://attack.mitre.org/techniques/T1134/"),
    "T1574": _M("T1574", "Hijack Execution Flow", "Privilege Escalation", "https://attack.mitre.org/techniques/T1574/"),
    "T1046": _M("T1046", "Network Service Discovery", "Discovery", "https://attack.mitre.org/techniques/T1046/"),
    "T1595": _M("T1595", "Active Scanning", "Reconnaissance", "https://attack.mitre.org/techniques/T1595/"),
    "T1195": _M("T1195", "Supply Chain Compromise", "Initial Access", "https://attack.mitre.org/techniques/T1195/"),
}

# ── OWASP 2021 quick-ref ──────────────────────────────────────────────────────
OWASP = {
    "A01": OwaspMapping("A01:2021", "Broken Access Control"),
    "A02": OwaspMapping("A02:2021", "Cryptographic Failures"),
    "A03": OwaspMapping("A03:2021", "Injection"),
    "A04": OwaspMapping("A04:2021", "Insecure Design"),
    "A05": OwaspMapping("A05:2021", "Security Misconfiguration"),
    "A06": OwaspMapping("A06:2021", "Vulnerable and Outdated Components"),
    "A07": OwaspMapping("A07:2021", "Identification and Authentication Failures"),
    "A08": OwaspMapping("A08:2021", "Software and Data Integrity Failures"),
    "A09": OwaspMapping("A09:2021", "Security Logging and Monitoring Failures"),
    "A10": OwaspMapping("A10:2021", "Server-Side Request Forgery"),
}

# ── NIST 800-53 controls ──────────────────────────────────────────────────────
NIST = {
    "AC-2":  NistControl("AC-2",  "Account Management", "Access Control"),
    "AC-6":  NistControl("AC-6",  "Least Privilege", "Access Control"),
    "AC-17": NistControl("AC-17", "Remote Access", "Access Control"),
    "AU-2":  NistControl("AU-2",  "Event Logging", "Audit and Accountability"),
    "AU-9":  NistControl("AU-9",  "Protection of Audit Information", "Audit and Accountability"),
    "IA-2":  NistControl("IA-2",  "Identification and Authentication", "IA"),
    "IA-5":  NistControl("IA-5",  "Authenticator Management", "IA"),
    "SC-8":  NistControl("SC-8",  "Transmission Confidentiality and Integrity", "System and Comm"),
    "SC-28": NistControl("SC-28", "Protection of Information at Rest", "System and Comm"),
    "SI-10": NistControl("SI-10", "Information Input Validation", "System Integrity"),
    "SI-2":  NistControl("SI-2",  "Flaw Remediation", "System Integrity"),
    "CP-10": NistControl("CP-10", "System Recovery and Reconstitution", "Contingency Planning"),
    "SA-11": NistControl("SA-11", "Developer Testing and Evaluation", "System Acquisition"),
}


# ── Rule definitions ──────────────────────────────────────────────────────────

def _internet_boost(c: Component) -> int:
    return 1 if c.internet_facing else 0


def _pii_boost(c: Component) -> int:
    return 1 if c.stores_pii else 0


def _no_ratelimit_boost(c: Component) -> int:
    return 1 if not c.has_rate_limiting else 0


def _no_log_boost(c: Component) -> int:
    return 1 if not c.has_logging else 0


def _weak_auth_boost(c: Component) -> int:
    return 1 if c.auth_type in ("none", "basic", "api_key") else 0


def generate_component_threats(c: Component, idx: int) -> list[Threat]:
    """Generate STRIDE threats for a single component."""
    threats: list[Threat] = []
    prefix = f"T{idx:03d}"
    n = 0

    def tid() -> str:
        nonlocal n
        n += 1
        return f"{prefix}-{n:02d}"

    ct = c.type

    # ── SPOOFING ──────────────────────────────────────────────────────────────
    if ct in (ComponentType.WEB_APP, ComponentType.API, ComponentType.AUTH_SERVICE):
        lk = min(5, 3 + _internet_boost(c) + _weak_auth_boost(c))
        threats.append(Threat(
            id=tid(), title=f"Identity Spoofing — {c.name}",
            stride_category=StrideCategory.SPOOFING, component=c.name,
            description=f"Attacker impersonates a legitimate user or service accessing {c.name} "
                        f"via credential theft, session hijacking, or weak authentication bypass.",
            attack_vector="Credential stuffing, brute-force, stolen session tokens, OAuth token replay.",
            business_impact=(
                "Unauthorised access to customer accounts or internal systems. "
                "Potential for data theft, fraudulent transactions, reputational damage, "
                "and regulatory liability under GDPR/PCI-DSS."
            ),
            likelihood=lk, impact=5 if c.stores_pii else 4,
            mitigations=[
                "Enforce MFA on all user-facing authentication flows.",
                "Implement account lockout after 5 failed attempts.",
                "Use short-lived JWTs with refresh token rotation.",
                "Monitor for credential stuffing patterns (IP velocity, geo-anomalies).",
            ],
            mitre_mappings=[MITRE["T1110"], MITRE["T1539"], MITRE["T1078"]],
            owasp_mappings=[OWASP["A07"]],
            nist_controls=[NIST["IA-2"], NIST["IA-5"], NIST["AC-2"]],
            remediation_effort="Medium",
        ))

    if ct == ComponentType.API and c.auth_type in ("none", "api_key"):
        threats.append(Threat(
            id=tid(), title=f"API Key Compromise — {c.name}",
            stride_category=StrideCategory.SPOOFING, component=c.name,
            description=f"Long-lived API keys for {c.name} stored in source code, logs, or "
                        "environment variables allow attacker to permanently impersonate any client.",
            attack_vector="GitHub secret scan, log file exfiltration, insider threat.",
            business_impact="Permanent impersonation of any API consumer until key is rotated. "
                            "Mass data exfiltration or service abuse at no cost to attacker.",
            likelihood=3, impact=4,
            mitigations=[
                "Rotate to short-lived OAuth2 client credentials or mTLS.",
                "Scan all repos with truffleHog or GitHub secret scanning.",
                "Centralise secrets in Vault/AWS Secrets Manager — no plaintext in env vars.",
            ],
            mitre_mappings=[MITRE["T1552"], MITRE["T1078"]],
            owasp_mappings=[OWASP["A07"], OWASP["A05"]],
            nist_controls=[NIST["IA-5"], NIST["SC-28"]],
            remediation_effort="Low",
        ))

    # ── TAMPERING ─────────────────────────────────────────────────────────────
    if ct in (ComponentType.WEB_APP, ComponentType.API):
        lk = min(5, 3 + _internet_boost(c))
        threats.append(Threat(
            id=tid(), title=f"Injection Attack — {c.name}",
            stride_category=StrideCategory.TAMPERING, component=c.name,
            description=f"Malicious input reaches {c.name} without proper validation or "
                        "parameterisation, enabling SQL injection, command injection, or XSS.",
            attack_vector="Crafted HTTP requests targeting form fields, query params, JSON bodies, headers.",
            business_impact="Complete database exfiltration, remote code execution, "
                            "customer data theft. SQLi breaches average $3.86M (IBM Cost of a Data Breach).",
            likelihood=lk, impact=5,
            mitigations=[
                "Parameterise all database queries — never concatenate user input.",
                "Implement strict input validation and allowlisting at every entry point.",
                "Deploy WAF rules for SQLi, XSS, command injection patterns.",
                "Use Content Security Policy headers to mitigate XSS impact.",
                "Run SAST (Semgrep/Bandit) and DAST (ZAP) in CI pipeline.",
            ],
            mitre_mappings=[MITRE["T1190"], MITRE["T1059"]],
            owasp_mappings=[OWASP["A03"]],
            nist_controls=[NIST["SI-10"], NIST["SA-11"]],
            remediation_effort="Medium",
        ))

    if ct == ComponentType.DATABASE:
        threats.append(Threat(
            id=tid(), title=f"Data Tampering — {c.name}",
            stride_category=StrideCategory.TAMPERING, component=c.name,
            description=f"Attacker with excessive DB privileges or via SQLi modifies records in {c.name}, "
                        "corrupting financial data, audit trails, or application state.",
            attack_vector="Overprivileged service accounts, SQLi through upstream app, insider access.",
            business_impact="Data integrity loss. Corrupted financial records trigger compliance audit failures. "
                            "Reverting tampered data requires costly forensic investigation.",
            likelihood=2 + _pii_boost(c), impact=4 + _pii_boost(c),
            mitigations=[
                "Apply least-privilege — app service account: SELECT/INSERT/UPDATE only, no DDL/DROP.",
                "Enable database audit logging for all DDL and bulk operations.",
                "Implement row-level checksums or audit tables for sensitive records.",
                "Restrict direct DB access to DB admins via PAM jump server.",
            ],
            mitre_mappings=[MITRE["T1565"]],
            owasp_mappings=[OWASP["A01"], OWASP["A04"]],
            nist_controls=[NIST["AC-6"], NIST["AU-2"]],
            remediation_effort="Medium",
        ))

    # ── REPUDIATION ───────────────────────────────────────────────────────────
    if not c.has_logging:
        threats.append(Threat(
            id=tid(), title=f"Missing Audit Trail — {c.name}",
            stride_category=StrideCategory.REPUDIATION, component=c.name,
            description=f"{c.name} does not log critical operations, allowing an attacker "
                        "(or insider) to perform actions that cannot be attributed or reconstructed.",
            attack_vector="Any action within the component — no evidence remains after the fact.",
            business_impact="Incident response is blind. Regulatory fines for inadequate audit trails "
                            "(GDPR Art. 30, SOC2 CC7). Legal liability if breach cannot be scoped.",
            likelihood=3, impact=4,
            mitigations=[
                "Implement structured logging (JSON) for all state-changing operations.",
                "Ship logs to centralised SIEM (Splunk/ELK) with tamper-evident storage.",
                "Include user ID, IP, timestamp, action, and resource in every log event.",
                "Set log retention minimum 90 days hot, 1 year cold.",
            ],
            mitre_mappings=[MITRE["T1562"], MITRE["T1070"]],
            owasp_mappings=[OWASP["A09"]],
            nist_controls=[NIST["AU-2"], NIST["AU-9"]],
            remediation_effort="Low",
        ))
    else:
        threats.append(Threat(
            id=tid(), title=f"Log Tampering / Evasion — {c.name}",
            stride_category=StrideCategory.REPUDIATION, component=c.name,
            description=f"Attacker with access to {c.name} clears or manipulates logs to cover tracks, "
                        "undermining forensic investigation and incident response.",
            attack_vector="Elevated OS/DB access, log rotation exploit, direct log file write access.",
            business_impact="Incident scope cannot be determined. Forensic investigation fails. "
                            "Regulatory reporting deadlines missed (72h GDPR breach notification).",
            likelihood=2, impact=3,
            mitigations=[
                "Forward logs to immutable remote SIEM immediately — local logs are secondary.",
                "Restrict log file write permissions to logging daemon only.",
                "Alert on log gaps, rotation anomalies, or log volume drops.",
            ],
            mitre_mappings=[MITRE["T1070"]],
            owasp_mappings=[OWASP["A09"]],
            nist_controls=[NIST["AU-9"]],
            remediation_effort="Low",
        ))

    # ── INFORMATION DISCLOSURE ────────────────────────────────────────────────
    if c.stores_pii or c.stores_credentials:
        lk = min(5, 2 + _internet_boost(c) + _pii_boost(c))
        threats.append(Threat(
            id=tid(), title=f"Sensitive Data Exposure — {c.name}",
            stride_category=StrideCategory.INFO_DISCLOSURE, component=c.name,
            description=f"{c.name} stores {'PII and/or credentials' if c.stores_pii and c.stores_credentials else 'PII' if c.stores_pii else 'credentials'}. "
                        "Exfiltration via unencrypted storage, over-permissive access controls, or API leakage exposes this data.",
            attack_vector="Direct database access, API response over-sharing, backup file exposure, "
                          "unencrypted data at rest.",
            business_impact=(
                "GDPR breach notification required within 72 hours. Fines up to €20M or 4% of global turnover. "
                "Class action risk. Average PII breach cost: $4.45M (IBM 2023)."
                if c.stores_pii else
                "Credential exposure enables full account takeover and lateral movement across all systems using those credentials."
            ),
            likelihood=lk, impact=5,
            mitigations=[
                "Encrypt PII at rest using AES-256; rotate encryption keys annually.",
                "Implement field-level encryption for highly sensitive fields (SSN, payment data).",
                "Apply data masking in non-production environments.",
                "Enforce column-level access control — limit which roles can SELECT PII columns.",
                "Audit all queries touching PII tables.",
            ],
            mitre_mappings=[MITRE["T1213"], MITRE["T1530"]],
            owasp_mappings=[OWASP["A02"], OWASP["A01"]],
            nist_controls=[NIST["SC-28"], NIST["AC-6"]],
            remediation_effort="High",
        ))

    if ct in (ComponentType.WEB_APP, ComponentType.API) and c.internet_facing:
        threats.append(Threat(
            id=tid(), title=f"Error Message Information Leakage — {c.name}",
            stride_category=StrideCategory.INFO_DISCLOSURE, component=c.name,
            description=f"Verbose error messages from {c.name} expose stack traces, internal paths, "
                        "framework versions, or database query details to unauthenticated users.",
            attack_vector="Intentional malformed requests; crawler collection of public error pages.",
            business_impact="Aids attacker reconnaissance — reduces time-to-exploit by revealing "
                            "exact technology versions with known CVEs.",
            likelihood=3, impact=2,
            mitigations=[
                "Return generic error messages to clients; log verbose errors server-side only.",
                "Implement global exception handler returning RFC 7807 Problem Details format.",
                "Remove server/framework headers (X-Powered-By, Server).",
            ],
            mitre_mappings=[MITRE["T1595"]],
            owasp_mappings=[OWASP["A05"]],
            nist_controls=[NIST["SI-10"]],
            remediation_effort="Low",
        ))

    # ── DENIAL OF SERVICE ─────────────────────────────────────────────────────
    if c.internet_facing:
        lk = min(5, 3 + _no_ratelimit_boost(c))
        threats.append(Threat(
            id=tid(), title=f"Application-Layer DoS — {c.name}",
            stride_category=StrideCategory.DENIAL_OF_SERVICE, component=c.name,
            description=f"Attacker floods {c.name} with high-cost requests (complex queries, large uploads, "
                        "expensive computations) causing resource exhaustion and service unavailability.",
            attack_vector="HTTP flood, slow-loris, algorithmic complexity attacks, XML/JSON bombs.",
            business_impact="Service outage. SLA breach — potential penalties. "
                            "Revenue loss during downtime. Reputational damage to brand.",
            likelihood=lk, impact=3 + _pii_boost(c),
            mitigations=[
                "Implement rate limiting per IP and per authenticated user.",
                "Set request size limits and connection timeouts.",
                "Deploy CDN with DDoS protection (Cloudflare/AWS Shield) in front of service.",
                "Implement circuit breakers for downstream dependencies.",
            ],
            mitre_mappings=[MITRE["T1499"], MITRE["T1498"]],
            owasp_mappings=[OWASP["A04"], OWASP["A05"]],
            nist_controls=[NIST["CP-10"], NIST["AC-17"]],
            remediation_effort="Medium",
        ))

    if ct == ComponentType.DATABASE:
        threats.append(Threat(
            id=tid(), title=f"Database Query Exhaustion — {c.name}",
            stride_category=StrideCategory.DENIAL_OF_SERVICE, component=c.name,
            description=f"Unbounded queries or missing connection pooling limits cause {c.name} "
                        "connection exhaustion, crashing the database and all dependent services.",
            attack_vector="N+1 query loops, missing pagination, unrestricted JOIN depth.",
            business_impact="Full application outage affecting all users. Data writes lost if in-flight "
                            "transactions are rolled back. Recovery may take hours.",
            likelihood=2, impact=4,
            mitigations=[
                "Enforce query timeout limits (e.g. 30s max).",
                "Implement connection pooling (PgBouncer/HikariCP) with max pool size.",
                "Add LIMIT clauses to all paginated queries — reject unbounded requests.",
                "Monitor slow query log; alert on queries exceeding 5s.",
            ],
            mitre_mappings=[MITRE["T1499"]],
            owasp_mappings=[OWASP["A04"]],
            nist_controls=[NIST["CP-10"]],
            remediation_effort="Medium",
        ))

    # ── ELEVATION OF PRIVILEGE ────────────────────────────────────────────────
    if ct in (ComponentType.WEB_APP, ComponentType.API, ComponentType.AUTH_SERVICE):
        lk = min(5, 2 + _internet_boost(c) + _weak_auth_boost(c))
        threats.append(Threat(
            id=tid(), title=f"Broken Access Control — {c.name}",
            stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE, component=c.name,
            description=f"Insufficient authorisation checks in {c.name} allow a low-privilege user "
                        "to access or modify resources belonging to other users or perform admin actions.",
            attack_vector="Horizontal privilege escalation (IDOR), vertical escalation via role confusion, "
                          "JWT algorithm confusion attacks, mass assignment.",
            business_impact="Any user can read/modify any other user's data. Admin panel exposed to regular users. "
                            "GDPR violation if other users' PII is accessed. A01:2021 — #1 OWASP risk.",
            likelihood=lk, impact=5,
            mitigations=[
                "Enforce authorisation checks server-side for every resource access — never trust client claims.",
                "Implement RBAC/ABAC framework; deny by default.",
                "Use opaque resource IDs (UUIDs) instead of sequential integers to prevent IDOR enumeration.",
                "Validate JWT signature and algorithm server-side; reject 'alg: none'.",
                "Automated DAST scans for authorisation bypass in CI/CD.",
            ],
            mitre_mappings=[MITRE["T1548"], MITRE["T1134"]],
            owasp_mappings=[OWASP["A01"]],
            nist_controls=[NIST["AC-6"], NIST["AC-2"]],
            remediation_effort="High",
        ))

    # ── CACHE ─────────────────────────────────────────────────────────────────
    if ct == ComponentType.CACHE:
        threats.append(Threat(
            id=tid(), title=f"Cache Poisoning — {c.name}",
            stride_category=StrideCategory.TAMPERING, component=c.name,
            description=f"Attacker injects malicious entries into {c.name}, causing the application "
                        "to serve corrupted or attacker-controlled data to all users who hit the cache.",
            attack_vector="Unauthenticated cache write access, HTTP response splitting, cache key confusion.",
            business_impact="Mass data corruption served to all users. Attacker can poison auth tokens, "
                            "session data, or API responses affecting every cached request.",
            likelihood=2 + _internet_boost(c), impact=4,
            mitigations=[
                "Require authentication (password/TLS) for all cache connections — no unauthenticated Redis.",
                "Use namespaced, hard-to-guess cache keys — never derived directly from user input.",
                "Set short TTLs on sensitive cached data; purge on security-relevant events.",
            ],
            mitre_mappings=[MITRE["T1565"]],
            owasp_mappings=[OWASP["A04"]],
            nist_controls=[NIST["SC-8"], NIST["SI-10"]],
            remediation_effort="Medium",
        ))
        if c.stores_pii or c.stores_credentials:
            threats.append(Threat(
                id=tid(), title=f"Sensitive Data in Cache — {c.name}",
                stride_category=StrideCategory.INFO_DISCLOSURE, component=c.name,
                description=f"{c.name} holds sensitive data in-memory. A cache dump or memory "
                            "forensics attack exposes plaintext credentials or PII.",
                attack_vector="Redis KEYS * dump, memory forensics, persistence file (.rdb) exfiltration.",
                business_impact="Full credential or PII exposure. GDPR breach trigger. "
                                "Credential dump enables lateral movement across all systems.",
                likelihood=2, impact=5,
                mitigations=[
                    "Never cache raw credentials or unmasked PII.",
                    "Enable Redis AUTH and TLS; disable persistence (save '') for session stores.",
                    "Encrypt sensitive fields before caching; store only encrypted blobs.",
                ],
                mitre_mappings=[MITRE["T1552"], MITRE["T1213"]],
                owasp_mappings=[OWASP["A02"]],
                nist_controls=[NIST["SC-28"]],
                remediation_effort="Medium",
            ))

    # ── MESSAGE QUEUE ─────────────────────────────────────────────────────────
    if ct == ComponentType.MESSAGE_QUEUE:
        threats.append(Threat(
            id=tid(), title=f"Message Injection / Replay — {c.name}",
            stride_category=StrideCategory.TAMPERING, component=c.name,
            description=f"Unauthenticated producers inject malicious messages into {c.name}, "
                        "or replay captured messages to trigger duplicate or out-of-order processing.",
            attack_vector="Unauthenticated broker access, SSRF to internal broker, captured message replay.",
            business_impact="Malicious commands executed by consumers, duplicate financial transactions, "
                            "state corruption in downstream services.",
            likelihood=2 + _internet_boost(c), impact=4,
            mitigations=[
                "Require SASL/TLS authentication for all producers and consumers.",
                "Implement message signing (HMAC) to detect tampered payloads.",
                "Assign per-service ACLs — producers cannot consume, consumers cannot produce to other topics.",
                "Include idempotency keys and timestamps; reject replays outside allowed window.",
            ],
            mitre_mappings=[MITRE["T1565"], MITRE["T1078"]],
            owasp_mappings=[OWASP["A08"]],
            nist_controls=[NIST["IA-2"], NIST["SC-8"]],
            remediation_effort="Medium",
        ))
        threats.append(Threat(
            id=tid(), title=f"Queue Flooding / DoS — {c.name}",
            stride_category=StrideCategory.DENIAL_OF_SERVICE, component=c.name,
            description=f"Attacker floods {c.name} with high-volume or oversized messages, "
                        "exhausting broker memory/disk and starving legitimate consumers.",
            attack_vector="Unauthenticated producer publishing, compromised internal service.",
            business_impact="All downstream consumers blocked; async pipeline halted. "
                            "Cascading failure across all services consuming from the broker.",
            likelihood=2, impact=4,
            mitigations=[
                "Set per-producer publish rate limits and max message size limits at the broker.",
                "Configure broker disk/memory quotas per topic/queue.",
                "Monitor consumer lag; alert when lag exceeds SLA threshold.",
            ],
            mitre_mappings=[MITRE["T1499"]],
            owasp_mappings=[OWASP["A04"]],
            nist_controls=[NIST["CP-10"]],
            remediation_effort="Medium",
        ))

    # ── LOAD BALANCER ─────────────────────────────────────────────────────────
    if ct == ComponentType.LOAD_BALANCER:
        threats.append(Threat(
            id=tid(), title=f"Header Injection / IP Spoofing — {c.name}",
            stride_category=StrideCategory.SPOOFING, component=c.name,
            description=f"Attacker manipulates X-Forwarded-For or X-Real-IP headers at {c.name}, "
                        "causing backend services to trust a spoofed source IP for rate limiting, "
                        "geo-blocking, or access control decisions.",
            attack_vector="Direct backend access bypassing the LB, crafted headers on LB-facing requests.",
            business_impact="Rate limit bypass, IP allowlist evasion, false attribution in audit logs. "
                            "Attacker accesses geo-restricted resources or bypasses IP-based MFA.",
            likelihood=2 + _internet_boost(c), impact=3,
            mitigations=[
                "Strip and re-set X-Forwarded-For at the LB — never trust client-supplied values.",
                "Block direct backend access — all traffic must route through the LB.",
                "Use signed request headers for LB-to-backend service authentication.",
            ],
            mitre_mappings=[MITRE["T1078"], MITRE["T1190"]],
            owasp_mappings=[OWASP["A05"]],
            nist_controls=[NIST["SC-8"], NIST["AC-17"]],
            remediation_effort="Low",
        ))
        threats.append(Threat(
            id=tid(), title=f"TLS Termination Plaintext Exposure — {c.name}",
            stride_category=StrideCategory.INFO_DISCLOSURE, component=c.name,
            description=f"{c.name} terminates TLS and forwards plaintext to backends. "
                        "An attacker with access to the internal network can capture all decrypted traffic.",
            attack_vector="Internal network interception, ARP poisoning between LB and backend services.",
            business_impact="Full plaintext exposure of all user traffic, including credentials and PII, "
                            "between the load balancer and backend services.",
            likelihood=2, impact=4,
            mitigations=[
                "Re-encrypt LB-to-backend traffic (end-to-end TLS or mTLS).",
                "Segment the backend network; restrict LB-to-backend traffic to a dedicated VLAN.",
            ],
            mitre_mappings=[MITRE["T1552"]],
            owasp_mappings=[OWASP["A02"]],
            nist_controls=[NIST["SC-8"]],
            remediation_effort="Medium",
        ))

    # ── CDN ───────────────────────────────────────────────────────────────────
    if ct == ComponentType.CDN:
        threats.append(Threat(
            id=tid(), title=f"CDN Cache Poisoning — {c.name}",
            stride_category=StrideCategory.TAMPERING, component=c.name,
            description=f"Attacker exploits cache key ambiguity or unkeyed headers at {c.name} "
                        "to poison cached responses, serving malicious content globally to all edge users.",
            attack_vector="HTTP request smuggling, unkeyed header injection (X-Forwarded-Host), "
                          "cache deception via path confusion.",
            business_impact="Malicious responses served globally at CDN scale. "
                            "XSS payload delivery or credential-harvesting pages to all users.",
            likelihood=2, impact=4,
            mitigations=[
                "Include all security-relevant headers in the CDN cache key.",
                "Normalise and strip ambiguous request headers at the CDN edge.",
                "Monitor for unexpected response size or content-type changes in cached objects.",
            ],
            mitre_mappings=[MITRE["T1565"], MITRE["T1190"]],
            owasp_mappings=[OWASP["A05"]],
            nist_controls=[NIST["SC-8"], NIST["SI-10"]],
            remediation_effort="Medium",
        ))
        threats.append(Threat(
            id=tid(), title=f"Private Content Served via CDN — {c.name}",
            stride_category=StrideCategory.INFO_DISCLOSURE, component=c.name,
            description=f"Misconfigured caching rules at {c.name} cause authenticated or private content "
                        "to be cached and served to unauthenticated users.",
            attack_vector="Missing Vary/Cache-Control headers; CDN caching authenticated API responses.",
            business_impact="User PII, session data, or proprietary content served publicly. "
                            "GDPR breach trigger. Mass data exposure at CDN edge scale.",
            likelihood=2, impact=4,
            mitigations=[
                "Set Cache-Control: no-store on all authenticated or personalised responses.",
                "Configure CDN to respect Vary: Authorization; never cache responses with Set-Cookie.",
                "Audit CDN cache rules quarterly; probe with unauthenticated requests against private endpoints.",
            ],
            mitre_mappings=[MITRE["T1530"]],
            owasp_mappings=[OWASP["A01"]],
            nist_controls=[NIST["AC-6"], NIST["SC-28"]],
            remediation_effort="Low",
        ))

    # ── EXTERNAL SERVICE ──────────────────────────────────────────────────────
    if ct == ComponentType.EXTERNAL_SERVICE:
        threats.append(Threat(
            id=tid(), title=f"Supply Chain Compromise — {c.name}",
            stride_category=StrideCategory.TAMPERING, component=c.name,
            description=f"Third-party service {c.name} is compromised or returns malicious payloads. "
                        "Implicit trust in external responses propagates attacker-controlled data into internal systems.",
            attack_vector="Vendor breach, BGP hijack, DNS poisoning redirecting to attacker-controlled endpoint.",
            business_impact="Attacker-controlled data executed within internal systems via a trusted dependency. "
                            "Similar breach vector to SolarWinds; full compromise possible.",
            likelihood=2, impact=4,
            mitigations=[
                "Validate and sanitise all external API responses — never treat them as trusted internal data.",
                "Pin TLS certificates for critical external dependencies; alert on certificate changes.",
                "Implement circuit breakers: fail safe if external service behaves anomalously.",
                "Monitor vendor security advisories; maintain a documented vendor-breach response plan.",
            ],
            mitre_mappings=[MITRE["T1195"], MITRE["T1574"]],
            owasp_mappings=[OWASP["A08"]],
            nist_controls=[NIST["SI-2"], NIST["SC-8"]],
            remediation_effort="Medium",
        ))
        if c.stores_pii:
            threats.append(Threat(
                id=tid(), title=f"PII Transmitted to Third Party — {c.name}",
                stride_category=StrideCategory.INFO_DISCLOSURE, component=c.name,
                description=f"PII or sensitive data is transmitted to external service {c.name}. "
                            "GDPR data processor obligations apply once data leaves the trust boundary.",
                attack_vector="Oversharing in API request bodies, external service logging of PII fields.",
                business_impact="GDPR Art. 28 obligations triggered. Third-party breach exposes your users' data. "
                                "Loss of data residency control. Fines up to 4% global turnover.",
                likelihood=3, impact=4,
                mitigations=[
                    "Data minimisation: send only the minimum fields required by the external API.",
                    "Ensure a signed DPA (Data Processing Agreement) exists with all PII-processing vendors.",
                    "Audit outbound request bodies in staging; redact PII fields in external service logs.",
                ],
                mitre_mappings=[MITRE["T1213"]],
                owasp_mappings=[OWASP["A01"]],
                nist_controls=[NIST["AC-6"], NIST["SC-28"]],
                remediation_effort="Low",
            ))

    # ── MOBILE APP ────────────────────────────────────────────────────────────
    if ct == ComponentType.MOBILE_APP:
        threats.append(Threat(
            id=tid(), title=f"Certificate Pinning Bypass — {c.name}",
            stride_category=StrideCategory.SPOOFING, component=c.name,
            description=f"Attacker intercepts {c.name} traffic by bypassing certificate pinning via "
                        "Frida/Objection or custom CA install, enabling MitM interception of all API calls.",
            attack_vector="Rooted/jailbroken device, Frida dynamic instrumentation, custom CA injection.",
            business_impact="Full plaintext interception of all API traffic including credentials and session tokens. "
                            "Attacker can replay or modify requests on behalf of any user.",
            likelihood=2 + _internet_boost(c), impact=4,
            mitigations=[
                "Implement certificate pinning with multi-pin backup via network_security_config (Android) "
                "or NSAppTransportSecurity (iOS).",
                "Detect rooted/jailbroken devices at runtime; block or warn before sensitive operations.",
                "Obfuscate pinning logic; rotate pins via remote config with short validity windows.",
            ],
            mitre_mappings=[MITRE["T1552"], MITRE["T1539"]],
            owasp_mappings=[OWASP["A02"]],
            nist_controls=[NIST["SC-8"], NIST["IA-2"]],
            remediation_effort="Medium",
        ))
        threats.append(Threat(
            id=tid(), title=f"Insecure Local Storage — {c.name}",
            stride_category=StrideCategory.INFO_DISCLOSURE, component=c.name,
            description=f"{c.name} may store session tokens, credentials, or PII in plaintext "
                        "in local storage, SQLite databases, or SharedPreferences.",
            attack_vector="Physical device access, ADB backup extraction, "
                          "malicious app with READ_EXTERNAL_STORAGE permission.",
            business_impact="Credential theft from physical device access. Mass account takeover "
                            "if device is lost, stolen, or submitted for repair.",
            likelihood=2 + _pii_boost(c), impact=4,
            mitigations=[
                "Use Android Keystore / iOS Keychain for all credentials and tokens — never SharedPreferences.",
                "Encrypt SQLite databases with SQLCipher.",
                "Disable Android backup for sensitive app data (android:allowBackup=\"false\").",
            ],
            mitre_mappings=[MITRE["T1552"], MITRE["T1213"]],
            owasp_mappings=[OWASP["A02"]],
            nist_controls=[NIST["SC-28"]],
            remediation_effort="Medium",
        ))

    # ── WORKER ────────────────────────────────────────────────────────────────
    if ct == ComponentType.WORKER:
        threats.append(Threat(
            id=tid(), title=f"Malicious Job Injection — {c.name}",
            stride_category=StrideCategory.TAMPERING, component=c.name,
            description=f"Attacker injects malicious payloads into jobs consumed by {c.name}, "
                        "exploiting unsanitised job arguments to achieve RCE or data corruption.",
            attack_vector="Compromised job producer, unauthenticated queue access, "
                          "SSRF triggering internal job enqueue endpoints.",
            business_impact="Remote code execution in the worker environment. "
                            "If the worker holds elevated permissions (DB admin, cloud IAM), full system compromise.",
            likelihood=2, impact=4 + _internet_boost(c),
            mitigations=[
                "Validate and sanitise all job payload fields before processing — treat as untrusted input.",
                "Run workers with least-privilege service accounts; no interactive login capability.",
                "Authenticate job producers; reject jobs from unauthenticated sources.",
            ],
            mitre_mappings=[MITRE["T1059"], MITRE["T1548"]],
            owasp_mappings=[OWASP["A03"], OWASP["A01"]],
            nist_controls=[NIST["SI-10"], NIST["AC-6"]],
            remediation_effort="Medium",
        ))
        threats.append(Threat(
            id=tid(), title=f"Worker Privilege Escalation — {c.name}",
            stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE, component=c.name,
            description=f"{c.name} processes background jobs, often with elevated permissions to access "
                        "databases, cloud APIs, or file systems. Compromise grants attacker those permissions.",
            attack_vector="Deserialization vulnerability in job payload, dependency confusion in worker image, "
                          "insecure job parameter handling.",
            business_impact="Attacker inherits all permissions of the worker process — "
                            "potentially DB admin, cloud IAM, or file system write access across the system.",
            likelihood=2, impact=4,
            mitigations=[
                "Scope worker IAM roles to minimum required — read-only where possible.",
                "Run each worker type in an isolated container with no shared credentials.",
                "Use AWS IAM task roles / Kubernetes service accounts scoped per worker type.",
            ],
            mitre_mappings=[MITRE["T1548"], MITRE["T1574"]],
            owasp_mappings=[OWASP["A01"]],
            nist_controls=[NIST["AC-6"], NIST["IA-2"]],
            remediation_effort="Medium",
        ))

    return threats


def generate_dataflow_threats(df: DataFlow, idx: int) -> list[Threat]:
    """Generate threats for unencrypted or cross-boundary data flows."""
    threats: list[Threat] = []
    prefix = f"DF{idx:03d}"
    n = 0

    def tid() -> str:
        nonlocal n
        n += 1
        return f"{prefix}-{n:02d}"

    if not df.encrypted:
        threats.append(Threat(
            id=tid(),
            title=f"Unencrypted Data Flow — {df.source} → {df.destination}",
            stride_category=StrideCategory.INFO_DISCLOSURE,
            component=f"{df.source} → {df.destination}",
            description=f"Data flow '{df.name}' transmits {df.data_classification} data in plaintext "
                        f"over {df.protocol}. Network-positioned attacker can capture and read all traffic.",
            attack_vector="Man-in-the-middle attack, network tap, ARP poisoning on internal segments.",
            business_impact=(
                "Full plaintext exposure of all transmitted data. "
                "If confidential/restricted: immediate GDPR breach trigger. "
                "Credentials in transit = complete system compromise."
            ),
            likelihood=3 if df.crosses_trust_boundary else 2,
            impact=5 if df.data_classification in ("confidential", "restricted") else 3,
            mitigations=[
                f"Upgrade {df.protocol} to TLS 1.2+ minimum; enforce TLS 1.3 where possible.",
                "Implement mutual TLS (mTLS) for service-to-service flows.",
                "Disable HTTP fallback; HSTS with 1-year max-age.",
            ],
            mitre_mappings=[MITRE["T1552"]],
            owasp_mappings=[OWASP["A02"]],
            nist_controls=[NIST["SC-8"]],
            remediation_effort="Low",
        ))

    if df.crosses_trust_boundary and not df.authenticated:
        threats.append(Threat(
            id=tid(),
            title=f"Unauthenticated Cross-Boundary Flow — {df.source} → {df.destination}",
            stride_category=StrideCategory.SPOOFING,
            component=f"{df.source} → {df.destination}",
            description=f"Data flow '{df.name}' crosses a trust boundary without authentication. "
                        "Any system in the source network can send data to the destination.",
            attack_vector="Rogue service impersonation, SSRF pivoting through internal trust.",
            business_impact="Attacker can inject arbitrary data into trusted downstream systems, "
                            "trigger actions as an implicitly trusted internal service.",
            likelihood=3, impact=4,
            mitigations=[
                "Enforce service-to-service authentication (mTLS, signed JWTs, HMAC).",
                "Treat all cross-boundary traffic as untrusted — validate and sanitise at receiver.",
                "Network segmentation: firewall rules allowing only expected source IPs.",
            ],
            mitre_mappings=[MITRE["T1078"]],
            owasp_mappings=[OWASP["A07"]],
            nist_controls=[NIST["AC-17"], NIST["IA-2"]],
            remediation_effort="Medium",
        ))

    return threats


def run_stride(app: ApplicationDescriptor) -> list[Threat]:
    """Run full STRIDE analysis across all components and data flows."""
    threats: list[Threat] = []
    for i, component in enumerate(app.components, start=1):
        threats.extend(generate_component_threats(component, i))
    for j, flow in enumerate(app.data_flows, start=1):
        threats.extend(generate_dataflow_threats(flow, j))
    # Parser-attached threats (e.g. Terraform config-level: public S3, IAM *).
    # ponytail: single sidecar attribute is simpler than a parser-rules plugin bus.
    threats.extend(getattr(app, "terraform_threats", []) or [])
    return threats
