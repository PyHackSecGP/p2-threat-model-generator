"""Data models for P2 Threat Model Generator."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ComponentType(str, Enum):
    WEB_APP = "web_app"
    API = "api"
    DATABASE = "database"
    AUTH_SERVICE = "auth_service"
    MESSAGE_QUEUE = "message_queue"
    CACHE = "cache"
    STORAGE = "storage"
    CDN = "cdn"
    LOAD_BALANCER = "load_balancer"
    EXTERNAL_SERVICE = "external_service"
    MOBILE_APP = "mobile_app"
    WORKER = "worker"
    GENERIC = "generic"


class StrideCategory(str, Enum):
    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFO_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class AuthType(str, Enum):
    NONE = "none"
    API_KEY = "api_key"
    JWT = "jwt"
    OAUTH2 = "oauth2"
    BASIC = "basic"
    MTLS = "mtls"
    SESSION = "session"


@dataclass
class DataFlow:
    name: str
    source: str
    destination: str
    data_classification: str = "internal"  # public, internal, confidential, restricted
    encrypted: bool = True
    authenticated: bool = True
    crosses_trust_boundary: bool = False
    protocol: str = "HTTPS"
    notes: str = ""


@dataclass
class TrustBoundary:
    name: str
    components: list[str] = field(default_factory=list)
    description: str = ""


@dataclass
class Component:
    name: str
    type: ComponentType = ComponentType.GENERIC
    description: str = ""
    technology: str = ""
    auth_type: AuthType = AuthType.NONE
    stores_pii: bool = False
    stores_credentials: bool = False
    internet_facing: bool = False
    has_logging: bool = True
    has_rate_limiting: bool = False
    trust_boundary: str = ""
    notes: str = ""


@dataclass
class MitreMapping:
    technique_id: str
    technique_name: str
    tactic: str
    url: str = ""


@dataclass
class OwaspMapping:
    category_id: str
    category_name: str
    year: int = 2021


@dataclass
class NistControl:
    control_id: str
    control_name: str
    family: str


@dataclass
class Threat:
    id: str
    title: str
    stride_category: StrideCategory
    component: str
    description: str
    attack_vector: str
    business_impact: str
    likelihood: int           # 1-5
    impact: int               # 1-5
    risk_score: float = 0.0   # computed: likelihood * impact * 4
    severity: Severity = Severity.MEDIUM
    mitigations: list[str] = field(default_factory=list)
    mitre_mappings: list[MitreMapping] = field(default_factory=list)
    owasp_mappings: list[OwaspMapping] = field(default_factory=list)
    nist_controls: list[NistControl] = field(default_factory=list)
    llm_narrative: str = ""
    remediation_effort: str = "Medium"  # Low, Medium, High
    sprint_priority: int = 2            # 1=immediate, 2=this quarter, 3=backlog

    def __post_init__(self) -> None:
        self.risk_score = round(self.likelihood * self.impact * 4, 1)
        if self.risk_score >= 80:
            self.severity = Severity.CRITICAL
            self.sprint_priority = 1
        elif self.risk_score >= 50:
            self.severity = Severity.HIGH
            self.sprint_priority = 1
        elif self.risk_score >= 25:
            self.severity = Severity.MEDIUM
            self.sprint_priority = 2
        elif self.risk_score >= 10:
            self.severity = Severity.LOW
            self.sprint_priority = 3
        else:
            self.severity = Severity.INFO
            self.sprint_priority = 3


@dataclass
class ComplianceFlag:
    framework: str
    requirement: str
    threat_ids: list[str]
    description: str


@dataclass
class ApplicationDescriptor:
    name: str
    version: str = "1.0"
    description: str = ""
    owner: str = ""
    team: str = ""
    environment: str = "production"
    internet_facing: bool = True
    data_classification: str = "confidential"
    components: list[Component] = field(default_factory=list)
    data_flows: list[DataFlow] = field(default_factory=list)
    trust_boundaries: list[TrustBoundary] = field(default_factory=list)
    compliance_frameworks: list[str] = field(default_factory=list)  # gdpr, pci_dss, soc2, hipaa


@dataclass
class ThreatModel:
    app: ApplicationDescriptor
    threats: list[Threat] = field(default_factory=list)
    compliance_flags: list[ComplianceFlag] = field(default_factory=list)
    overall_risk_score: float = 0.0
    generated_at: str = ""
    analyst: str = "P2 Threat Model Generator"

    @property
    def critical_threats(self) -> list[Threat]:
        return [t for t in self.threats if t.severity == Severity.CRITICAL]

    @property
    def high_threats(self) -> list[Threat]:
        return [t for t in self.threats if t.severity == Severity.HIGH]

    @property
    def medium_threats(self) -> list[Threat]:
        return [t for t in self.threats if t.severity == Severity.MEDIUM]

    @property
    def low_threats(self) -> list[Threat]:
        return [t for t in self.threats if t.severity in (Severity.LOW, Severity.INFO)]

    @property
    def sprint1_threats(self) -> list[Threat]:
        return sorted(
            [t for t in self.threats if t.sprint_priority == 1],
            key=lambda x: x.risk_score, reverse=True,
        )

    @property
    def stride_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {c.value: 0 for c in StrideCategory}
        for t in self.threats:
            counts[t.stride_category.value] += 1
        return counts
