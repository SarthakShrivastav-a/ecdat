"""Core data model. Collectors emit RawFinding; merge turns them into CryptoAsset; every later
layer reads and annotates CryptoAsset only. All objects serialise with to_dict()."""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

Confidence = Literal["high", "medium", "low"]
AssetType = Literal["algorithm", "certificate", "protocol", "related-crypto-material", "library"]

CONF_ORDER = {"low": 0, "medium": 1, "high": 2}


def _clean(obj: Any) -> Any:
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: _clean(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_clean(v) for v in obj]
    if isinstance(obj, datetime):
        return obj.isoformat()
    return obj


class _Dictable:
    def to_dict(self) -> dict:
        return _clean(self)


@dataclass
class Evidence(_Dictable):
    collector: str
    location: str
    line: int | None = None
    snippet: str | None = None
    confidence: Confidence = "medium"
    context: dict = field(default_factory=dict)


@dataclass
class RawFinding(_Dictable):
    collector: str
    asset_type: AssetType
    name: str                       # raw name as seen ("rsa", "sha256WithRSAEncryption", CN, "TLS")
    location: str
    line: int | None = None
    snippet: str | None = None
    confidence: Confidence = "medium"
    component: str = "unknown"
    props: dict = field(default_factory=dict)     # key_size, mode, padding, cert fields, cipher suites...
    context: dict = field(default_factory=dict)   # is_test, is_vendored, in_comment, zone, best_effort...

    def evidence(self) -> Evidence:
        return Evidence(self.collector, self.location, self.line, self.snippet, self.confidence, dict(self.context))


@dataclass
class Component(_Dictable):
    bom_ref: str
    name: str
    type: str = "application"       # application | library | container | file | device
    version: str | None = None
    zone: str = "internal"          # internal | external
    data_class: str | None = None
    criticality: str | None = None  # low | medium | high | critical
    path: str | None = None
    props: dict = field(default_factory=dict)


@dataclass
class AgilityScore(_Dictable):
    dimensions: dict = field(default_factory=dict)   # name -> 0..1 (1 = rigid)
    total: int = 50                                   # 0..100 (100 = fully agile)
    y_years: float = 3.0
    reasons: list = field(default_factory=list)


@dataclass
class RiskAssessment(_Dictable):
    quantum_class: str = "unknown"      # broken | weakened | legacy-broken | safe | unknown
    reason: str = ""
    hndl_applicable: bool = False
    x: float = 0.0
    y: float = 0.0
    z: float = 0.0
    mosca_gap: float = 0.0
    tier: str = "MONITOR"               # EXPOSED | ACT_NOW | MONITOR | SAFE
    priority: float = 0.0
    deadline_year: int | None = None
    overlays: list = field(default_factory=list)
    reasons: list = field(default_factory=list)


@dataclass
class Recommendation(_Dictable):
    target: str | None = None
    alternative: str | None = None
    cnsa_target: str | None = None
    fips: list = field(default_factory=list)
    deltas: dict = field(default_factory=dict)
    runtime_note: str = ""
    effort_weeks: float = 0.0
    hybrid: bool = False
    rationale: str = ""
    patches: list = field(default_factory=list)


@dataclass
class CryptoAsset(_Dictable):
    bom_ref: str
    asset_type: AssetType
    name: str                          # canonical ("RSA", "AES-256", CN for certs, "TLS")
    family: str | None = None
    primitive: str | None = None       # CycloneDX primitive enum
    key_size: int | None = None
    mode: str | None = None
    padding: str | None = None
    oid: str | None = None
    parameter_set: str | None = None
    curve: str | None = None
    crypto_functions: list = field(default_factory=list)
    classical_security_level: int | None = None
    nist_quantum_security_level: int | None = None
    component: str = "unknown"
    provided_by: str | None = None
    confidence: Confidence = "medium"
    evidence: list = field(default_factory=list)   # list[Evidence]
    props: dict = field(default_factory=dict)      # cert / protocol / key details
    context: dict = field(default_factory=dict)    # usage, is_test, corroborated, best_effort ...
    exposure: dict = field(default_factory=dict)
    lifetime_years: float | None = None
    data_class: str | None = None
    criticality: str | None = None
    criticality_multiplier: float = 1.0
    agility: AgilityScore | None = None
    risk: RiskAssessment | None = None
    recommendation: Recommendation | None = None
    vex: str = "in_triage"                         # affected | not_affected | resolved | in_triage
    certin: dict = field(default_factory=dict)

    @property
    def collectors(self) -> set[str]:
        return {e.collector for e in self.evidence}


@dataclass
class ScanParams(_Dictable):
    z_year: int = 2041
    y_default: float = 3.0
    engineers: int = 4
    months: int = 6
    profile: str = "cii"           # cii | enterprise
    now_year: int = 2026
    passwords: list = field(default_factory=lambda: ["", "changeit", "password", "zoo", "zoopass"])
    use_external_tools: bool = True

    @property
    def z_years(self) -> float:
        return float(self.z_year - self.now_year)


@dataclass
class ScanResult(_Dictable):
    name: str = "scan"
    targets: list = field(default_factory=list)
    components: list = field(default_factory=list)
    assets: list = field(default_factory=list)
    params: ScanParams = field(default_factory=ScanParams)
    stats: dict = field(default_factory=dict)
    plan: dict = field(default_factory=dict)
    tool_versions: dict = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    id: str = ""


def bump(conf: Confidence, up: int = 1) -> Confidence:
    order = ["low", "medium", "high"]
    return order[min(2, order.index(conf) + up)]
