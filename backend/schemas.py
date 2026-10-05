"""The report contract shared by parsing, policy, UI and exports."""
from typing import Any, Literal
from pydantic import BaseModel, Field


class Evidence(BaseModel):
    id: str
    packet_index: int
    timestamp: float
    field: str
    value: Any


class Fact(BaseModel):
    name: str
    value: Any = None
    scope: str = "ike_sa"
    status: Literal["observed", "selected_observed", "offered_only", "unknown"]
    evidence_refs: list[str] = Field(default_factory=list)
    reason: str = ""


class Transform(BaseModel):
    type_id: int
    transform_id: int
    name: str
    key_bits: int | None = None
    attributes: list[dict] = Field(default_factory=list)


class Proposal(BaseModel):
    number: int
    protocol_id: int
    spi: str
    transforms: list[Transform]
    evidence_ref: str


class Session(BaseModel):
    id: str
    initiator: str
    responder: str
    initiator_spi: str
    responder_spi: str
    version: str
    interface: str = "0"
    transport_observations: list[dict] = Field(default_factory=list)
    exchanges: list[str] = Field(default_factory=list)
    message_ids: list[int] = Field(default_factory=list)
    offered: list[Proposal] = Field(default_factory=list)
    selected: list[Proposal] = Field(default_factory=list)
    selection_status: str = "unknown"
    selection_reason: str = "No usable responder-selected IKE suite in the capture."
    retransmissions: int = 0
    facts: list[Fact] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class Stream(BaseModel):
    id: str
    source: str
    destination: str
    spi: str
    interface: str
    encapsulation: str
    packets: int = 0
    bytes: int = 0
    first_timestamp: float
    last_timestamp: float
    first_sequence: int
    last_sequence: int
    duplicate_sequences: int = 0
    out_of_order: int = 0
    evidence_refs: list[str] = Field(default_factory=list)
    facts: list[Fact] = Field(default_factory=list)


class Finding(BaseModel):
    rule_id: str
    target_id: str
    scope: str
    status: Literal["PASS", "FAIL", "UNKNOWN", "ADVISORY", "NOT_APPLICABLE"]
    severity: str
    rationale: str
    remediation: str
    evidence_refs: list[str] = Field(default_factory=list)
    policy_source: str
    scored: bool = True


class Assessment(BaseModel):
    risk_score: int | None = None
    rating: str = "Insufficient evidence"
    coverage_percent: float = 0
    evaluated_rules: int = 0
    unknown_rules: int = 0
    applicable_rules: int = 0
    scope: str = "Observed IKE SA settings; full VPN configuration remains partial"
    policy_version: str
    target_scores: dict[str, int | None] = Field(default_factory=dict)
    note: str = "Project-defined risk score, not CVSS or a compliance certification."


class InputSummary(BaseModel):
    filename: str
    format: str
    byte_size: int
    packets: int = 0
    ike_packets: int = 0
    esp_packets: int = 0
    keepalives: int = 0
    other_packets: int = 0
    skipped_packets: int = 0
    first_timestamp: float | None = None
    last_timestamp: float | None = None
    duration_seconds: float = 0
    link_types: list[int] = Field(default_factory=list)
    endpoint_pairs: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class Analysis(BaseModel):
    id: str
    schema_version: str = "1.1"
    created_at: str
    input_sha256: str
    source_kind: str
    summary: InputSummary
    ike_sessions: list[Session]
    esp_streams: list[Stream]
    evidence: list[Evidence]
    findings: list[Finding]
    assessment: Assessment
    inference: dict = Field(default_factory=lambda: {
        "method": "unavailable", "result": "UNKNOWN", "model_score": None,
        "reason": "Tier A has no trained traffic classifier. ESP content remains encrypted.",
    })
    executive_summary: str
    limitations: list[str]
