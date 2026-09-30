from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class CertificateDetails(BaseModel):
    subject: str = "NOT OBSERVABLE"
    issuer: str = "NOT OBSERVABLE"
    valid_from: str = "NOT OBSERVABLE"
    valid_until: str = "NOT OBSERVABLE"
    is_expired: bool = False
    is_not_yet_valid: bool = False
    is_self_signed: bool = False
    public_key_algorithm: str = "NOT OBSERVABLE"
    key_length: str = "NOT OBSERVABLE"
    signature_algorithm: str = "NOT OBSERVABLE"
    certificate_status: str = "NOT OBSERVABLE"  # VALID, EXPIRED, NOT_YET_VALID, WEAK_KEY, WEAK_SIGNATURE, SELF_SIGNED, NOT OBSERVABLE
    san_list: List[str] = Field(default_factory=list)
    fingerprint_sha256: str = "NOT OBSERVABLE"

class Finding(BaseModel):
    id: str
    rule_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    protocol: str  # SMTP, IMAP, POP3, TLS
    evidence_id: str
    evidence_filename: str
    session_id: str
    detected_at: str
    status: str = "DETECTED"
    description: str
    why_it_matters: str
    technical_details: str
    recommendation: str

class EvidenceChainNode(BaseModel):
    step: str
    title: str
    status: str  # "secure", "warning", "critical", "neutral"
    details: str
    technical_props: Dict[str, Any] = Field(default_factory=dict)

class NetworkDetails(BaseModel):
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    packet_count: int
    session_duration: float
    start_time: str
    end_time: str

class TLSDetails(BaseModel):
    tls_detected: bool = False
    tls_version: str = "NOT OBSERVABLE"
    cipher_suite: str = "NOT OBSERVABLE"
    cipher_code: Optional[str] = None
    key_exchange: str = "NOT OBSERVABLE"
    forward_secrecy: str = "NOT OBSERVABLE"  # SUPPORTED, NOT SUPPORTED, NOT OBSERVABLE
    handshake_status: str = "NOT OBSERVABLE"  # COMPLETED, FAILED, INCOMPLETE, NOT OBSERVABLE
    alpn: str = "NOT OBSERVABLE"
    sni: str = "NOT OBSERVABLE"

class SessionRecord(BaseModel):
    session_id: str
    evidence_id: str
    evidence_filename: str
    protocol: str  # SMTP, IMAP, POP3
    network: NetworkDetails
    starttls_detected: bool = False
    starttls_status: str = "NOT OBSERVABLE"  # OFFERED_AND_ACCEPTED, OFFERED_NOT_UPGRADED, NOT_OFFERED, NOT OBSERVABLE
    tls: TLSDetails = Field(default_factory=TLSDetails)
    certificate: CertificateDetails = Field(default_factory=CertificateDetails)
    risk_level: str = "SECURE"  # CRITICAL, HIGH, MEDIUM, LOW, SECURE
    risk_score: int = 0
    findings: List[Finding] = Field(default_factory=list)
    evidence_chain: List[EvidenceChainNode] = Field(default_factory=list)

class EvidenceRecord(BaseModel):
    id: str
    filename: str
    file_size_bytes: int
    file_size_display: str
    sha256: str
    uploaded_at: str
    analysis_status: str  # UPLOADED, PROCESSING, ANALYZED, FAILED
    error_message: Optional[str] = None
    session_count: int = 0
    finding_count: int = 0
    risk_score: int = 0
    risk_level: str = "SECURE"
    protocols_found: List[str] = Field(default_factory=list)

class ContributingFactor(BaseModel):
    factor: str
    points: int
    severity: str
    details: str
    count: int = 1

class RiskPosture(BaseModel):
    overall_score: int
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, SECURE
    contributing_factors: List[ContributingFactor]
    risk_distribution: Dict[str, int]
    risk_by_protocol: Dict[str, int]
    risk_by_evidence: List[Dict[str, Any]]

class OverviewMetrics(BaseModel):
    total_evidence: int
    total_sessions: int
    at_risk_sessions: int
    high_critical_findings: int
    total_findings: int = 0
    risk_distribution: Dict[str, int]
    protocol_distribution: Dict[str, int]
    tls_distribution: Dict[str, int]
    cert_health_distribution: Dict[str, int]
    recent_findings: List[Finding]

class ReportRecord(BaseModel):
    id: str
    evidence_id: str
    evidence_filename: str
    generated_at: str
    formats: List[str]  # ["JSON", "HTML", "PDF"]
    risk_score: int
    risk_level: str
    session_count: int
    finding_count: int

class SystemStatus(BaseModel):
    app_version: str = "1.0.0-prototype"
    analyzer_version: str = "2.4.0-forensics-core"
    max_upload_size_mb: int = 100
    engine_status: str = "READY"
    tshark_status: str = "NOT DETECTED (FALLBACK TO BUILTIN PURE PYTHON PCAP/PCAPNG ENGINE)"
    openssl_status: str = "BUILTIN CRYPTOGRAPHY (OpenSSL 3.x bindings available via PyCA)"
    database_status: str = "CONNECTED (Forensic In-Memory / File SQLite)"
    forensic_mode: str = "STRICT_PASSIVE_PCAP"
