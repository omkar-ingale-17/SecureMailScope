export interface NetworkDetails {
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  packet_count: number;
  session_duration: number;
  start_time: string;
  end_time: string;
}

export interface TLSDetails {
  tls_detected: boolean;
  tls_version: string;
  cipher_suite: string;
  cipher_code?: string | null;
  key_exchange: string;
  forward_secrecy: string;
  handshake_status: string;
  alpn: string;
  sni: string;
}

export interface CertificateDetails {
  subject: string;
  issuer: string;
  valid_from: string;
  valid_until: string;
  is_expired: boolean;
  is_not_yet_valid: boolean;
  is_self_signed: boolean;
  public_key_algorithm: string;
  key_length: string;
  signature_algorithm: string;
  certificate_status: string;
  san_list: string[];
  fingerprint_sha256: string;
}

export interface Finding {
  id: string;
  rule_id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  title: string;
  protocol: string;
  evidence_id: string;
  evidence_filename: string;
  session_id: string;
  detected_at: string;
  status: string;
  description: string;
  why_it_matters: string;
  technical_details: string;
  recommendation: string;
}

export interface EvidenceChainNode {
  step: string;
  title: string;
  status: 'secure' | 'warning' | 'critical' | 'neutral';
  details: string;
  technical_props: Record<string, any>;
}

export interface SessionRecord {
  session_id: string;
  evidence_id: string;
  evidence_filename: string;
  protocol: 'SMTP' | 'IMAP' | 'POP3' | string;
  network: NetworkDetails;
  starttls_detected: boolean;
  starttls_status: string;
  tls: TLSDetails;
  certificate: CertificateDetails;
  risk_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SECURE';
  risk_score: number;
  findings: Finding[];
  evidence_chain: EvidenceChainNode[];
}

export interface EvidenceRecord {
  id: string;
  filename: string;
  file_size_bytes: number;
  file_size_display: string;
  sha256: string;
  uploaded_at: string;
  analysis_status: 'UPLOADED' | 'PROCESSING' | 'ANALYZED' | 'FAILED';
  error_message?: string | null;
  session_count: number;
  finding_count: number;
  risk_score: number;
  risk_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SECURE';
  protocols_found: string[];
}

export interface ContributingFactor {
  factor: string;
  points: number;
  severity: string;
  details: string;
  count: number;
}

export interface RiskPosture {
  overall_score: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SECURE';
  contributing_factors: ContributingFactor[];
  risk_distribution: Record<string, number>;
  risk_by_protocol: Record<string, number>;
  risk_by_evidence: Array<{
    evidence_id: string;
    filename: string;
    score: number;
    severity: string;
    session_count: number;
    finding_count: number;
  }>;
}

export interface OverviewMetrics {
  total_evidence: number;
  total_sessions: number;
  at_risk_sessions: number;
  high_critical_findings: number;
  total_findings: number;
  risk_distribution: Record<string, number>;
  protocol_distribution: Record<string, number>;
  tls_distribution: Record<string, number>;
  cert_health_distribution: Record<string, number>;
  recent_findings: Finding[];
}

export interface ReportRecord {
  id: string;
  evidence_id: string;
  evidence_filename: string;
  generated_at: string;
  formats: string[];
  risk_score: number;
  risk_level: string;
  session_count: number;
  finding_count: number;
}

export interface SystemStatus {
  app_version: string;
  analyzer_version: string;
  max_upload_size_mb: number;
  engine_status: string;
  tshark_status: string;
  openssl_status: string;
  database_status: string;
  forensic_mode: string;
}

const API_BASE = '/api';

async function fetchJson<T>(url: string, options?: RequestInit): Promise<T> {
  const res = await fetch(url, options);
  if (!res.ok) {
    let errorMsg = `HTTP Error ${res.status}: ${res.statusText}`;
    try {
      const body = await res.json();
      if (body.detail) errorMsg = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail);
    } catch (_) {
      // ignore
    }
    throw new Error(errorMsg);
  }
  return res.json();
}

export const api = {
  getHealth: () => fetchJson<{ status: string; app: string; forensic_mode: string }>(`${API_BASE}/health`),

  getOverview: () => fetchJson<OverviewMetrics>(`${API_BASE}/overview`),

  uploadEvidence: async (file: File, autoAnalyze: boolean = true): Promise<EvidenceRecord> => {
    const formData = new FormData();
    formData.append('file', file);
    return fetchJson<EvidenceRecord>(`${API_BASE}/evidence/upload?auto_analyze=${autoAnalyze}`, {
      method: 'POST',
      body: formData,
    });
  },

  listEvidence: () => fetchJson<EvidenceRecord[]>(`${API_BASE}/evidence`),

  getEvidence: (id: string) => fetchJson<EvidenceRecord>(`${API_BASE}/evidence/${id}`),

  analyzeEvidence: (id: string) =>
    fetchJson<EvidenceRecord>(`${API_BASE}/evidence/${id}/analyze`, { method: 'POST' }),

  listSessions: (params?: {
    evidence_id?: string;
    protocol?: string;
    risk?: string;
    tls_version?: string;
    cert_status?: string;
    search?: string;
  }) => {
    const query = new URLSearchParams();
    if (params?.evidence_id) query.append('evidence_id', params.evidence_id);
    if (params?.protocol) query.append('protocol', params.protocol);
    if (params?.risk) query.append('risk', params.risk);
    if (params?.tls_version) query.append('tls_version', params.tls_version);
    if (params?.cert_status) query.append('cert_status', params.cert_status);
    if (params?.search) query.append('search', params.search);
    const qs = query.toString();
    return fetchJson<SessionRecord[]>(`${API_BASE}/sessions${qs ? `?${qs}` : ''}`);
  },

  getSession: (id: string) => fetchJson<SessionRecord>(`${API_BASE}/sessions/${id}`),

  listFindings: (params?: {
    evidence_id?: string;
    severity?: string;
    protocol?: string;
    search?: string;
  }) => {
    const query = new URLSearchParams();
    if (params?.evidence_id) query.append('evidence_id', params.evidence_id);
    if (params?.severity) query.append('severity', params.severity);
    if (params?.protocol) query.append('protocol', params.protocol);
    if (params?.search) query.append('search', params.search);
    const qs = query.toString();
    return fetchJson<Finding[]>(`${API_BASE}/findings${qs ? `?${qs}` : ''}`);
  },

  getFinding: (id: string) => fetchJson<Finding>(`${API_BASE}/findings/${id}`),

  getRiskPosture: () => fetchJson<RiskPosture>(`${API_BASE}/risk-posture`),

  listReports: () => fetchJson<ReportRecord[]>(`${API_BASE}/reports`),

  getReportViewUrl: (reportId: string, format: 'html' | 'json' = 'html') =>
    `${API_BASE}/reports/${reportId}/view?format=${format}`,

  getReportDownloadUrl: (reportId: string, format: 'pdf' | 'html' | 'json' = 'pdf') =>
    `${API_BASE}/reports/${reportId}/download?format=${format}`,

  deleteEvidence: (id: string) =>
    fetchJson<{ message: string }>(`${API_BASE}/evidence/${id}`, {
      method: 'DELETE',
    }),

  clearAllEvidence: () =>
    fetchJson<{ message: string }>(`${API_BASE}/evidence/clear-all`, {
      method: 'POST',
    }),

  getSystemStatus: () => fetchJson<SystemStatus>(`${API_BASE}/settings/status`),
};

