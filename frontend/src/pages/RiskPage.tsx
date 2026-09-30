import React from 'react';
import type { RiskPosture } from '../services/api';
import { RiskBadge, SeverityBadge } from '../components/Badges';
import { EmptyState, LoadingState } from '../components/FeedbackStates';
import { Target, Layers, ShieldCheck, AlertTriangle, ChevronRight } from 'lucide-react';

interface RiskPageProps {
  riskPosture: RiskPosture | null;
  loading: boolean;
  onNavigateToEvidenceSessions?: (evidenceId: string) => void;
}

export const RiskPage: React.FC<RiskPageProps> = ({
  riskPosture,
  loading,
  onNavigateToEvidenceSessions,
}) => {
  if (loading && !riskPosture) {
    return <LoadingState message="Calculating Explainable Risk Posture..." />;
  }

  if (!riskPosture || (riskPosture.overall_score === 0 && riskPosture.contributing_factors.length === 0)) {
    return (
      <div>
        <div className="panel-card" style={{ marginBottom: 0 }}>
          <div className="panel-header">
            <span className="panel-title">
              <Target size={15} style={{ color: 'var(--accent-cyan)' }} />
              CRYPTOGRAPHIC SECURITY POSTURE & RISK ENGINE
            </span>
            <RiskBadge level="SECURE" score={0} />
          </div>
          <div className="panel-body">
            <EmptyState
              title="NO FORENSIC EVIDENCE TO ASSESS"
              description="Upload and analyze network packet capture files to calculate the explainable cryptographic security posture score."
            />
          </div>
        </div>
      </div>
    );
  }

  const {
    overall_score,
    severity,
    contributing_factors,
    risk_distribution,
    risk_by_protocol,
    risk_by_evidence,
  } = riskPosture;

  const getScoreColor = (sev: string) => {
    switch (sev) {
      case 'CRITICAL': return 'var(--status-critical)';
      case 'HIGH': return 'var(--status-high)';
      case 'MEDIUM': return 'var(--status-medium)';
      case 'LOW': return 'var(--status-low)';
      default: return 'var(--status-secure)';
    }
  };

  const scoreColor = getScoreColor(severity);

  return (
    <div>
      {/* 1. Main Security Posture Score & Narrative */}
      <div className="panel-card" style={{ marginBottom: 20 }}>
        <div className="panel-header">
          <span className="panel-title">
            <Target size={15} style={{ color: 'var(--accent-cyan)' }} />
            AGGREGATE SECURITY POSTURE (EXPLAINABLE RISK ENGINE)
          </span>
          <RiskBadge level={severity} />
        </div>

        <div className="panel-body">
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
              gap: 24,
              alignItems: 'center',
            }}
          >
            {/* Score Big Display */}
            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
                padding: '24px 20px',
                background: 'var(--bg-surface)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 8,
                textAlign: 'center',
              }}
            >
              <span
                style={{
                  fontSize: 11,
                  fontWeight: 700,
                  color: 'var(--text-muted)',
                  fontFamily: 'var(--font-mono)',
                  textTransform: 'uppercase',
                  marginBottom: 8,
                }}
              >
                DETERMINISTIC COMPOSITE SCORE
              </span>

              <div
                style={{
                  fontSize: 48,
                  fontWeight: 800,
                  fontFamily: 'var(--font-mono)',
                  color: scoreColor,
                  lineHeight: 1,
                  marginBottom: 10,
                }}
              >
                {overall_score}
                <span style={{ fontSize: 20, color: 'var(--text-muted)' }}>/100</span>
              </div>

              <RiskBadge level={severity} />

              <div
                style={{
                  fontSize: 11,
                  color: 'var(--text-muted)',
                  marginTop: 12,
                  lineHeight: 1.5,
                  maxWidth: 260,
                }}
              >
                Deterministic risk score derived from protocol, cipher, certificate, and cleartext violations.
              </div>
            </div>

            {/* Posture Explanation & Session Count */}
            <div>
              <div
                style={{
                  fontSize: 14,
                  fontWeight: 700,
                  color: '#FFFFFF',
                  marginBottom: 8,
                  display: 'flex',
                  alignItems: 'center',
                  gap: 8,
                }}
              >
                <ShieldCheck size={16} style={{ color: 'var(--accent-cyan)' }} />
                <span>EVIDENCE-BASED RISK METHODOLOGY</span>
              </div>

              <p style={{ color: 'var(--text-secondary)', fontSize: 12.5, lineHeight: 1.6, marginBottom: 16 }}>
                SecureMailScope does NOT use opaque or fabricated scoring. Every point added to the risk
                score is tied to observable network telemetry: cleartext transmissions, deprecated TLS versions
                (TLS 1.0, SSL 3.0), weak ciphers (RC4, 3DES), and expired or weak-key X.509 certificates.
              </p>

              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
                  gap: 10,
                  background: 'var(--bg-surface)',
                  padding: '12px 16px',
                  borderRadius: 6,
                  border: '1px solid var(--border-subtle)',
                }}
              >
                <div>
                  <span style={{ fontSize: 10, color: 'var(--text-muted)', display: 'block', textTransform: 'uppercase' }}>
                    Critical Sessions
                  </span>
                  <span style={{ fontSize: 16, fontWeight: 700, color: 'var(--status-critical)', fontFamily: 'var(--font-mono)' }}>
                    {risk_distribution['CRITICAL'] || 0}
                  </span>
                </div>
                <div>
                  <span style={{ fontSize: 10, color: 'var(--text-muted)', display: 'block', textTransform: 'uppercase' }}>
                    High Risk
                  </span>
                  <span style={{ fontSize: 16, fontWeight: 700, color: 'var(--status-high)', fontFamily: 'var(--font-mono)' }}>
                    {risk_distribution['HIGH'] || 0}
                  </span>
                </div>
                <div>
                  <span style={{ fontSize: 10, color: 'var(--text-muted)', display: 'block', textTransform: 'uppercase' }}>
                    Medium Risk
                  </span>
                  <span style={{ fontSize: 16, fontWeight: 700, color: 'var(--status-medium)', fontFamily: 'var(--font-mono)' }}>
                    {risk_distribution['MEDIUM'] || 0}
                  </span>
                </div>
                <div>
                  <span style={{ fontSize: 10, color: 'var(--text-muted)', display: 'block', textTransform: 'uppercase' }}>
                    Low / Secure
                  </span>
                  <span style={{ fontSize: 16, fontWeight: 700, color: 'var(--status-low)', fontFamily: 'var(--font-mono)' }}>
                    {(risk_distribution['LOW'] || 0) + (risk_distribution['SECURE'] || 0)}
                  </span>
                </div>
              </div>

              {/* Risk Scale Legend */}
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))',
                  gap: 8,
                  marginTop: 12,
                  padding: '8px 12px',
                  background: 'rgba(0,0,0,0.25)',
                  border: '1px solid rgba(255,255,255,0.06)',
                  borderRadius: 6,
                  fontFamily: 'var(--font-mono)',
                  fontSize: 10.5,
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <span style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--status-low)' }} />
                  <span style={{ color: '#94a3b8' }}>LOW: <strong style={{ color: 'var(--status-low)' }}>0 – 20</strong></span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <span style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--status-medium)' }} />
                  <span style={{ color: '#94a3b8' }}>MED: <strong style={{ color: 'var(--status-medium)' }}>21 – 40</strong></span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <span style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--status-high)' }} />
                  <span style={{ color: '#94a3b8' }}>HIGH: <strong style={{ color: 'var(--status-high)' }}>41 – 60</strong></span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <span style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--status-critical)' }} />
                  <span style={{ color: '#94a3b8' }}>CRIT: <strong style={{ color: 'var(--status-critical)' }}>&gt; 60</strong></span>
                </div>
              </div>

              {/* Protocol Risk Breakdown */}
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 12,
                  marginTop: 12,
                  fontFamily: 'var(--font-mono)',
                  fontSize: 11,
                  color: 'var(--text-muted)',
                }}
              >
                <span>PROTOCOL RISK:</span>
                {Object.entries(risk_by_protocol).map(([proto, count]) => (
                  <span key={proto} style={{ color: count > 0 ? 'var(--status-high)' : 'var(--status-secure)' }}>
                    {proto}: {count} at-risk
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* 2. Contributing Factors Breakdown Table */}
      <div className="panel-card" style={{ marginBottom: 20 }}>
        <div className="panel-header">
          <span className="panel-title">
            <AlertTriangle size={15} style={{ color: 'var(--status-high)' }} />
            OBSERVED CONTRIBUTING FACTORS BREAKDOWN
          </span>
          <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
            TRANSPARENT RISK ATTRIBUTION
          </span>
        </div>
        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>CONTRIBUTING FACTOR</th>
                <th>WEIGHT IMPACT</th>
                <th>SEVERITY</th>
                <th>OBSERVED OCCURRENCES</th>
                <th>TECHNICAL EXPLANATION</th>
              </tr>
            </thead>
            <tbody>
              {contributing_factors && contributing_factors.length > 0 ? (
                contributing_factors.map((f, idx) => (
                  <tr key={idx}>
                    <td style={{ fontWeight: 600, color: '#FFFFFF' }}>{f.factor}</td>
                    <td>
                      <span className="mono-cell" style={{ color: 'var(--accent-cyan)', fontWeight: 700 }}>
                        +{f.points} pts
                      </span>
                    </td>
                    <td>
                      <SeverityBadge severity={f.severity} />
                    </td>
                    <td>
                      <span className="mono-cell" style={{ color: '#E2E8F0', fontWeight: 600 }}>
                        {f.count} session(s)
                      </span>
                    </td>
                    <td style={{ color: 'var(--text-secondary)', fontSize: 12 }}>{f.details}</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={5} style={{ textAlign: 'center', padding: 24, color: 'var(--text-muted)' }}>
                    No risk contributing factors identified. All traffic conforms to cryptographic baseline.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* 3. Risk by Evidence File */}
      {risk_by_evidence && risk_by_evidence.length > 0 && (
        <div className="panel-card" style={{ marginBottom: 0 }}>
          <div className="panel-header">
            <span className="panel-title">
              <Layers size={15} style={{ color: 'var(--accent-teal)' }} />
              RISK BREAKDOWN BY CAPTURE EVIDENCE FILE
            </span>
            <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              {risk_by_evidence.length} EVIDENCE RECORD(S)
            </span>
          </div>
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>EVIDENCE ID</th>
                  <th>FILENAME</th>
                  <th>RISK SCORE</th>
                  <th>SEVERITY LEVEL</th>
                  <th>RECONSTRUCTED SESSIONS</th>
                  <th>FINDINGS COUNT</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {risk_by_evidence.map((ev) => (
                  <tr key={ev.evidence_id}>
                    <td>
                      <span className="mono-cell" style={{ color: 'var(--accent-cyan)', fontWeight: 700 }}>
                        {ev.evidence_id}
                      </span>
                    </td>
                    <td style={{ fontWeight: 600, color: '#FFFFFF' }}>{ev.filename}</td>
                    <td>
                      <span className="mono-cell" style={{ fontWeight: 700 }}>
                        {ev.score} / 100
                      </span>
                    </td>
                    <td>
                      <RiskBadge level={ev.severity} />
                    </td>
                    <td className="mono-cell">{ev.session_count}</td>
                    <td className="mono-cell">{ev.finding_count}</td>
                    <td style={{ textAlign: 'right' }}>
                      {onNavigateToEvidenceSessions && (
                        <button
                          className="header-btn"
                          style={{ height: 24, padding: '0 8px', fontSize: 10.5 }}
                          onClick={() => onNavigateToEvidenceSessions(ev.evidence_id)}
                        >
                          View Sessions
                          <ChevronRight size={11} />
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
