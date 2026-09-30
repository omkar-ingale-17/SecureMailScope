import React, { useState } from 'react';
import type { OverviewMetrics, Finding } from '../services/api';
import { MetricCard } from '../components/MetricCard';
import { SeverityBadge } from '../components/Badges';
import { EmptyState, LoadingState, ErrorState } from '../components/FeedbackStates';
import { FindingModal } from '../components/FindingModal';
import {
  Database,
  Network,
  ShieldAlert,
  AlertOctagon,
  UploadCloud,
  Layers,
  ArrowRight,
  ShieldCheck,
  Lock,
  Key,
  FileCheck,
  AlertTriangle,
  ChevronRight,
} from 'lucide-react';

interface OverviewPageProps {
  metrics: OverviewMetrics | null;
  loading: boolean;
  error: string | null;
  onRetry: () => void;
  onNavigateToEvidence: () => void;
  onNavigateToSessions: () => void;
  onNavigateToSession: (sessionId: string) => void;
}

export const OverviewPage: React.FC<OverviewPageProps> = ({
  metrics,
  loading,
  error,
  onRetry,
  onNavigateToEvidence,
  onNavigateToSessions,
  onNavigateToSession,
}) => {
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  if (loading && !metrics) {
    return <LoadingState message="Loading Forensic Overview Telemetry..." />;
  }

  if (error) {
    return <ErrorState error={error} onRetry={onRetry} />;
  }

  const hasData = metrics && metrics.total_evidence > 0;

  if (!hasData) {
    return (
      <div>
        {/* Metric Cards showing 0 in empty state */}
        <div className="metric-grid">
          <MetricCard
            label="TOTAL EVIDENCE"
            value={0}
            subtext="0 PCAP/PCAPNG files in custody"
            icon={<Database size={16} />}
            accent="cyan"
          />
          <MetricCard
            label="RECONSTRUCTED SESSIONS"
            value={0}
            subtext="0 email streams reassembled"
            icon={<Network size={16} />}
            accent="teal"
          />
          <MetricCard
            label="AT-RISK SESSIONS"
            value={0}
            subtext="No vulnerabilities detected"
            icon={<AlertOctagon size={16} />}
            accent="yellow"
          />
          <MetricCard
            label="HIGH / CRITICAL FINDINGS"
            value={0}
            subtext="No severe violations"
            icon={<ShieldAlert size={16} />}
            accent="red"
          />
        </div>

        <EmptyState
          title="NO EVIDENCE ANALYZED"
          description="Upload a PCAP or PCAPNG capture file containing SMTP, IMAP, or POP3 network traffic to begin passive forensic investigation and cryptographic posture evaluation."
          actionText="Upload PCAP Evidence"
          onAction={onNavigateToEvidence}
          icon={<UploadCloud size={40} />}
        />
      </div>
    );
  }

  const riskDist = metrics.risk_distribution || {};
  const protoDist = metrics.protocol_distribution || {};
  const tlsDist = metrics.tls_distribution || {};
  const certDist = metrics.cert_health_distribution || {};
  const totalSessions = metrics.total_sessions || 1;

  // Real pipeline indicators based on actual data
  const pipelineSteps = [
    {
      id: 'pcap',
      label: 'PCAP Custody',
      sub: `${metrics.total_evidence} capture(s)`,
      icon: <Database size={13} />,
      active: metrics.total_evidence > 0,
      onClick: onNavigateToEvidence,
    },
    {
      id: 'sessions',
      label: 'TCP Reassembly',
      sub: `${metrics.total_sessions} session(s)`,
      icon: <Network size={13} />,
      active: metrics.total_sessions > 0,
      onClick: onNavigateToSessions,
    },
    {
      id: 'protocols',
      label: 'Email Protocols',
      sub: 'SMTP / IMAP / POP3',
      icon: <Layers size={13} />,
      active: Object.values(protoDist).some((v) => v > 0),
      onClick: onNavigateToSessions,
    },
    {
      id: 'tls',
      label: 'TLS Extraction',
      sub: `${(tlsDist['TLS 1.3'] || 0) + (tlsDist['TLS 1.2'] || 0)} modern TLS`,
      icon: <Lock size={13} />,
      active: metrics.total_sessions > (tlsDist['Cleartext (No TLS)'] || 0),
      onClick: onNavigateToSessions,
    },
    {
      id: 'certs',
      label: 'X.509 Certificates',
      sub: `${certDist['VALID'] || 0} valid cert(s)`,
      icon: <Key size={13} />,
      active: Object.values(certDist).some((v) => v > 0),
      onClick: onNavigateToSessions,
    },
    {
      id: 'findings',
      label: 'Deterministic Rules',
      sub: `${metrics.total_findings || metrics.recent_findings.length} finding(s)`,
      icon: <AlertTriangle size={13} />,
      active: (metrics.total_findings || metrics.recent_findings.length) > 0,
    },
    {
      id: 'risk',
      label: 'Risk Posture',
      sub: `${metrics.at_risk_sessions} at-risk`,
      icon: <ShieldCheck size={13} />,
      active: metrics.total_sessions > 0,
    },
  ];

  return (
    <div>
      {/* 1. VISUAL INVESTIGATION PIPELINE BAR */}
      <div
        className="panel-card"
        style={{
          marginBottom: 20,
          background: 'var(--bg-secondary)',
          border: '1px solid var(--border-normal)',
        }}
      >
        <div
          className="panel-header"
          style={{
            padding: '10px 18px',
            fontSize: 11,
            background: 'rgba(17, 25, 35, 0.7)',
          }}
        >
          <span className="panel-title" style={{ fontSize: 11 }}>
            <FileCheck size={14} style={{ color: 'var(--accent-cyan)' }} />
            INVESTIGATION WORKFLOW & TRACEABILITY CHAIN
          </span>
          <span style={{ fontSize: 10.5, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
            EVIDENCE-LINKED DETERMINISTIC STAGES
          </span>
        </div>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            overflowX: 'auto',
            padding: '12px 18px',
            gap: 8,
          }}
        >
          {pipelineSteps.map((step, idx) => (
            <React.Fragment key={step.id}>
              <div
                onClick={step.onClick}
                style={{
                  background: step.active ? 'var(--bg-surface)' : 'rgba(15, 23, 34, 0.4)',
                  border: `1px solid ${step.active ? 'var(--border-highlight)' : 'var(--border-subtle)'}`,
                  borderRadius: 6,
                  padding: '8px 12px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 10,
                  cursor: step.onClick ? 'pointer' : 'default',
                  flexShrink: 0,
                  transition: 'all 0.15s ease',
                }}
                className={step.onClick ? 'chain-node' : ''}
              >
                <div
                  style={{
                    color: step.active ? 'var(--accent-cyan)' : 'var(--text-muted)',
                    display: 'flex',
                    alignItems: 'center',
                  }}
                >
                  {step.icon}
                </div>
                <div>
                  <div
                    style={{
                      fontSize: 11,
                      fontWeight: 700,
                      color: step.active ? '#FFFFFF' : 'var(--text-muted)',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    {step.label}
                  </div>
                  <div
                    style={{
                      fontSize: 9.5,
                      color: step.active ? 'var(--text-secondary)' : 'var(--text-dim)',
                      fontFamily: 'var(--font-mono)',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    {step.sub}
                  </div>
                </div>
              </div>
              {idx < pipelineSteps.length - 1 && (
                <ArrowRight size={13} style={{ color: 'var(--text-dim)', flexShrink: 0 }} />
              )}
            </React.Fragment>
          ))}
        </div>
      </div>

      {/* 2. Top Metric Cards */}
      <div className="metric-grid">
        <MetricCard
          label="PCAP EVIDENCE"
          value={metrics.total_evidence}
          subtext={`${metrics.total_evidence} file(s) in forensic custody`}
          icon={<Database size={16} />}
          accent="cyan"
        />
        <MetricCard
          label="NETWORK SESSIONS"
          value={metrics.total_sessions}
          subtext="Reconstructed TCP email streams"
          icon={<Network size={16} />}
          accent="teal"
        />
        <MetricCard
          label="AT-RISK SESSIONS"
          value={metrics.at_risk_sessions}
          subtext="Streams with identified weaknesses"
          icon={<AlertOctagon size={16} />}
          accent="yellow"
        />
        <MetricCard
          label="SECURITY FINDINGS"
          value={metrics.total_findings || metrics.high_critical_findings}
          subtext={`${metrics.high_critical_findings} high/critical violations`}
          icon={<ShieldAlert size={16} />}
          accent="red"
        />
      </div>

      {/* 3. Second Row: Risk Distribution & Protocol Breakdown */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))',
          gap: 20,
          marginBottom: 20,
        }}
      >
        {/* Risk Distribution */}
        <div className="panel-card" style={{ marginBottom: 0 }}>
          <div className="panel-header">
            <span className="panel-title">SESSION RISK POSTURE DISTRIBUTION</span>
            <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              {metrics.total_sessions} SESSIONS
            </span>
          </div>
          <div className="panel-body">
            {[
              { label: 'Critical Risk (> 60)', key: 'CRITICAL', color: 'var(--status-critical)' },
              { label: 'High Risk (41 – 60)', key: 'HIGH', color: 'var(--status-high)' },
              { label: 'Medium Risk (21 – 40)', key: 'MEDIUM', color: 'var(--status-medium)' },
              { label: 'Low Risk (0 – 20)', key: 'LOW', color: 'var(--status-low)' },
              { label: 'Secure Baseline (0)', key: 'SECURE', color: 'var(--status-secure)' },
            ].map((item) => {
              const count = riskDist[item.key] || 0;
              const pct = totalSessions > 0 ? (count / totalSessions) * 100 : 0;
              return (
                <div key={item.key} style={{ marginBottom: 12 }}>
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      fontSize: 11.5,
                      marginBottom: 5,
                    }}
                  >
                    <span style={{ color: 'var(--text-secondary)' }}>{item.label}</span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: '#FFFFFF' }}>
                      {count} <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>({pct.toFixed(0)}%)</span>
                    </span>
                  </div>
                  <div
                    style={{
                      height: 5,
                      borderRadius: 3,
                      backgroundColor: 'var(--bg-surface-elevated)',
                      overflow: 'hidden',
                    }}
                  >
                    <div
                      style={{
                        width: `${pct}%`,
                        height: '100%',
                        backgroundColor: item.color,
                        borderRadius: 3,
                        transition: 'width 0.4s ease',
                      }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Protocol Distribution */}
        <div className="panel-card" style={{ marginBottom: 0 }}>
          <div className="panel-header">
            <span className="panel-title">APPLICATION PROTOCOL DISTRIBUTION</span>
            <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              RECONSTRUCTED EMAIL TRAFFIC
            </span>
          </div>
          <div className="panel-body">
            {[
              { label: 'SMTP (Ports 25, 465, 587)', key: 'SMTP', color: 'var(--accent-cyan)' },
              { label: 'IMAP (Ports 143, 993)', key: 'IMAP', color: 'var(--accent-teal)' },
              { label: 'POP3 (Ports 110, 995)', key: 'POP3', color: '#A855F7' },
            ].map((item) => {
              const count = protoDist[item.key] || 0;
              const pct = totalSessions > 0 ? (count / totalSessions) * 100 : 0;
              return (
                <div key={item.key} style={{ marginBottom: 14 }}>
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      fontSize: 11.5,
                      marginBottom: 5,
                    }}
                  >
                    <span style={{ color: 'var(--text-secondary)' }}>{item.label}</span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: '#FFFFFF' }}>
                      {count} <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>({pct.toFixed(0)}%)</span>
                    </span>
                  </div>
                  <div
                    style={{
                      height: 5,
                      borderRadius: 3,
                      backgroundColor: 'var(--bg-surface-elevated)',
                      overflow: 'hidden',
                    }}
                  >
                    <div
                      style={{
                        width: `${pct}%`,
                        height: '100%',
                        backgroundColor: item.color,
                        borderRadius: 3,
                        transition: 'width 0.4s ease',
                      }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* 4. Third Row: TLS Protocol Distribution & Certificate Health */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))',
          gap: 20,
          marginBottom: 20,
        }}
      >
        {/* TLS Version Breakdown */}
        <div className="panel-card" style={{ marginBottom: 0 }}>
          <div className="panel-header">
            <span className="panel-title">TLS PROTOCOL NEGOTIATIONS</span>
            <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              HANDSHAKE TELEMETRY
            </span>
          </div>
          <div className="panel-body">
            {[
              { label: 'TLS 1.3 (Modern Secure)', key: 'TLS 1.3', color: 'var(--status-secure)' },
              { label: 'TLS 1.2 (Standard)', key: 'TLS 1.2', color: 'var(--accent-cyan)' },
              { label: 'TLS 1.1 (Deprecated)', key: 'TLS 1.1', color: 'var(--status-high)' },
              { label: 'TLS 1.0 (Deprecated)', key: 'TLS 1.0', color: 'var(--status-critical)' },
              { label: 'SSL 3.0 (Exploitable)', key: 'SSL 3.0', color: 'var(--status-critical)' },
              { label: 'Cleartext (No TLS)', key: 'Cleartext (No TLS)', color: 'var(--status-critical)' },
            ].map((item) => {
              const count = tlsDist[item.key] || 0;
              const pct = totalSessions > 0 ? (count / totalSessions) * 100 : 0;
              return (
                <div key={item.key} style={{ marginBottom: 10 }}>
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      fontSize: 11,
                      marginBottom: 4,
                    }}
                  >
                    <span style={{ color: 'var(--text-secondary)' }}>{item.label}</span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: '#FFFFFF' }}>
                      {count} <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>({pct.toFixed(0)}%)</span>
                    </span>
                  </div>
                  <div
                    style={{
                      height: 4,
                      borderRadius: 2,
                      backgroundColor: 'var(--bg-surface-elevated)',
                      overflow: 'hidden',
                    }}
                  >
                    <div
                      style={{
                        width: `${pct}%`,
                        height: '100%',
                        backgroundColor: item.color,
                        borderRadius: 2,
                        transition: 'width 0.4s ease',
                      }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Certificate Health Distribution */}
        <div className="panel-card" style={{ marginBottom: 0 }}>
          <div className="panel-header">
            <span className="panel-title">X.509 CERTIFICATE POSTURE</span>
            <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              PUBLIC KEY INFRASTRUCTURE
            </span>
          </div>
          <div className="panel-body">
            {[
              { label: 'Valid & Trusted Certificate', key: 'VALID', color: 'var(--status-secure)' },
              { label: 'Expired Certificate', key: 'EXPIRED', color: 'var(--status-critical)' },
              { label: 'Self-Signed Certificate', key: 'SELF_SIGNED', color: 'var(--status-medium)' },
              { label: 'Weak RSA Key (< 2048-bit)', key: 'WEAK_KEY', color: 'var(--status-high)' },
              { label: 'Weak Signature Algorithm', key: 'WEAK_SIGNATURE', color: 'var(--status-high)' },
              { label: 'Not Observable (Cleartext)', key: 'NOT OBSERVABLE', color: 'var(--text-dim)' },
            ].map((item) => {
              const count = certDist[item.key] || 0;
              const pct = totalSessions > 0 ? (count / totalSessions) * 100 : 0;
              return (
                <div key={item.key} style={{ marginBottom: 10 }}>
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      fontSize: 11,
                      marginBottom: 4,
                    }}
                  >
                    <span style={{ color: 'var(--text-secondary)' }}>{item.label}</span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: '#FFFFFF' }}>
                      {count} <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>({pct.toFixed(0)}%)</span>
                    </span>
                  </div>
                  <div
                    style={{
                      height: 4,
                      borderRadius: 2,
                      backgroundColor: 'var(--bg-surface-elevated)',
                      overflow: 'hidden',
                    }}
                  >
                    <div
                      style={{
                        width: `${pct}%`,
                        height: '100%',
                        backgroundColor: item.color,
                        borderRadius: 2,
                        transition: 'width 0.4s ease',
                      }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* 5. Recent Findings Inventory Table */}
      <div className="panel-card" style={{ marginBottom: 0 }}>
        <div className="panel-header">
          <span className="panel-title">
            <AlertTriangle size={15} style={{ color: 'var(--status-high)' }} />
            OBSERVED FORENSIC FINDINGS INVENTORY
          </span>
          <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
            TOP {metrics.recent_findings.length} DETECTIONS
          </span>
        </div>

        {metrics.recent_findings.length === 0 ? (
          <div style={{ padding: 32, textAlign: 'center', color: 'var(--text-muted)', fontSize: 12 }}>
            No security violations detected in the analyzed packet captures.
          </div>
        ) : (
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>SEVERITY</th>
                  <th>RULE ID</th>
                  <th>FINDING TITLE</th>
                  <th>PROTOCOL</th>
                  <th>SESSION ID</th>
                  <th>ACTION</th>
                </tr>
              </thead>
              <tbody>
                {metrics.recent_findings.map((f) => (
                  <tr key={f.id} onClick={() => setSelectedFinding(f)}>
                    <td>
                      <SeverityBadge severity={f.severity} />
                    </td>
                    <td>
                      <span className="mono-cell" style={{ color: 'var(--accent-cyan)', fontWeight: 700 }}>
                        {f.rule_id}
                      </span>
                    </td>
                    <td style={{ color: '#FFFFFF', fontWeight: 600 }}>{f.title}</td>
                    <td>
                      <span className="mono-cell">{f.protocol}</span>
                    </td>
                    <td>
                      <span className="mono-cell" style={{ color: 'var(--accent-teal)' }}>
                        {f.session_id}
                      </span>
                    </td>
                    <td>
                      <button
                        className="header-btn"
                        style={{ height: 24, padding: '0 8px', fontSize: 10.5 }}
                        onClick={(e) => {
                          e.stopPropagation();
                          onNavigateToSession(f.session_id);
                        }}
                      >
                        Inspect Stream
                        <ChevronRight size={11} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Finding Detail Dossier Modal */}
      {selectedFinding && (
        <FindingModal
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
          onNavigateToSession={(sid) => {
            setSelectedFinding(null);
            onNavigateToSession(sid);
          }}
        />
      )}
    </div>
  );
};
