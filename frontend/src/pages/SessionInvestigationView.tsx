import React, { useState } from 'react';
import type { SessionRecord, Finding } from '../services/api';
import { RiskBadge, SeverityBadge } from '../components/Badges';
import { EvidenceChain } from '../components/EvidenceChain';
import { TechnicalDetailPanel } from '../components/TechnicalDetailPanel';
import { FindingModal } from '../components/FindingModal';
import { ArrowLeft, AlertTriangle, ShieldCheck, ChevronRight, Copy, Check } from 'lucide-react';

interface SessionInvestigationViewProps {
  session: SessionRecord;
  onBack: () => void;
}

export const SessionInvestigationView: React.FC<SessionInvestigationViewProps> = ({
  session,
  onBack,
}) => {
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [copiedTuple, setCopiedTuple] = useState(false);

  const fiveTupleStr = `${session.network.src_ip}:${session.network.src_port} -> ${session.network.dst_ip}:${session.network.dst_port}`;

  const handleCopyTuple = () => {
    navigator.clipboard.writeText(fiveTupleStr);
    setCopiedTuple(true);
    setTimeout(() => setCopiedTuple(false), 2000);
  };

  return (
    <div>
      {/* Top Navigation & Session Header */}
      <div
        className="panel-card"
        style={{
          marginBottom: 20,
          background: 'var(--bg-secondary)',
          border: '1px solid var(--border-normal)',
          padding: '16px 20px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            <button className="header-btn" onClick={onBack} title="Return to Sessions Explorer">
              <ArrowLeft size={14} />
              <span>Back to Sessions</span>
            </button>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                <span style={{ fontSize: 17, fontWeight: 800, color: '#FFFFFF', fontFamily: 'var(--font-mono)' }}>
                  STREAM #{session.session_id}
                </span>
                <span className="mono-cell" style={{ fontSize: 12, color: 'var(--accent-cyan)', fontWeight: 700 }}>
                  [{session.protocol}]
                </span>
                <RiskBadge level={session.risk_level} score={session.risk_score} />
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginTop: 4 }}>
                INGESTED VIA: <span style={{ color: '#E2E8F0' }}>{session.evidence_filename}</span> ({session.evidence_id})
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div
              style={{
                background: 'var(--bg-surface)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 6,
                padding: '6px 12px',
                textAlign: 'right',
                fontFamily: 'var(--font-mono)',
              }}
            >
              <div style={{ fontSize: 9.5, color: 'var(--text-muted)', textTransform: 'uppercase' }}>FLOW 5-TUPLE</div>
              <div style={{ fontSize: 11.5, color: '#FFFFFF', display: 'flex', alignItems: 'center', gap: 6 }}>
                <span>
                  {session.network.src_ip}:{session.network.src_port} → {session.network.dst_ip}:{session.network.dst_port}
                </span>
                <button
                  className="header-btn"
                  style={{ height: 18, width: 18, padding: 0, justifyContent: 'center' }}
                  onClick={handleCopyTuple}
                  title="Copy 5-tuple"
                >
                  {copiedTuple ? <Check size={10} style={{ color: 'var(--status-secure)' }} /> : <Copy size={10} />}
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Visual Evidence Chain (10 Connected Nodes) */}
      <EvidenceChain nodes={session.evidence_chain} />

      {/* Structured Technical Details Panel */}
      <div style={{ marginBottom: 20 }}>
        <TechnicalDetailPanel session={session} />
      </div>

      {/* Session Rule Findings Table */}
      <div className="panel-card" style={{ marginBottom: 0 }}>
        <div className="panel-header">
          <span className="panel-title">
            <AlertTriangle size={15} style={{ color: 'var(--status-high)' }} />
            SESSION SECURITY RULE FINDINGS ({session.findings.length})
          </span>
          <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
            EVIDENCE-LINKED OBSERVATIONS
          </span>
        </div>
        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>SEVERITY</th>
                <th>RULE ID</th>
                <th>FINDING TITLE</th>
                <th>OBSERVED PACKET TELEMETRY</th>
                <th>REMEDIATION RECOMMENDATION</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {session.findings && session.findings.length > 0 ? (
                session.findings.map((f) => (
                  <tr key={f.id} onClick={() => setSelectedFinding(f)}>
                    <td>
                      <SeverityBadge severity={f.severity} />
                    </td>
                    <td>
                      <span className="mono-cell" style={{ color: 'var(--accent-cyan)', fontWeight: 700 }}>
                        {f.rule_id}
                      </span>
                    </td>
                    <td>
                      <div style={{ fontWeight: 600, color: '#FFFFFF' }}>{f.title}</div>
                      <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{f.description}</div>
                    </td>
                    <td className="mono-cell" style={{ maxWidth: 240, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {f.technical_details}
                    </td>
                    <td style={{ color: 'var(--accent-teal)', fontSize: 11.5 }}>
                      {f.recommendation}
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <button
                        className="header-btn"
                        style={{ height: 24, padding: '0 8px', fontSize: 10.5 }}
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedFinding(f);
                        }}
                      >
                        Inspect
                        <ChevronRight size={11} />
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6} style={{ textAlign: 'center', padding: 32, color: 'var(--status-secure)' }}>
                    <ShieldCheck size={24} style={{ marginBottom: 6, display: 'inline-block' }} />
                    <div style={{ fontWeight: 600 }}>NO SECURITY VIOLATIONS DETECTED</div>
                    <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginTop: 2 }}>
                      This stream fully conforms to the expected cryptographic and protocol security baseline.
                    </div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Finding Inspection Modal */}
      <FindingModal
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
      />
    </div>
  );
};
