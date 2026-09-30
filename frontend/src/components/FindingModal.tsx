import React from 'react';
import type { Finding } from '../services/api';
import { RiskBadge } from './Badges';
import { X, ShieldAlert, CheckCircle2 } from 'lucide-react';

interface FindingModalProps {
  finding: Finding | null;
  onClose: () => void;
  onNavigateToSession?: (sessionId: string) => void;
}

export const FindingModal: React.FC<FindingModalProps> = ({
  finding,
  onClose,
  onNavigateToSession,
}) => {
  if (!finding) return null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <RiskBadge level={finding.severity} />
            <span className="modal-title">{finding.title}</span>
          </div>
          <button className="modal-close-btn" onClick={onClose}>
            <X size={18} />
          </button>
        </div>

        <div className="modal-body">
          {/* Metadata bar */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(4, 1fr)',
              gap: 12,
              background: '#090E1A',
              padding: 12,
              borderRadius: 6,
              border: '1px solid var(--border-subtle)',
              marginBottom: 16,
              fontFamily: 'var(--font-mono)',
              fontSize: 11,
            }}
          >
            <div>
              <span style={{ color: 'var(--text-muted)', display: 'block' }}>RULE ID</span>
              <span style={{ color: 'var(--accent-cyan)', fontWeight: 600 }}>{finding.rule_id}</span>
            </div>
            <div>
              <span style={{ color: 'var(--text-muted)', display: 'block' }}>PROTOCOL</span>
              <span style={{ color: '#FFFFFF', fontWeight: 600 }}>{finding.protocol}</span>
            </div>
            <div>
              <span style={{ color: 'var(--text-muted)', display: 'block' }}>SESSION</span>
              <span
                style={{
                  color: 'var(--accent-teal)',
                  cursor: onNavigateToSession ? 'pointer' : 'default',
                  textDecoration: onNavigateToSession ? 'underline' : 'none',
                }}
                onClick={() => onNavigateToSession && onNavigateToSession(finding.session_id)}
              >
                {finding.session_id}
              </span>
            </div>
            <div>
              <span style={{ color: 'var(--text-muted)', display: 'block' }}>EVIDENCE FILE</span>
              <span style={{ color: '#FFFFFF' }}>{finding.evidence_filename}</span>
            </div>
          </div>

          {/* Description */}
          <div style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', marginBottom: 4, textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>
              OBSERVED FORENSIC EVENT
            </div>
            <div style={{ color: '#E2E8F0', fontSize: 13, lineHeight: 1.6 }}>
              {finding.description}
            </div>
          </div>

          {/* Why it matters */}
          <div style={{ marginBottom: 16, background: 'rgba(239, 68, 68, 0.05)', border: '1px solid rgba(239, 68, 68, 0.2)', padding: 12, borderRadius: 5 }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--status-critical)', marginBottom: 4, textTransform: 'uppercase', fontFamily: 'var(--font-mono)', display: 'flex', alignItems: 'center', gap: 6 }}>
              <ShieldAlert size={14} />
              WHY IT MATTERS (RISK IMPACT)
            </div>
            <div style={{ color: '#F1F5F9', fontSize: 12.5, lineHeight: 1.5 }}>
              {finding.why_it_matters}
            </div>
          </div>

          {/* Technical Details */}
          <div style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', marginBottom: 4, textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>
              EXTRACTED PACKET TELEMETRY
            </div>
            <div style={{ background: '#090E1A', padding: 12, borderRadius: 4, border: '1px solid var(--border-subtle)', fontFamily: 'var(--font-mono)', fontSize: 11.5, color: 'var(--accent-cyan)' }}>
              {finding.technical_details}
            </div>
          </div>

          {/* Recommendation */}
          <div style={{ background: 'rgba(10, 228, 186, 0.05)', border: '1px solid rgba(10, 228, 186, 0.25)', padding: 12, borderRadius: 5 }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--accent-teal)', marginBottom: 4, textTransform: 'uppercase', fontFamily: 'var(--font-mono)', display: 'flex', alignItems: 'center', gap: 6 }}>
              <CheckCircle2 size={14} />
              DETERMINISTIC REMEDIATION RECOMMENDATION
            </div>
            <div style={{ color: '#F1F5F9', fontSize: 12.5, lineHeight: 1.5 }}>
              {finding.recommendation}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
