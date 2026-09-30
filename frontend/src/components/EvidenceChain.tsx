import React, { useState } from 'react';
import type { EvidenceChainNode } from '../services/api';
import {
  CheckCircle2,
  AlertTriangle,
  AlertOctagon,
  MinusCircle,
  Copy,
  Check,
  ChevronRight,
  Activity,
} from 'lucide-react';

interface EvidenceChainProps {
  nodes: EvidenceChainNode[];
}

export const EvidenceChain: React.FC<EvidenceChainProps> = ({ nodes }) => {
  const [selectedIdx, setSelectedIdx] = useState<number>(0);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  if (!nodes || nodes.length === 0) {
    return null;
  }

  const activeNode = nodes[selectedIdx] || nodes[0];

  const handleCopyValue = (key: string, val: string) => {
    navigator.clipboard.writeText(val);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1800);
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'critical':
        return <AlertOctagon size={14} style={{ color: 'var(--status-critical)' }} />;
      case 'warning':
        return <AlertTriangle size={14} style={{ color: 'var(--status-high)' }} />;
      case 'secure':
        return <CheckCircle2 size={14} style={{ color: 'var(--status-secure)' }} />;
      default:
        return <MinusCircle size={14} style={{ color: 'var(--text-muted)' }} />;
    }
  };

  const getStatusBadgeClass = (status: string) => {
    switch (status) {
      case 'critical': return 'badge-critical';
      case 'warning': return 'badge-high';
      case 'secure': return 'badge-secure';
      default: return 'badge-neutral';
    }
  };

  return (
    <div className="evidence-chain-wrapper">
      <div className="chain-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Activity size={15} style={{ color: 'var(--accent-cyan)' }} />
          <span>DETERMINISTIC EVIDENCE CHAIN ({nodes.length} VERIFIED NODES)</span>
        </div>
        <span style={{ color: 'var(--text-muted)', fontSize: 10.5, fontFamily: 'var(--font-mono)' }}>
          SELECT ANY NODE TO EXPAND EXTRACTED FORENSIC TELEMETRY
        </span>
      </div>

      {/* Horizontal Steps Track */}
      <div className="chain-steps-track">
        {nodes.map((node, idx) => {
          const isSelected = idx === selectedIdx;

          return (
            <React.Fragment key={idx}>
              <div
                className={`chain-node ${isSelected ? 'active' : ''}`}
                onClick={() => setSelectedIdx(idx)}
                title={node.details}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
                  <span className="chain-node-step">
                    NODE {idx + 1}: {node.step.replace(/_/g, ' ')}
                  </span>
                  <div>{getStatusIcon(node.status)}</div>
                </div>
                <div className="chain-node-title">{node.title}</div>
              </div>
              {idx < nodes.length - 1 && (
                <div className="chain-arrow">
                  <ChevronRight size={14} />
                </div>
              )}
            </React.Fragment>
          );
        })}
      </div>

      {/* Active Node Detailed Forensic Inspector */}
      {activeNode && (
        <div className="chain-inspector-box">
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              marginBottom: 12,
              paddingBottom: 10,
              borderBottom: '1px solid var(--border-subtle)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span className="chain-inspector-title">
                INSPECTOR: {activeNode.step.replace(/_/g, ' ')}
              </span>
              <span style={{ color: '#FFFFFF', fontWeight: 700, fontSize: 13 }}>
                — {activeNode.title}
              </span>
            </div>
            <span className={`badge ${getStatusBadgeClass(activeNode.status)}`}>
              <span className="badge-dot" />
              STATUS: {activeNode.status.toUpperCase()}
            </span>
          </div>

          <div
            style={{
              color: '#CBD5E1',
              fontSize: 12.5,
              lineHeight: 1.6,
              marginBottom: 16,
              padding: '10px 14px',
              backgroundColor: 'var(--bg-surface)',
              borderRadius: 6,
              border: '1px solid var(--border-subtle)',
            }}
          >
            {activeNode.details}
          </div>

          {activeNode.technical_props && Object.keys(activeNode.technical_props).length > 0 && (
            <div>
              <div
                style={{
                  fontSize: 10.5,
                  fontWeight: 700,
                  color: 'var(--text-muted)',
                  textTransform: 'uppercase',
                  letterSpacing: 0.6,
                  fontFamily: 'var(--font-mono)',
                  marginBottom: 8,
                }}
              >
                EXTRACTED WIRE-LEVEL FIELDS & CRYPTOGRAPHIC ATTRIBUTES
              </div>

              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
                  gap: 10,
                }}
              >
                {Object.entries(activeNode.technical_props).map(([key, val]) => {
                  const displayVal = Array.isArray(val) ? val.join(', ') || 'NONE' : String(val);
                  return (
                    <div
                      key={key}
                      style={{
                        background: 'var(--bg-surface)',
                        padding: '8px 12px',
                        borderRadius: 6,
                        border: '1px solid var(--border-subtle)',
                        display: 'flex',
                        flexDirection: 'column',
                        justifyContent: 'space-between',
                      }}
                    >
                      <div
                        style={{
                          fontSize: 9.5,
                          color: 'var(--text-muted)',
                          textTransform: 'uppercase',
                          fontFamily: 'var(--font-mono)',
                          marginBottom: 4,
                        }}
                      >
                        {key.replace(/_/g, ' ')}
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 6 }}>
                        <span
                          style={{
                            color: 'var(--accent-cyan)',
                            fontFamily: 'var(--font-mono)',
                            fontSize: 11,
                            wordBreak: 'break-all',
                          }}
                        >
                          {displayVal}
                        </span>
                        <button
                          className="header-btn"
                          style={{ height: 18, width: 18, padding: 0, justifyContent: 'center' }}
                          onClick={() => handleCopyValue(key, displayVal)}
                          title="Copy field value"
                        >
                          {copiedKey === key ? (
                            <Check size={10} style={{ color: 'var(--status-secure)' }} />
                          ) : (
                            <Copy size={10} />
                          )}
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
