import React, { useState } from 'react';
import type { SessionRecord } from '../services/api';
import { RiskBadge, StatusBadge } from '../components/Badges';
import { EmptyState, LoadingState } from '../components/FeedbackStates';
import { Search, Network, ChevronRight, ArrowUpDown } from 'lucide-react';

interface SessionsPageProps {
  sessions: SessionRecord[];
  loading: boolean;
  selectedEvidenceId?: string | null;
  onClearEvidenceFilter?: () => void;
  onSelectSession: (session: SessionRecord) => void;
}

export const SessionsPage: React.FC<SessionsPageProps> = ({
  sessions,
  loading,
  selectedEvidenceId,
  onClearEvidenceFilter,
  onSelectSession,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [protocolFilter, setProtocolFilter] = useState('ALL');
  const [riskFilter, setRiskFilter] = useState('ALL');
  const [tlsFilter, setTlsFilter] = useState('ALL');
  const [certFilter, setCertFilter] = useState('ALL');
  const [sortBy, setSortBy] = useState<'risk' | 'id' | 'packets'>('risk');
  const [sortAsc, setSortAsc] = useState(false);

  if (loading) {
    return <LoadingState message="Reconstructing Forensic Network Streams..." />;
  }

  // Filter client-side
  const filtered = sessions.filter((s) => {
    if (selectedEvidenceId && s.evidence_id !== selectedEvidenceId) return false;
    if (protocolFilter !== 'ALL' && s.protocol !== protocolFilter) return false;
    if (riskFilter !== 'ALL' && s.risk_level !== riskFilter) return false;
    if (tlsFilter !== 'ALL' && !s.tls.tls_version.includes(tlsFilter)) return false;
    if (certFilter !== 'ALL' && s.certificate.certificate_status !== certFilter) return false;

    if (searchTerm) {
      const q = searchTerm.toLowerCase();
      const match =
        s.session_id.toLowerCase().includes(q) ||
        s.protocol.toLowerCase().includes(q) ||
        s.network.src_ip.toLowerCase().includes(q) ||
        s.network.dst_ip.toLowerCase().includes(q) ||
        s.tls.cipher_suite.toLowerCase().includes(q) ||
        s.tls.tls_version.toLowerCase().includes(q) ||
        (s.certificate.subject && s.certificate.subject.toLowerCase().includes(q));
      if (!match) return false;
    }
    return true;
  });

  // Sort
  filtered.sort((a, b) => {
    let diff = 0;
    if (sortBy === 'risk') {
      diff = a.risk_score - b.risk_score;
    } else if (sortBy === 'packets') {
      diff = a.network.packet_count - b.network.packet_count;
    } else {
      diff = a.session_id.localeCompare(b.session_id);
    }
    return sortAsc ? diff : -diff;
  });

  const toggleSort = (field: 'risk' | 'id' | 'packets') => {
    if (sortBy === field) {
      setSortAsc(!sortAsc);
    } else {
      setSortBy(field);
      setSortAsc(false);
    }
  };

  return (
    <div>
      {/* Evidence Filter Banner if scoped */}
      {selectedEvidenceId && (
        <div
          style={{
            background: 'rgba(0, 242, 254, 0.08)',
            border: '1px solid rgba(0, 242, 254, 0.3)',
            borderRadius: 6,
            padding: '10px 16px',
            marginBottom: 16,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            fontFamily: 'var(--font-mono)',
            fontSize: 12,
          }}
        >
          <span>
            FILTERED BY CAPTURE IDENTIFIER: <strong style={{ color: 'var(--accent-cyan)' }}>{selectedEvidenceId}</strong>
          </span>
          <button
            className="header-btn"
            style={{ height: 24, fontSize: 11 }}
            onClick={onClearEvidenceFilter}
          >
            Show All Sessions
          </button>
        </div>
      )}

      {/* Filter and Search Bar */}
      <div
        style={{
          display: 'flex',
          gap: 12,
          marginBottom: 16,
          flexWrap: 'wrap',
          alignItems: 'center',
        }}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            background: 'var(--bg-card)',
            border: '1px solid var(--border-normal)',
            borderRadius: 6,
            padding: '6px 12px',
            flex: '1 1 240px',
          }}
        >
          <Search size={14} style={{ color: 'var(--text-muted)' }} />
          <input
            type="text"
            placeholder="Search session ID, IP, cipher, cert subject..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{
              background: 'transparent',
              border: 'none',
              outline: 'none',
              color: '#FFFFFF',
              width: '100%',
              fontSize: 12,
              fontFamily: 'var(--font-sans)',
            }}
          />
        </div>

        {/* Protocol Filter */}
        <select
          value={protocolFilter}
          onChange={(e) => setProtocolFilter(e.target.value)}
          className="header-btn"
          style={{ height: 32, fontSize: 11 }}
        >
          <option value="ALL">Protocol: All</option>
          <option value="SMTP">SMTP (25/465/587)</option>
          <option value="IMAP">IMAP (143/993)</option>
          <option value="POP3">POP3 (110/995)</option>
        </select>

        {/* Risk Filter */}
        <select
          value={riskFilter}
          onChange={(e) => setRiskFilter(e.target.value)}
          className="header-btn"
          style={{ height: 32, fontSize: 11 }}
        >
          <option value="ALL">Risk: All Levels</option>
          <option value="CRITICAL">Critical (&gt; 60)</option>
          <option value="HIGH">High (41 – 60)</option>
          <option value="MEDIUM">Medium (21 – 40)</option>
          <option value="LOW">Low (0 – 20)</option>
          <option value="SECURE">Secure Baseline</option>
        </select>

        {/* TLS Version Filter */}
        <select
          value={tlsFilter}
          onChange={(e) => setTlsFilter(e.target.value)}
          className="header-btn"
          style={{ height: 32, fontSize: 11 }}
        >
          <option value="ALL">TLS Version: All</option>
          <option value="TLS 1.3">TLS 1.3</option>
          <option value="TLS 1.2">TLS 1.2</option>
          <option value="TLS 1.1">TLS 1.1 (Deprecated)</option>
          <option value="TLS 1.0">TLS 1.0 (Deprecated)</option>
          <option value="SSL 3.0">SSL 3.0 (Vulnerable)</option>
          <option value="Cleartext">Cleartext (No TLS)</option>
        </select>

        {/* Certificate Status Filter */}
        <select
          value={certFilter}
          onChange={(e) => setCertFilter(e.target.value)}
          className="header-btn"
          style={{ height: 32, fontSize: 11 }}
        >
          <option value="ALL">Cert Status: All</option>
          <option value="VALID">Valid Certificate</option>
          <option value="EXPIRED">Expired Certificate</option>
          <option value="WEAK_KEY">Weak RSA Key</option>
          <option value="SELF_SIGNED">Self-Signed</option>
          <option value="NOT OBSERVABLE">Not Observable</option>
        </select>
      </div>

      {/* Reconstructed Sessions Data Table */}
      <div className="panel-card" style={{ marginBottom: 0 }}>
        <div className="panel-header">
          <span className="panel-title">
            <Network size={15} style={{ color: 'var(--accent-teal)' }} />
            RECONSTRUCTED EMAIL NETWORK SESSIONS
          </span>
          <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
            SHOWING {filtered.length} OF {sessions.length} SESSIONS (SELECT ROW TO DEEP INSPECT)
          </span>
        </div>

        {sessions.length === 0 ? (
          <EmptyState
            title="NO EMAIL SESSIONS CAPTURED"
            description="Reconstructed sessions will appear here once evidence PCAPs with SMTP, IMAP, or POP3 traffic are ingested and analyzed."
          />
        ) : filtered.length === 0 ? (
          <div style={{ padding: 48, textAlign: 'center', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 12 }}>
            No reconstructed sessions match the specified filter criteria.
          </div>
        ) : (
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th onClick={() => toggleSort('id')} style={{ cursor: 'pointer' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                      SESSION ID
                      <ArrowUpDown size={11} />
                    </div>
                  </th>
                  <th>PROTOCOL</th>
                  <th>SOURCE (CLIENT)</th>
                  <th>DESTINATION (SERVER)</th>
                  <th>STARTTLS</th>
                  <th>TLS DETECTED</th>
                  <th>TLS VERSION</th>
                  <th>CIPHER SUITE</th>
                  <th onClick={() => toggleSort('risk')} style={{ cursor: 'pointer' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                      RISK SCORE
                      <ArrowUpDown size={11} />
                    </div>
                  </th>
                  <th>CERT STATUS</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((s) => (
                  <tr key={s.session_id} onClick={() => onSelectSession(s)}>
                    <td>
                      <span className="mono-cell" style={{ color: 'var(--accent-cyan)', fontWeight: 700 }}>
                        {s.session_id}
                      </span>
                    </td>
                    <td>
                      <span className="mono-cell" style={{ fontWeight: 700, color: '#FFFFFF' }}>
                        {s.protocol}
                      </span>
                    </td>
                    <td className="mono-cell">
                      {s.network.src_ip}:{s.network.src_port}
                    </td>
                    <td className="mono-cell">
                      {s.network.dst_ip}:{s.network.dst_port}
                    </td>
                    <td>
                      <StatusBadge status={s.starttls_status} />
                    </td>
                    <td className="mono-cell">
                      {s.tls.tls_detected ? (
                        <span style={{ color: 'var(--status-secure)' }}>YES</span>
                      ) : (
                        <span style={{ color: 'var(--status-critical)' }}>NO</span>
                      )}
                    </td>
                    <td className="mono-cell" style={{ color: '#E2E8F0' }}>
                      {s.tls.tls_version}
                    </td>
                    <td className="mono-cell" style={{ maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {s.tls.cipher_suite}
                    </td>
                    <td>
                      <RiskBadge level={s.risk_level} score={s.risk_score} />
                    </td>
                    <td>
                      <StatusBadge status={s.certificate.certificate_status} />
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <button
                        className="header-btn"
                        style={{ height: 24, padding: '0 8px', fontSize: 10.5 }}
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectSession(s);
                        }}
                      >
                        Inspect
                        <ChevronRight size={12} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
