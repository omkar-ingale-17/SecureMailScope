import React, { useState, useMemo } from 'react';
import type { Finding, SessionRecord } from '../services/api';
import { SeverityBadge, RiskBadge } from '../components/Badges';
import { EmptyState, LoadingState } from '../components/FeedbackStates';
import {
  AlertTriangle, ShieldAlert, AlertOctagon, ShieldCheck,
  Search, ChevronRight, ArrowLeft, Info, Shield, Network,
  Clock, Lock, X,
} from 'lucide-react';

// ─── Types ───────────────────────────────────────────────────────────
interface FindingsPageProps {
  findings: Finding[];
  sessions: SessionRecord[];
  totalSessionsCount?: number;
  loading: boolean;
  onNavigateToSession: (sessionId: string) => void;
}

interface SessionGroup {
  session: SessionRecord;
  findings: Finding[];
  highestSeverity: string;
  critCount: number;
  highCount: number;
  medCount: number;
  lowCount: number;
}

// ─── Severity helpers ─────────────────────────────────────────────────
const SEV_ORDER: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
const SEV_COLOR: Record<string, string> = {
  CRITICAL: 'var(--status-critical)',
  HIGH: 'var(--status-high)',
  MEDIUM: 'var(--status-medium)',
  LOW: 'var(--status-low)',
  INFO: '#64748b',
};
const SEV_BG: Record<string, string> = {
  CRITICAL: 'rgba(239,68,68,0.10)',
  HIGH: 'rgba(249,115,22,0.10)',
  MEDIUM: 'rgba(234,179,8,0.10)',
  LOW: 'rgba(6,182,212,0.10)',
  INFO: 'rgba(100,116,139,0.08)',
};

function highestSev(fs: Finding[]): string {
  if (!fs.length) return 'SECURE';
  return fs.reduce(
    (best, f) => ((SEV_ORDER[f.severity] ?? 9) < (SEV_ORDER[best] ?? 9) ? f.severity : best),
    fs[0].severity
  );
}

// ─── Finding Detail Drawer (Level 3) ─────────────────────────────────
interface DrawerProps {
  finding: Finding;
  onClose: () => void;
  onNavigateToSession?: (id: string) => void;
}
const FindingDrawer: React.FC<DrawerProps> = ({ finding, onClose, onNavigateToSession }) => {
  const sc = SEV_COLOR[finding.severity] ?? '#94a3b8';
  const sb = SEV_BG[finding.severity] ?? 'rgba(100,116,139,0.08)';
  return (
    <>
      <div onClick={onClose} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.48)', zIndex: 1000 }} />
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          position: 'fixed', top: 0, right: 0, bottom: 0,
          width: 'min(520px,95vw)', background: '#0D1420',
          borderLeft: '1px solid rgba(0,242,254,0.18)',
          zIndex: 1001, display: 'flex', flexDirection: 'column', overflow: 'hidden',
        }}
      >
        {/* Header */}
        <div style={{
          display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between',
          padding: '18px 20px 14px', borderBottom: '1px solid rgba(255,255,255,0.07)',
          background: sb, flexShrink: 0,
        }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
              <SeverityBadge severity={finding.severity} />
              <span style={{
                fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)',
                background: 'rgba(0,0,0,0.3)', padding: '2px 6px', borderRadius: 3,
              }}>
                {finding.rule_id}
              </span>
            </div>
            <div style={{ fontSize: 15, fontWeight: 700, color: '#FFFFFF', lineHeight: 1.3 }}>
              {finding.title}
            </div>
          </div>
          <button className="header-btn" onClick={onClose}
            style={{ height: 28, width: 28, padding: 0, justifyContent: 'center', flexShrink: 0, marginLeft: 12 }}>
            <X size={14} />
          </button>
        </div>
        {/* Scrollable body */}
        <div style={{ overflowY: 'auto', flex: 1, padding: '18px 20px' }}>
          {/* Identifiers grid */}
          <div style={{
            display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10,
            background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.07)',
            borderRadius: 6, padding: 12, marginBottom: 16,
            fontFamily: 'var(--font-mono)', fontSize: 11,
          }}>
            {[
              { label: 'SEVERITY',    value: finding.severity,                 color: sc },
              { label: 'PROTOCOL',    value: finding.protocol,                 color: '#FFFFFF' },
              { label: 'SESSION',     value: finding.session_id,               color: 'var(--accent-teal)', onClick: onNavigateToSession ? () => onNavigateToSession!(finding.session_id) : undefined },
              { label: 'EVIDENCE',    value: finding.evidence_id,              color: 'var(--accent-cyan)' },
              { label: 'DETECTED AT', value: finding.detected_at || 'N/A',     color: '#94a3b8' },
              { label: 'STATUS',      value: finding.status || 'DETECTED',     color: '#94a3b8' },
            ].map(({ label, value, color, onClick }) => (
              <div key={label}>
                <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: 9.5, marginBottom: 2 }}>{label}</span>
                <span
                  style={{ color, fontWeight: 600, cursor: onClick ? 'pointer' : 'default', textDecoration: onClick ? 'underline' : 'none', wordBreak: 'break-all' }}
                  onClick={onClick}
                >
                  {value || 'Not available'}
                </span>
              </div>
            ))}
          </div>
          {/* Observation */}
          <section style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', marginBottom: 6, textTransform: 'uppercase', fontFamily: 'var(--font-mono)', letterSpacing: '0.8px' }}>
              OBSERVATION
            </div>
            <div style={{ color: '#E2E8F0', fontSize: 13, lineHeight: 1.65 }}>
              {finding.description || 'Not available'}
            </div>
          </section>
          {/* Technical evidence */}
          {finding.technical_details && finding.technical_details !== 'NOT OBSERVABLE' && (
            <section style={{ marginBottom: 16 }}>
              <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', marginBottom: 6, textTransform: 'uppercase', fontFamily: 'var(--font-mono)', letterSpacing: '0.8px' }}>
                TECHNICAL EVIDENCE
              </div>
              <div style={{
                background: '#06090F', border: '1px solid rgba(0,242,254,0.12)',
                borderRadius: 5, padding: 12, fontFamily: 'var(--font-mono)',
                fontSize: 11.5, color: 'var(--accent-cyan)', lineHeight: 1.6, wordBreak: 'break-word',
              }}>
                {finding.technical_details}
              </div>
            </section>
          )}
          {/* Why it matters */}
          {finding.why_it_matters && (
            <section style={{ marginBottom: 16, background: 'rgba(239,68,68,0.05)', border: '1px solid rgba(239,68,68,0.2)', borderRadius: 5, padding: 12 }}>
              <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--status-critical)', marginBottom: 6, textTransform: 'uppercase', fontFamily: 'var(--font-mono)', letterSpacing: '0.8px', display: 'flex', alignItems: 'center', gap: 6 }}>
                <ShieldAlert size={13} /> WHY IT MATTERS
              </div>
              <div style={{ color: '#F1F5F9', fontSize: 12.5, lineHeight: 1.6 }}>{finding.why_it_matters}</div>
            </section>
          )}
          {/* Recommendation */}
          {finding.recommendation && (
            <section style={{ background: 'rgba(10,228,186,0.05)', border: '1px solid rgba(10,228,186,0.22)', borderRadius: 5, padding: 12 }}>
              <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--accent-teal)', marginBottom: 6, textTransform: 'uppercase', fontFamily: 'var(--font-mono)', letterSpacing: '0.8px', display: 'flex', alignItems: 'center', gap: 6 }}>
                <ShieldCheck size={13} /> RECOMMENDATION
              </div>
              <div style={{ color: '#F1F5F9', fontSize: 12.5, lineHeight: 1.6 }}>{finding.recommendation}</div>
            </section>
          )}
        </div>
      </div>
    </>
  );
};

// ─── Session Findings Panel (Level 2) ────────────────────────────────
interface SessionPanelProps {
  group: SessionGroup;
  onBack: () => void;
  onSelectFinding: (f: Finding) => void;
  onNavigateToSession: (id: string) => void;
}
const SessionFindingsPanel: React.FC<SessionPanelProps> = ({ group, onBack, onSelectFinding, onNavigateToSession }) => {
  const { session, findings } = group;
  const sc = SEV_COLOR[group.highestSeverity] ?? '#94a3b8';
  const sorted = [...findings].sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));
  const dur = typeof session.network.session_duration === 'number'
    ? `${session.network.session_duration.toFixed(2)}s`
    : 'Not available';

  return (
    <div>
      <button className="header-btn" onClick={onBack} style={{ marginBottom: 16, height: 30 }}>
        <ArrowLeft size={13} /><span>All Sessions</span>
      </button>

      {/* Session header */}
      <div className="panel-card" style={{
        marginBottom: 18,
        border: `1px solid ${sc}40`,
        background: `linear-gradient(135deg, rgba(0,0,0,0) 0%, ${SEV_BG[group.highestSeverity] ?? 'rgba(0,0,0,0)'} 100%)`,
      }}>
        <div className="panel-header" style={{ borderBottom: '1px solid rgba(255,255,255,0.07)', paddingBottom: 12, marginBottom: 14 }}>
          <span className="panel-title" style={{ color: '#FFFFFF', fontSize: 14 }}>
            <Network size={15} style={{ color: 'var(--accent-cyan)' }} />
            SESSION {session.session_id}
          </span>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <RiskBadge level={session.risk_level} score={session.risk_score} />
            <button className="header-btn" style={{ height: 26, fontSize: 11 }} onClick={() => onNavigateToSession(session.session_id)}>
              Full Inspect <ChevronRight size={12} />
            </button>
          </div>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill,minmax(160px,1fr))', gap: 12, fontFamily: 'var(--font-mono)', fontSize: 11 }}>
          {[
            { icon: <Network size={11} />, label: 'PROTOCOL',    value: session.protocol },
            { icon: <Network size={11} />, label: 'SOURCE',      value: `${session.network.src_ip}:${session.network.src_port}` },
            { icon: <Network size={11} />, label: 'DESTINATION', value: `${session.network.dst_ip}:${session.network.dst_port}` },
            { icon: <Clock   size={11} />, label: 'DURATION',    value: dur },
            { icon: <Lock    size={11} />, label: 'TLS',         value: session.tls.tls_detected ? session.tls.tls_version : 'No TLS (Cleartext)' },
            { icon: <Lock    size={11} />, label: 'STARTTLS',    value: session.starttls_status.replace(/_/g, ' ') },
            { icon: <Shield  size={11} />, label: 'CIPHER',      value: session.tls.cipher_suite || 'Not observable' },
            { icon: <Shield  size={11} />, label: 'CERT STATUS', value: session.certificate.certificate_status.replace(/_/g, ' ') },
          ].map(({ icon, label, value }) => (
            <div key={label}>
              <div style={{ color: 'var(--text-muted)', fontSize: 9.5, marginBottom: 3, display: 'flex', alignItems: 'center', gap: 4 }}>{icon} {label}</div>
              <div style={{ color: '#E2E8F0', fontWeight: 600, wordBreak: 'break-all' }}>{value || 'Not available'}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Severity distribution */}
      <div style={{ display: 'flex', gap: 10, marginBottom: 16, flexWrap: 'wrap', alignItems: 'center' }}>
        {[
          { label: 'CRITICAL', count: group.critCount, color: 'var(--status-critical)', bg: 'rgba(239,68,68,0.12)',  br: 'rgba(239,68,68,0.3)' },
          { label: 'HIGH',     count: group.highCount, color: 'var(--status-high)',     bg: 'rgba(249,115,22,0.10)', br: 'rgba(249,115,22,0.25)' },
          { label: 'MEDIUM',   count: group.medCount,  color: 'var(--status-medium)',   bg: 'rgba(234,179,8,0.10)',  br: 'rgba(234,179,8,0.25)' },
          { label: 'LOW',      count: group.lowCount,  color: 'var(--status-low)',      bg: 'rgba(6,182,212,0.10)',  br: 'rgba(6,182,212,0.25)' },
        ].map(({ label, count, color, bg, br }) => count > 0 ? (
          <div key={label} style={{ background: bg, border: `1px solid ${br}`, borderRadius: 5, padding: '5px 12px', display: 'flex', alignItems: 'center', gap: 6, fontFamily: 'var(--font-mono)', fontSize: 11 }}>
            <span style={{ color, fontWeight: 800, fontSize: 14 }}>{count}</span>
            <span style={{ color }}>{label}</span>
          </div>
        ) : null)}
        <div style={{ marginLeft: 'auto', fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)' }}>
          {findings.length} FINDING{findings.length !== 1 ? 'S' : ''} TOTAL
        </div>
      </div>

      {/* Finding cards */}
      <div className="panel-card" style={{ padding: 0 }}>
        <div className="panel-header">
          <span className="panel-title">
            <AlertTriangle size={14} style={{ color: 'var(--status-high)' }} />
            SECURITY FINDINGS ({findings.length})
          </span>
          <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>CLICK FINDING TO INSPECT</span>
        </div>
        <div>
          {sorted.map((f, idx) => {
            const fsc = SEV_COLOR[f.severity] ?? '#94a3b8';
            const fsb = SEV_BG[f.severity] ?? 'rgba(0,0,0,0)';
            return (
              <div key={f.id} onClick={() => onSelectFinding(f)}
                style={{ padding: '14px 18px', cursor: 'pointer', borderBottom: idx < sorted.length - 1 ? '1px solid rgba(255,255,255,0.05)' : 'none', display: 'flex', alignItems: 'flex-start', gap: 14, transition: 'background 0.15s' }}
                onMouseEnter={(e) => (e.currentTarget.style.background = fsb)}
                onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
              >
                <div style={{ width: 3, minHeight: 44, borderRadius: 2, background: fsc, flexShrink: 0, alignSelf: 'stretch' }} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 4 }}>
                    <SeverityBadge severity={f.severity} />
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--accent-cyan)', background: 'rgba(0,242,254,0.08)', padding: '2px 6px', borderRadius: 3 }}>{f.rule_id}</span>
                  </div>
                  <div style={{ fontWeight: 700, color: '#FFFFFF', fontSize: 13, marginBottom: 3 }}>{f.title}</div>
                  <div style={{ fontSize: 11.5, color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                    {f.description ? f.description.slice(0, 140) + (f.description.length > 140 ? '\u2026' : '') : ''}
                  </div>
                </div>
                <ChevronRight size={16} style={{ color: 'var(--text-muted)', flexShrink: 0, marginTop: 10 }} />
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

// ─── Main FindingsPage (Level 1) ──────────────────────────────────────
export const FindingsPage: React.FC<FindingsPageProps> = ({
  findings, sessions, totalSessionsCount, loading, onNavigateToSession,
}) => {
  const [selectedGroup, setSelectedGroup]   = useState<SessionGroup | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [searchTerm,   setSearchTerm]   = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [protocolFilter, setProtocolFilter] = useState('ALL');
  const [sortMode, setSortMode] = useState<'severity' | 'count' | 'id' | 'protocol'>('severity');

  if (loading) return <LoadingState message="Loading Forensic Rule Findings..." />;

  // Build session groups — use session.findings[] as the authoritative per-session source
  // eslint-disable-next-line react-hooks/rules-of-hooks
  const groups: SessionGroup[] = useMemo(() =>
    sessions
      .filter((s) => s.findings && s.findings.length > 0)
      .map((s) => {
        const fs = s.findings;
        return {
          session: s, findings: fs,
          highestSeverity: highestSev(fs),
          critCount: fs.filter((f) => f.severity === 'CRITICAL').length,
          highCount: fs.filter((f) => f.severity === 'HIGH').length,
          medCount:  fs.filter((f) => f.severity === 'MEDIUM').length,
          lowCount:  fs.filter((f) => f.severity === 'LOW').length,
        };
      }),
    [sessions]
  );

  // Global metrics — derive from the authoritative flat findings list
  const totalFindings    = findings.length;
  const affectedSessions = groups.length;
  const totalSessions    = sessions.length;
  const critGlobal = findings.filter((f) => f.severity === 'CRITICAL').length;
  const highGlobal = findings.filter((f) => f.severity === 'HIGH').length;
  const medGlobal  = findings.filter((f) => f.severity === 'MEDIUM').length;
  const lowGlobal  = findings.filter((f) => f.severity === 'LOW').length;
  const multiViolation = groups.filter((g) => g.findings.length > 1).length;

  // Filtered + sorted groups
  // eslint-disable-next-line react-hooks/rules-of-hooks
  const filteredGroups = useMemo(() => {
    let r = [...groups];
    if (severityFilter !== 'ALL') r = r.filter((g) => g.findings.some((f) => f.severity === severityFilter));
    if (protocolFilter !== 'ALL') r = r.filter((g) => g.session.protocol === protocolFilter);
    if (searchTerm) {
      const q = searchTerm.toLowerCase();
      r = r.filter((g) =>
        g.session.session_id.toLowerCase().includes(q) ||
        g.session.protocol.toLowerCase().includes(q) ||
        g.session.network.src_ip.toLowerCase().includes(q) ||
        g.session.network.dst_ip.toLowerCase().includes(q) ||
        g.findings.some((f) =>
          f.title.toLowerCase().includes(q) ||
          f.rule_id.toLowerCase().includes(q) ||
          f.description.toLowerCase().includes(q)
        )
      );
    }
    r.sort((a, b) => {
      if (sortMode === 'severity') return (SEV_ORDER[a.highestSeverity] ?? 9) - (SEV_ORDER[b.highestSeverity] ?? 9);
      if (sortMode === 'count')    return b.findings.length - a.findings.length;
      if (sortMode === 'protocol') return a.session.protocol.localeCompare(b.session.protocol);
      return a.session.session_id.localeCompare(b.session.session_id);
    });
    return r;
  }, [groups, severityFilter, protocolFilter, searchTerm, sortMode]);

  // ── LEVEL 2: Session Findings ────────────────────────────────────────
  if (selectedGroup) {
    return (
      <>
        <SessionFindingsPanel
          group={selectedGroup}
          onBack={() => setSelectedGroup(null)}
          onSelectFinding={setSelectedFinding}
          onNavigateToSession={onNavigateToSession}
        />
        {selectedFinding && (
          <FindingDrawer
            finding={selectedFinding}
            onClose={() => setSelectedFinding(null)}
            onNavigateToSession={(id) => { setSelectedFinding(null); setSelectedGroup(null); onNavigateToSession(id); }}
          />
        )}
      </>
    );
  }

  // ── LEVEL 1: Session List ────────────────────────────────────────────
  return (
    <div>
      {/* Metric cards */}
      <div className="metric-grid" style={{ marginBottom: 16 }}>
        {([
          { icon: <AlertTriangle size={13} style={{ color: 'var(--accent-cyan)' }} />,       label: 'SECURITY FINDINGS',  value: String(totalFindings),                      sub: 'Total rule violation detections',                            vc: '#FFFFFF' },
          { icon: <AlertOctagon  size={13} style={{ color: 'var(--accent-teal)' }} />,       label: 'AFFECTED SESSIONS',  value: String(affectedSessions),                   sub: `${affectedSessions} of ${totalSessionsCount ?? totalSessions} streams flagged`, vc: '#FFFFFF' },
          { icon: <ShieldAlert   size={13} style={{ color: 'var(--status-critical)' }} />,   label: 'CRITICAL / HIGH',    value: `${critGlobal} / ${highGlobal}`,             sub: `${medGlobal} medium, ${lowGlobal} low`,                      vc: 'var(--status-critical)' },
          { icon: <ShieldCheck   size={13} style={{ color: '#f59e0b' }} />,                  label: 'MULTI-VIOLATION',    value: String(multiViolation),                     sub: 'Sessions with 2+ concurrent violations',                     vc: '#f59e0b' },
        ] as const).map(({ icon, label, value, sub, vc }) => (
          <div key={label} className="panel-card" style={{ padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: 4 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--text-muted)', fontSize: 10, fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>{icon} {label}</div>
            <div style={{ fontSize: 26, fontWeight: 800, color: vc, fontFamily: 'var(--font-mono)' }}>{value}</div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{sub}</div>
          </div>
        ))}
      </div>

      {/* Explainability banner */}
      <div style={{ background: 'rgba(0,242,254,0.04)', border: '1px solid rgba(0,242,254,0.15)', borderRadius: 7, padding: '10px 16px', marginBottom: 16, display: 'flex', alignItems: 'flex-start', gap: 10, fontSize: 12, lineHeight: 1.55, color: 'var(--text-secondary)' }}>
        <Info size={16} style={{ color: 'var(--accent-cyan)', flexShrink: 0, marginTop: 1 }} />
        <div>
          <strong style={{ color: '#FFFFFF' }}>Session-Centric Investigation:</strong>{' '}
          The <strong style={{ color: 'var(--accent-cyan)' }}>{totalFindings} security findings</strong> originate from{' '}
          <strong style={{ color: '#FFFFFF' }}>{affectedSessions} affected sessions</strong> (out of {totalSessionsCount ?? totalSessions} total streams).{' '}
          <strong style={{ color: 'var(--status-critical)' }}>{multiViolation} sessions</strong> triggered 2+ concurrent violations — a single stream can violate multiple cryptographic rules simultaneously.
          Select a session below to investigate.
        </div>
      </div>

      {/* Filter / Sort controls */}
      <div style={{ display: 'flex', gap: 10, marginBottom: 14, flexWrap: 'wrap', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, background: 'var(--bg-card)', border: '1px solid var(--border-normal)', borderRadius: 6, padding: '6px 12px', flex: '1 1 220px' }}>
          <Search size={13} style={{ color: 'var(--text-muted)' }} />
          <input type="text" placeholder="Search session ID, IP, rule, finding title…" value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{ background: 'transparent', border: 'none', outline: 'none', color: '#FFFFFF', width: '100%', fontSize: 12, fontFamily: 'var(--font-sans)' }} />
          {searchTerm && (
            <button onClick={() => setSearchTerm('')} style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0, color: 'var(--text-muted)', display: 'flex' }}>
              <X size={13} />
            </button>
          )}
        </div>
        <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)} className="header-btn" style={{ height: 32, fontSize: 11 }}>
          <option value="ALL">Severity: All</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
        <select value={protocolFilter} onChange={(e) => setProtocolFilter(e.target.value)} className="header-btn" style={{ height: 32, fontSize: 11 }}>
          <option value="ALL">Protocol: All</option>
          <option value="SMTP">SMTP</option>
          <option value="IMAP">IMAP</option>
          <option value="POP3">POP3</option>
        </select>
        <select value={sortMode} onChange={(e) => setSortMode(e.target.value as typeof sortMode)} className="header-btn" style={{ height: 32, fontSize: 11 }}>
          <option value="severity">Sort: Highest Severity</option>
          <option value="count">Sort: Most Findings</option>
          <option value="id">Sort: Session ID</option>
          <option value="protocol">Sort: Protocol</option>
        </select>
      </div>

      {/* Session list */}
      {groups.length === 0 ? (
        <EmptyState title="NO SECURITY FINDINGS DETECTED" description="All analyzed traffic conforms to the standard cryptographic baseline, or no evidence has been ingested yet." />
      ) : filteredGroups.length === 0 ? (
        <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 12 }}>No sessions match the filter criteria.</div>
      ) : (
        <div className="panel-card" style={{ padding: 0 }}>
          <div className="panel-header">
            <span className="panel-title"><AlertTriangle size={14} style={{ color: 'var(--accent-cyan)' }} /> SESSIONS WITH SECURITY FINDINGS</span>
            <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{filteredGroups.length} OF {groups.length} — CLICK TO INVESTIGATE</span>
          </div>
          <div>
            {filteredGroups.map((group, idx) => {
              const sc2 = SEV_COLOR[group.highestSeverity] ?? '#94a3b8';
              const sb2 = SEV_BG[group.highestSeverity] ?? 'rgba(0,0,0,0)';
              return (
                <div key={group.session.session_id} onClick={() => setSelectedGroup(group)}
                  style={{ padding: '14px 18px', cursor: 'pointer', borderBottom: idx < filteredGroups.length - 1 ? '1px solid rgba(255,255,255,0.05)' : 'none', display: 'flex', alignItems: 'center', gap: 14, transition: 'background 0.15s', borderLeft: `3px solid ${sc2}` }}
                  onMouseEnter={(e) => (e.currentTarget.style.background = sb2)}
                  onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                >
                  {/* Session identity */}
                  <div style={{ flex: '0 0 auto', minWidth: 160 }}>
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 800, color: 'var(--accent-cyan)', marginBottom: 3 }}>{group.session.session_id}</div>
                    <div style={{ fontSize: 11, color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>{group.session.network.src_ip} → {group.session.network.dst_ip}</div>
                  </div>
                  {/* Protocol badge */}
                  <div style={{ flex: '0 0 auto', background: 'rgba(0,242,254,0.08)', border: '1px solid rgba(0,242,254,0.2)', borderRadius: 4, padding: '3px 9px', fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700, color: 'var(--accent-cyan)' }}>
                    {group.session.protocol}
                  </div>
                  {/* Severity chips */}
                  <div style={{ flex: 1, display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                    {group.critCount > 0 && <span style={{ background: 'rgba(239,68,68,0.15)', border: '1px solid rgba(239,68,68,0.35)', color: 'var(--status-critical)', borderRadius: 4, padding: '2px 8px', fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700 }}>● {group.critCount} Critical</span>}
                    {group.highCount > 0 && <span style={{ background: 'rgba(249,115,22,0.12)', border: '1px solid rgba(249,115,22,0.3)',  color: 'var(--status-high)',     borderRadius: 4, padding: '2px 8px', fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700 }}>● {group.highCount} High</span>}
                    {group.medCount  > 0 && <span style={{ background: 'rgba(234,179,8,0.10)',  border: '1px solid rgba(234,179,8,0.25)',   color: 'var(--status-medium)',   borderRadius: 4, padding: '2px 8px', fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700 }}>● {group.medCount} Medium</span>}
                    {group.lowCount  > 0 && <span style={{ background: 'rgba(6,182,212,0.10)',  border: '1px solid rgba(6,182,212,0.25)',   color: 'var(--status-low)',      borderRadius: 4, padding: '2px 8px', fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700 }}>● {group.lowCount} Low</span>}
                  </div>
                  {/* Finding count */}
                  <div style={{ flex: '0 0 auto', textAlign: 'right' }}>
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: 16, fontWeight: 800, color: sc2, marginBottom: 2 }}>{group.findings.length}</div>
                    <div style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>FINDING{group.findings.length !== 1 ? 'S' : ''}</div>
                  </div>
                  <div style={{ flex: '0 0 auto' }}><RiskBadge level={group.session.risk_level} score={group.session.risk_score} /></div>
                  <ChevronRight size={16} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
                </div>
              );
            })}
          </div>
        </div>
      )}

      {selectedFinding && (
        <FindingDrawer finding={selectedFinding} onClose={() => setSelectedFinding(null)}
          onNavigateToSession={(id) => { setSelectedFinding(null); onNavigateToSession(id); }} />
      )}
    </div>
  );
};
