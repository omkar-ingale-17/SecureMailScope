import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import type { SystemStatus } from '../services/api';
import { LoadingState } from '../components/FeedbackStates';
import { Settings, Cpu, ShieldCheck, CheckCircle2 } from 'lucide-react';

export const SettingsPage: React.FC = () => {
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .getSystemStatus()
      .then(setStatus)
      .catch((err: any) => console.error('Failed to load system status:', err))
      .finally(() => setLoading(false));
  }, []);

  if (loading || !status) {
    return <LoadingState message="Querying Forensics Engine Health..." />;
  }

  return (
    <div>
      <div className="panel-card" style={{ marginBottom: 24 }}>
        <div className="panel-header">
          <span className="panel-title">
            <Settings size={16} />
            FORENSIC SYSTEM HEALTH & ENGINE CAPABILITIES
          </span>
          <span className="forensic-mode-badge">
            <ShieldCheck size={12} />
            {status.forensic_mode}
          </span>
        </div>

        <div className="panel-body">
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 16 }}>
            {/* Core Forensics */}
            <div
              style={{
                background: 'var(--bg-surface)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 6,
                padding: 16,
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12, color: 'var(--accent-cyan)' }}>
                <Cpu size={16} />
                <span style={{ fontWeight: 700, fontSize: 12, textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>
                  ANALYSIS ENGINE RUNTIME
                </span>
              </div>
              <div className="tech-property-row">
                <span className="tech-prop-key">Application Version:</span>
                <span className="tech-prop-val">{status.app_version}</span>
              </div>
              <div className="tech-property-row">
                <span className="tech-prop-key">Forensic Analyzer Core:</span>
                <span className="tech-prop-val">{status.analyzer_version}</span>
              </div>
              <div className="tech-property-row">
                <span className="tech-prop-key">Analysis Engine Status:</span>
                <span className="tech-prop-val" style={{ color: 'var(--status-secure)' }}>
                  {status.engine_status}
                </span>
              </div>
              <div className="tech-property-row">
                <span className="tech-prop-key">Maximum PCAP Upload Size:</span>
                <span className="tech-prop-val">{status.max_upload_size_mb} MB</span>
              </div>
            </div>

            {/* Cryptographic Subsystem */}
            <div
              style={{
                background: 'var(--bg-surface)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 6,
                padding: 16,
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12, color: 'var(--accent-teal)' }}>
                <ShieldCheck size={16} />
                <span style={{ fontWeight: 700, fontSize: 12, textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>
                  CRYPTOGRAPHY & PARSER BINDINGS
                </span>
              </div>
              <div className="tech-property-row">
                <span className="tech-prop-key">OpenSSL / PyCA Cryptography:</span>
                <span className="tech-prop-val" style={{ color: 'var(--accent-teal)' }}>
                  ACTIVE (PyCA Cryptography 46.x)
                </span>
              </div>
              <div className="tech-property-row">
                <span className="tech-prop-key">Dissector / TShark Engine:</span>
                <span className="tech-prop-val" style={{ fontSize: 10.5 }}>
                  {status.tshark_status}
                </span>
              </div>
              <div className="tech-property-row">
                <span className="tech-prop-key">Supported Protocols:</span>
                <span className="tech-prop-val">SMTP, IMAP, POP3, STARTTLS, TLS 1.0-1.3</span>
              </div>
              <div className="tech-property-row">
                <span className="tech-prop-key">Database State:</span>
                <span className="tech-prop-val">{status.database_status}</span>
              </div>
            </div>
          </div>

          {/* Forensic Mode Description Box */}
          <div
            style={{
              marginTop: 20,
              background: '#090E1A',
              border: '1px solid var(--border-subtle)',
              borderRadius: 6,
              padding: 16,
              fontFamily: 'var(--font-mono)',
              fontSize: 12,
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--accent-cyan)', marginBottom: 8 }}>
              <CheckCircle2 size={16} />
              <span style={{ fontWeight: 700 }}>STRICT PASSIVE NETWORK FORENSICS GUARANTEE</span>
            </div>
            <p style={{ color: 'var(--text-secondary)', lineHeight: 1.6, margin: 0 }}>
              SecureMailScope operates strictly as an offline, passive network forensic investigation tool. It parses raw
              packet captures (PCAP/PCAPNG), reassembles TCP streams, evaluates X.509 certificates and TLS record layer handshakes,
              and generates explainable deterministic risk findings without connecting to live mail inboxes or analyzing proprietary
              email contents.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
