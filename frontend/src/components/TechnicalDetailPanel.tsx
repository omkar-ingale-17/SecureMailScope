import React, { useState } from 'react';
import type { SessionRecord } from '../services/api';
import { StatusBadge } from './Badges';
import { Copy, Check, Network, Lock, Key } from 'lucide-react';

interface TechnicalDetailPanelProps {
  session: SessionRecord;
}

export const TechnicalDetailPanel: React.FC<TechnicalDetailPanelProps> = ({ session }) => {
  const { network, tls, certificate } = session;
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const handleCopy = (key: string, val: any) => {
    if (!val || val === 'NOT OBSERVABLE') return;
    navigator.clipboard.writeText(String(val));
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1800);
  };

  const renderValue = (key: string, val: any, mono = true) => {
    if (val === undefined || val === null || val === '' || val === 'NOT OBSERVABLE') {
      return <span className="val-not-observable">NOT OBSERVABLE</span>;
    }
    const strVal = String(val);
    return (
      <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
        <span style={{ fontFamily: mono ? 'var(--font-mono)' : 'inherit' }}>{strVal}</span>
        <button
          className="header-btn"
          style={{ height: 18, width: 18, padding: 0, justifyContent: 'center' }}
          onClick={() => handleCopy(key, strVal)}
          title="Copy value"
        >
          {copiedKey === key ? (
            <Check size={9} style={{ color: 'var(--status-secure)' }} />
          ) : (
            <Copy size={9} />
          )}
        </button>
      </div>
    );
  };

  return (
    <div className="tech-details-grid">
      {/* 1. Network Telemetry */}
      <div className="tech-group-card">
        <div className="tech-group-title" style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
          <Network size={14} style={{ color: 'var(--accent-teal)' }} />
          <span>NETWORK & LAYER 4 FLOW TELEMETRY</span>
        </div>
        <div className="tech-property-row">
          <span className="tech-prop-key">Source (Client IP):</span>
          <span className="tech-prop-val">{renderValue('src_ip', network.src_ip)}</span>
        </div>
        <div className="tech-property-row">
          <span className="tech-prop-key">Source Port:</span>
          <span className="tech-prop-val">{renderValue('src_port', network.src_port)}</span>
        </div>
        <div className="tech-property-row">
          <span className="tech-prop-key">Destination (Server IP):</span>
          <span className="tech-prop-val">{renderValue('dst_ip', network.dst_ip)}</span>
        </div>
        <div className="tech-property-row">
          <span className="tech-prop-key">Destination Port:</span>
          <span className="tech-prop-val">{renderValue('dst_port', network.dst_port)}</span>
        </div>
        <div className="tech-property-row">
          <span className="tech-prop-key">Packet Count:</span>
          <span className="tech-prop-val">{renderValue('pkts', `${network.packet_count} packets`, false)}</span>
        </div>
        <div className="tech-property-row">
          <span className="tech-prop-key">Duration:</span>
          <span className="tech-prop-val">{renderValue('duration', `${network.session_duration}s`, false)}</span>
        </div>
        <div className="tech-property-row">
          <span className="tech-prop-key">Stream Start:</span>
          <span className="tech-prop-val">{renderValue('start_time', network.start_time)}</span>
        </div>
        <div className="tech-property-row">
          <span className="tech-prop-key">Stream End:</span>
          <span className="tech-prop-val">{renderValue('end_time', network.end_time)}</span>
        </div>
        <div className="tech-property-row">
          <span className="tech-prop-key">STARTTLS Command:</span>
          <span className="tech-prop-val">
            <StatusBadge status={session.starttls_status} />
          </span>
        </div>
      </div>

      {/* 2. TLS & Cryptographic Parameters */}
      <div className="tech-group-card">
        <div className="tech-group-title" style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
          <Lock size={14} style={{ color: 'var(--accent-cyan)' }} />
          <span>TLS HANDSHAKE & CIPHER PARAMETERS</span>
        </div>
        <div className="tech-property-row">
          <span className="tech-prop-key">Encryption Observed:</span>
          <span className="tech-prop-val">
            {tls.tls_detected ? (
              <span className="badge badge-secure">
                <span className="badge-dot" />
                TLS NEGOTIATED
              </span>
            ) : (
              <span className="badge badge-critical">
                <span className="badge-dot" />
                CLEARTEXT INSECURE
              </span>
            )}
          </span>
        </div>
        <div className="tech-property-row">
          <span className="tech-prop-key">TLS Protocol Version:</span>
          <span className="tech-prop-val">{renderValue('tls_version', tls.tls_version)}</span>
        </div>
        <div className="tech-property-row">
          <span className="tech-prop-key">Negotiated Cipher Suite:</span>
          <span className="tech-prop-val">{renderValue('cipher_suite', tls.cipher_suite)}</span>
        </div>
        <div className="tech-property-row">
          <span className="tech-prop-key">Cipher Hex Identifier:</span>
          <span className="tech-prop-val">{renderValue('cipher_code', tls.cipher_code)}</span>
        </div>
        <div className="tech-property-row">
          <span className="tech-prop-key">Key Exchange Mechanism:</span>
          <span className="tech-prop-val">{renderValue('key_exchange', tls.key_exchange)}</span>
        </div>
        <div className="tech-property-row">
          <span className="tech-prop-key">Forward Secrecy (PFS):</span>
          <span className="tech-prop-val">{renderValue('pfs', tls.forward_secrecy)}</span>
        </div>
        <div className="tech-property-row">
          <span className="tech-prop-key">Server Name Indication (SNI):</span>
          <span className="tech-prop-val">{renderValue('sni', tls.sni)}</span>
        </div>
        <div className="tech-property-row">
          <span className="tech-prop-key">ALPN Negotiation:</span>
          <span className="tech-prop-val">{renderValue('alpn', tls.alpn)}</span>
        </div>
        <div className="tech-property-row">
          <span className="tech-prop-key">Handshake State:</span>
          <span className="tech-prop-val">{renderValue('hs_status', tls.handshake_status)}</span>
        </div>
      </div>

      {/* 3. X.509 Certificate Telemetry */}
      <div className="tech-group-card">
        <div className="tech-group-title" style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
          <Key size={14} style={{ color: '#F59E0B' }} />
          <span>X.509 CERTIFICATE INFRASTRUCTURE</span>
        </div>
        <div className="tech-property-row">
          <span className="tech-prop-key">Certificate Validation:</span>
          <span className="tech-prop-val">
            <StatusBadge status={certificate.certificate_status} />
          </span>
        </div>
        <div className="tech-property-row">
          <span className="tech-prop-key">Subject (Common Name):</span>
          <span className="tech-prop-val">{renderValue('subject', certificate.subject)}</span>
        </div>
        <div className="tech-property-row">
          <span className="tech-prop-key">Issuer (Authority):</span>
          <span className="tech-prop-val">{renderValue('issuer', certificate.issuer)}</span>
        </div>
        <div className="tech-property-row">
          <span className="tech-prop-key">Not Valid Before:</span>
          <span className="tech-prop-val">{renderValue('valid_from', certificate.valid_from)}</span>
        </div>
        <div className="tech-property-row">
          <span className="tech-prop-key">Not Valid After (Expiry):</span>
          <span className="tech-prop-val">{renderValue('valid_until', certificate.valid_until)}</span>
        </div>
        <div className="tech-property-row">
          <span className="tech-prop-key">Key Algorithm & Length:</span>
          <span className="tech-prop-val">
            {!certificate.public_key_algorithm || certificate.public_key_algorithm.includes('OBSERVABLE')
              ? renderValue('key_info', 'NOT OBSERVABLE')
              : renderValue('key_info', `${certificate.public_key_algorithm} ${certificate.key_length}`)}
          </span>
        </div>
        <div className="tech-property-row">
          <span className="tech-prop-key">Signature Algorithm:</span>
          <span className="tech-prop-val">{renderValue('sig_algo', certificate.signature_algorithm)}</span>
        </div>
        <div className="tech-property-row">
          <span className="tech-prop-key">Subject Alt Names (SAN):</span>
          <span className="tech-prop-val">
            {certificate.san_list && certificate.san_list.length > 0 ? (
              renderValue('san_list', certificate.san_list.join(', '))
            ) : (
              <span className="val-not-observable">NONE SPECIFIED</span>
            )}
          </span>
        </div>
        <div className="tech-property-row">
          <span className="tech-prop-key">Fingerprint (SHA-256):</span>
          <span className="tech-prop-val" style={{ fontSize: 10 }}>
            {renderValue('fingerprint', certificate.fingerprint_sha256)}
          </span>
        </div>
      </div>
    </div>
  );
};
