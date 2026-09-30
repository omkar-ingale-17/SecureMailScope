import React, { useState, useRef } from 'react';
import { api } from '../services/api';
import type { EvidenceRecord } from '../services/api';
import { StatusBadge } from '../components/Badges';
import {
  UploadCloud,
  Play,
  Eye,
  RefreshCw,
  AlertCircle,
  Trash2,
  Zap,
  Copy,
  Check,
  ShieldCheck,
  HardDrive,
  FileCode,
} from 'lucide-react';

interface EvidencePageProps {
  evidenceList: EvidenceRecord[];
  loading?: boolean;
  error?: string | null;
  onRefresh: () => void;
  onNavigateToSessionsForEvidence: (evidenceId: string) => void;
}

export const EvidencePage: React.FC<EvidencePageProps> = ({
  evidenceList,
  onRefresh,
  onNavigateToSessionsForEvidence,
}) => {
  const [isDragging, setIsDragging] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [latestUploaded, setLatestUploaded] = useState<EvidenceRecord | null>(null);
  const [analyzingId, setAnalyzingId] = useState<string | null>(null);
  const [autoProcess, setAutoProcess] = useState(true);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      await processFileUpload(e.dataTransfer.files[0]);
    }
  };

  const handleFileInputChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      await processFileUpload(e.target.files[0]);
    }
  };

  const processFileUpload = async (file: File) => {
    const validExts = ['.pcap', '.pcapng', '.cap'];
    const hasValidExt = validExts.some((ext) => file.name.toLowerCase().endsWith(ext));
    if (!hasValidExt) {
      setUploadError(`Invalid capture format. Accepted network forensic extensions: ${validExts.join(', ')}.`);
      return;
    }

    setUploadError(null);
    setIsUploading(true);

    try {
      const result = await api.uploadEvidence(file, autoProcess);
      setLatestUploaded(result);
      onRefresh();
    } catch (err: any) {
      setUploadError(err.message || 'Evidence intake failed.');
    } finally {
      setIsUploading(false);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  const handleTriggerAnalysis = async (evId: string) => {
    setAnalyzingId(evId);
    try {
      const res = await api.analyzeEvidence(evId);
      setLatestUploaded(res);
      onRefresh();
    } catch (err: any) {
      setUploadError(`Forensic analysis failed: ${err.message}`);
    } finally {
      setAnalyzingId(null);
    }
  };

  const handleDeleteEvidence = async (evId: string) => {
    if (!window.confirm(`Permanently delete forensic capture ${evId} and all associated session streams?`)) return;
    try {
      await api.deleteEvidence(evId);
      if (latestUploaded?.id === evId) {
        setLatestUploaded(null);
      }
      onRefresh();
    } catch (err: any) {
      setUploadError(`Failed to delete capture: ${err.message}`);
    }
  };

  const handleClearAll = async () => {
    if (!window.confirm('Delete ALL forensic captures and reset custody records, sessions, findings, and reports?')) return;
    try {
      await api.clearAllEvidence();
      setLatestUploaded(null);
      onRefresh();
    } catch (err: any) {
      setUploadError(`Failed to reset evidence custody: ${err.message}`);
    }
  };

  const handleCopyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  return (
    <div>
      {/* Hidden file input */}
      <input
        type="file"
        ref={fileInputRef}
        onChange={handleFileInputChange}
        accept=".pcap,.pcapng,.cap"
        style={{ display: 'none' }}
      />

      {/* Forensic PCAP Intake Dropzone */}
      <div
        className={`upload-dropzone ${isDragging ? 'drag-active' : ''}`}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
      >
        <div className="dropzone-icon-box">
          {isUploading ? <RefreshCw size={24} className="spinner" /> : <UploadCloud size={24} />}
        </div>
        <div className="dropzone-title">
          {isUploading
            ? (autoProcess ? 'Cryptographically Hashing & Reconstructing PCAP Streams...' : 'Ingesting & Hashing Forensic Capture...')
            : 'Ingest Network Packet Capture (PCAP / PCAPNG)'}
        </div>
        <div className="dropzone-subtitle">
          Drag & drop raw packet capture files to reconstruct SMTP, IMAP, and POP3 streams with zero email-body inspection
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12, marginTop: 8 }}>
          <button
            type="button"
            className="header-btn accent"
            disabled={isUploading}
            onClick={(e) => {
              e.stopPropagation();
              fileInputRef.current?.click();
            }}
          >
            Select Evidence File
          </button>

          <div
            style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--text-secondary)' }}
            onClick={(e) => e.stopPropagation()}
          >
            <input
              type="checkbox"
              id="autoProcessCheck"
              checked={autoProcess}
              onChange={(e) => setAutoProcess(e.target.checked)}
              style={{ cursor: 'pointer', accentColor: 'var(--accent-cyan)' }}
            />
            <label htmlFor="autoProcessCheck" style={{ cursor: 'pointer', userSelect: 'none' }}>
              Automatically run stream reconstruction & rules evaluation upon upload
            </label>
          </div>
        </div>
      </div>

      {uploadError && (
        <div
          style={{
            background: 'var(--status-critical-dim)',
            border: '1px solid var(--status-critical-border)',
            color: '#FCA5A5',
            padding: 12,
            borderRadius: 6,
            marginBottom: 20,
            display: 'flex',
            alignItems: 'center',
            gap: 10,
            fontFamily: 'var(--font-mono)',
            fontSize: 12,
          }}
        >
          <AlertCircle size={16} style={{ color: 'var(--status-critical)', flexShrink: 0 }} />
          <span>{uploadError}</span>
        </div>
      )}

      {/* Active Evidence Receipt Card */}
      {latestUploaded && (
        <div
          className="panel-card"
          style={{
            marginBottom: 24,
            borderColor: 'var(--border-highlight)',
            boxShadow: '0 0 20px rgba(0, 242, 254, 0.06)',
          }}
        >
          <div className="panel-header" style={{ background: 'rgba(0, 242, 254, 0.04)' }}>
            <span className="panel-title" style={{ color: 'var(--accent-cyan)' }}>
              <ShieldCheck size={16} />
              ACTIVE EVIDENCE INTAKE RECEIPT — {latestUploaded.id}
            </span>
            <StatusBadge status={latestUploaded.analysis_status} />
          </div>
          <div className="panel-body">
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
                gap: 16,
                fontFamily: 'var(--font-mono)',
                fontSize: 11.5,
              }}
            >
              <div>
                <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: 10 }}>CUSTODY IDENTIFIER</span>
                <span style={{ color: 'var(--accent-cyan)', fontWeight: 700, fontSize: 13 }}>{latestUploaded.id}</span>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: 10 }}>FILENAME</span>
                <span style={{ color: '#FFFFFF', fontWeight: 600 }}>{latestUploaded.filename}</span>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: 10 }}>CAPTURE SIZE</span>
                <span style={{ color: '#FFFFFF' }}>{latestUploaded.file_size_display}</span>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: 10 }}>INGESTION TIMESTAMP</span>
                <span style={{ color: '#FFFFFF' }}>{latestUploaded.uploaded_at}</span>
              </div>
              <div style={{ gridColumn: 'span 2' }}>
                <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: 10 }}>SHA-256 EVIDENCE DIGEST</span>
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 8,
                    background: 'var(--bg-surface)',
                    padding: '6px 10px',
                    borderRadius: 4,
                    border: '1px solid var(--border-subtle)',
                    marginTop: 3,
                  }}
                >
                  <span style={{ color: '#E2E8F0', wordBreak: 'break-all', fontSize: 11, flex: 1 }}>
                    {latestUploaded.sha256}
                  </span>
                  <button
                    className="header-btn"
                    style={{ height: 22, padding: '0 6px', fontSize: 10 }}
                    onClick={() => handleCopyHash(latestUploaded.sha256)}
                    title="Copy SHA-256 Digest"
                  >
                    {copiedHash === latestUploaded.sha256 ? <Check size={11} style={{ color: 'var(--status-secure)' }} /> : <Copy size={11} />}
                    <span>{copiedHash === latestUploaded.sha256 ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
              </div>
            </div>

            <div
              style={{
                marginTop: 18,
                paddingTop: 14,
                borderTop: '1px solid var(--border-subtle)',
                display: 'flex',
                gap: 10,
                alignItems: 'center',
                flexWrap: 'wrap',
              }}
            >
              <button
                className="header-btn accent"
                style={{ padding: '7px 16px', fontSize: 12, fontWeight: 700 }}
                onClick={() => handleTriggerAnalysis(latestUploaded.id)}
                disabled={analyzingId === latestUploaded.id}
              >
                {analyzingId === latestUploaded.id ? (
                  <RefreshCw size={13} className="spinner" />
                ) : (
                  <Zap size={13} />
                )}
                {latestUploaded.analysis_status === 'UPLOADED' ? 'PROCESS & ANALYZE PCAP NOW' : 'RE-RUN PASSIVE ANALYSIS'}
              </button>

              {latestUploaded.analysis_status === 'ANALYZED' && (
                <button
                  className="header-btn"
                  style={{ padding: '7px 14px', fontSize: 12 }}
                  onClick={() => onNavigateToSessionsForEvidence(latestUploaded.id)}
                >
                  <Eye size={13} />
                  VIEW RECONSTRUCTED SESSIONS ({latestUploaded.session_count})
                </button>
              )}

              <button
                className="header-btn danger"
                style={{ padding: '7px 12px', fontSize: 12, marginLeft: 'auto' }}
                onClick={() => handleDeleteEvidence(latestUploaded.id)}
                title="Delete this evidence record"
              >
                <Trash2 size={13} />
                DELETE CAPTURE
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Registered Forensic Captures Table */}
      <div className="panel-card" style={{ marginBottom: 0 }}>
        <div className="panel-header">
          <span className="panel-title">
            <HardDrive size={15} style={{ color: 'var(--accent-cyan)' }} />
            REGISTERED FORENSIC CAPTURES IN CUSTODY
          </span>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              {evidenceList.length} RECORD(S) IN CUSTODY
            </span>
            {evidenceList.length > 0 && (
              <button
                className="header-btn danger"
                style={{ height: 24, padding: '0 8px', fontSize: 10.5 }}
                onClick={handleClearAll}
                title="Delete all evidence and reset telemetry"
              >
                <Trash2 size={12} />
                CLEAR ALL
              </button>
            )}
          </div>
        </div>

        {evidenceList.length === 0 ? (
          <div style={{ padding: 48, textAlign: 'center', color: 'var(--text-muted)' }}>
            <FileCode size={38} style={{ marginBottom: 12, color: 'var(--border-highlight)' }} />
            <div style={{ fontSize: 13, fontWeight: 700, color: '#E2E8F0', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>
              NO FORENSIC CAPTURES REGISTERED
            </div>
            <div style={{ fontSize: 12, marginTop: 4, color: 'var(--text-muted)' }}>
              Drag & drop a PCAP or PCAPNG packet capture file above to begin passive evidence intake.
            </div>
          </div>
        ) : (
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>EVIDENCE ID</th>
                  <th>FILENAME</th>
                  <th>SHA-256 DIGEST</th>
                  <th>SIZE</th>
                  <th>INGESTED</th>
                  <th>STATUS</th>
                  <th>SESSIONS</th>
                  <th>ACTIONS</th>
                </tr>
              </thead>
              <tbody>
                {evidenceList.map((ev) => (
                  <tr key={ev.id}>
                    <td>
                      <span className="mono-cell" style={{ color: 'var(--accent-cyan)', fontWeight: 700 }}>
                        {ev.id}
                      </span>
                    </td>
                    <td style={{ fontWeight: 600, color: '#FFFFFF' }}>{ev.filename}</td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <span className="mono-cell" style={{ maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {ev.sha256}
                        </span>
                        <button
                          className="header-btn"
                          style={{ height: 20, padding: '0 4px', fontSize: 9 }}
                          onClick={() => handleCopyHash(ev.sha256)}
                          title="Copy SHA-256"
                        >
                          {copiedHash === ev.sha256 ? <Check size={10} style={{ color: 'var(--status-secure)' }} /> : <Copy size={10} />}
                        </button>
                      </div>
                    </td>
                    <td className="mono-cell">{ev.file_size_display}</td>
                    <td className="mono-cell" style={{ fontSize: 11 }}>{ev.uploaded_at}</td>
                    <td>
                      <StatusBadge status={ev.analysis_status} />
                    </td>
                    <td className="mono-cell">
                      <span style={{ color: 'var(--accent-teal)', fontWeight: 600 }}>{ev.session_count} sess</span>
                      <span style={{ color: 'var(--text-muted)' }}> / {ev.finding_count} fnd</span>
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: 6 }}>
                        <button
                          className="header-btn"
                          style={{ height: 26, padding: '0 8px', fontSize: 11 }}
                          onClick={() => onNavigateToSessionsForEvidence(ev.id)}
                          title="View Sessions in this evidence"
                        >
                          <Eye size={12} />
                          VIEW
                        </button>
                        <button
                          className={`header-btn ${ev.analysis_status === 'UPLOADED' ? 'accent' : ''}`}
                          style={{ height: 26, padding: '0 8px', fontSize: 11 }}
                          onClick={() => handleTriggerAnalysis(ev.id)}
                          disabled={analyzingId === ev.id}
                          title={ev.analysis_status === 'UPLOADED' ? 'Process PCAP sessions and analyze posture' : 'Rerun Forensic Analysis'}
                        >
                          {analyzingId === ev.id ? (
                            <RefreshCw size={12} className="spinner" />
                          ) : (
                            <Play size={12} />
                          )}
                          {ev.analysis_status === 'UPLOADED' ? 'PROCESS' : 'RE-RUN'}
                        </button>
                        <button
                          className="header-btn danger"
                          style={{ height: 26, padding: '0 8px', fontSize: 11 }}
                          onClick={() => handleDeleteEvidence(ev.id)}
                          title="Delete evidence record"
                        >
                          <Trash2 size={12} />
                        </button>
                      </div>
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
