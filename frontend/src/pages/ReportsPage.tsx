import React, { useState } from 'react';
import { api } from '../services/api';
import type { ReportRecord } from '../services/api';
import { RiskBadge } from '../components/Badges';
import { EmptyState, LoadingState } from '../components/FeedbackStates';
import { FileText, Download, Eye, X, FileCode, Check, Copy } from 'lucide-react';

interface ReportsPageProps {
  reports: ReportRecord[];
  loading: boolean;
}

export const ReportsPage: React.FC<ReportsPageProps> = ({ reports, loading }) => {
  const [viewingReportId, setViewingReportId] = useState<string | null>(null);
  const [viewFormat, setViewFormat] = useState<'html' | 'json'>('html');
  const [rawContent, setRawContent] = useState<string | null>(null);
  const [contentLoading, setContentLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  if (loading) {
    return <LoadingState message="Loading Forensic Reports..." />;
  }

  const handleOpenReport = async (reportId: string, format: 'html' | 'json') => {
    setViewingReportId(reportId);
    setViewFormat(format);
    setContentLoading(true);

    try {
      const url = api.getReportViewUrl(reportId, format);
      const res = await fetch(url);
      const text = await res.text();
      setRawContent(text);
    } catch (err) {
      setRawContent('Error loading forensic report content.');
    } finally {
      setContentLoading(false);
    }
  };

  const handleDownload = (reportId: string, format: 'pdf' | 'html' | 'json') => {
    const url = api.getReportDownloadUrl(reportId, format);
    window.open(url, '_blank');
  };

  const handleCopyJson = () => {
    if (!rawContent) return;
    navigator.clipboard.writeText(rawContent);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div>
      <div className="panel-card" style={{ marginBottom: 0 }}>
        <div className="panel-header">
          <span className="panel-title">
            <FileText size={15} style={{ color: 'var(--accent-cyan)' }} />
            EVIDENCE-LINKED FORENSIC REPORTS
          </span>
          <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
            {reports.length} REPORT(S) GENERATED
          </span>
        </div>

        {reports.length === 0 ? (
          <EmptyState
            title="NO FORENSIC REPORTS GENERATED"
            description="Audit reports are compiled deterministically upon PCAP evidence registration and passive session stream analysis."
          />
        ) : (
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>REPORT ID</th>
                  <th>EVIDENCE CAPTURE</th>
                  <th>SESSIONS</th>
                  <th>FINDINGS</th>
                  <th>RISK POSTURE</th>
                  <th>COMPILED AT</th>
                  <th>FORMATS</th>
                  <th>EXPORT & PREVIEW</th>
                </tr>
              </thead>
              <tbody>
                {reports.map((rep) => (
                  <tr key={rep.id}>
                    <td>
                      <span className="mono-cell" style={{ color: 'var(--accent-cyan)', fontWeight: 700 }}>
                        {rep.id}
                      </span>
                    </td>
                    <td style={{ fontWeight: 600, color: '#FFFFFF' }}>{rep.evidence_filename}</td>
                    <td className="mono-cell">{rep.session_count}</td>
                    <td className="mono-cell">{rep.finding_count}</td>
                    <td>
                      <RiskBadge level={rep.risk_level} score={rep.risk_score} />
                    </td>
                    <td className="mono-cell" style={{ fontSize: 11 }}>{rep.generated_at}</td>
                    <td>
                      <div style={{ display: 'flex', gap: 4 }}>
                        <span className="badge badge-low">PDF</span>
                        <span className="badge badge-secure">HTML</span>
                        <span className="badge badge-neutral">JSON</span>
                      </div>
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: 6 }}>
                        <button
                          className="header-btn"
                          style={{ height: 26, padding: '0 8px', fontSize: 11 }}
                          onClick={() => handleOpenReport(rep.id, 'html')}
                          title="Preview HTML Forensic Report"
                        >
                          <Eye size={12} />
                          HTML
                        </button>
                        <button
                          className="header-btn"
                          style={{ height: 26, padding: '0 8px', fontSize: 11 }}
                          onClick={() => handleOpenReport(rep.id, 'json')}
                          title="Preview JSON Telemetry"
                        >
                          <FileCode size={12} />
                          JSON
                        </button>
                        <button
                          className="header-btn accent"
                          style={{ height: 26, padding: '0 8px', fontSize: 11 }}
                          onClick={() => handleDownload(rep.id, 'pdf')}
                          title="Download Official PDF Audit Report"
                        >
                          <Download size={12} />
                          PDF
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

      {/* Report Preview Modal */}
      {viewingReportId && (
        <div className="modal-overlay" onClick={() => setViewingReportId(null)}>
          <div
            className="modal-content"
            style={{ maxWidth: 880, height: '88vh' }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="modal-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <FileText size={16} style={{ color: 'var(--accent-cyan)' }} />
                <span className="modal-title">
                  REPORT PREVIEW: {viewingReportId} ({viewFormat.toUpperCase()})
                </span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                {viewFormat === 'json' && (
                  <button className="header-btn" style={{ height: 26 }} onClick={handleCopyJson}>
                    {copied ? <Check size={12} style={{ color: 'var(--status-secure)' }} /> : <Copy size={12} />}
                    <span>{copied ? 'Copied' : 'Copy JSON'}</span>
                  </button>
                )}
                <button
                  className="header-btn accent"
                  style={{ height: 26 }}
                  onClick={() => handleDownload(viewingReportId, viewFormat)}
                >
                  <Download size={12} />
                  Download {viewFormat.toUpperCase()}
                </button>
                <button className="modal-close-btn" onClick={() => setViewingReportId(null)}>
                  <X size={16} />
                </button>
              </div>
            </div>

            <div className="modal-body" style={{ padding: 0, height: 'calc(100% - 60px)' }}>
              {contentLoading ? (
                <div style={{ padding: 48, textAlign: 'center', color: 'var(--text-muted)' }}>
                  <div className="spinner" style={{ margin: '0 auto 16px auto' }}></div>
                  <span>Formatting forensic report output...</span>
                </div>
              ) : viewFormat === 'html' ? (
                <iframe
                  title="Forensic Report HTML View"
                  srcDoc={rawContent || ''}
                  style={{ width: '100%', height: '100%', border: 'none', background: '#FFFFFF' }}
                />
              ) : (
                <pre
                  style={{
                    padding: 20,
                    margin: 0,
                    fontSize: 11.5,
                    fontFamily: 'var(--font-mono)',
                    color: '#A5F3FC',
                    overflowY: 'auto',
                    height: '100%',
                    background: '#060A12',
                  }}
                >
                  {rawContent}
                </pre>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
