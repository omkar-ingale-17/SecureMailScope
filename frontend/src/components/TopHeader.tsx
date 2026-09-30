import React from 'react';
import { ShieldCheck, Cpu, Search, Command } from 'lucide-react';

interface TopHeaderProps {
  title: string;
  subtitle: string;
  statusText?: string;
  onOpenCommandPalette?: () => void;
}

export const TopHeader: React.FC<TopHeaderProps> = ({
  title,
  subtitle,
  statusText = 'READY',
  onOpenCommandPalette,
}) => {
  return (
    <header className="top-header">
      <div className="header-left">
        <div className="header-title-box">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span className="header-title">{title}</span>
            <span className="forensic-mode-badge">
              <ShieldCheck size={12} />
              FORENSIC PASSIVE
            </span>
          </div>
          <span className="header-subtitle">{subtitle}</span>
        </div>
      </div>

      <div className="header-right">
        {onOpenCommandPalette && (
          <button
            className="cmd-k-trigger"
            onClick={onOpenCommandPalette}
            title="Search actions or jump to page (Ctrl+K)"
          >
            <Search size={13} />
            <span>Search or jump...</span>
            <span className="kbd-shortcut">
              <Command size={10} style={{ display: 'inline', verticalAlign: 'middle' }} /> K
            </span>
          </button>
        )}

        <div className="status-indicator-pill">
          <span className="status-dot-active"></span>
          <span>ENGINE: {statusText}</span>
        </div>

        <div className="status-indicator-pill" style={{ color: 'var(--text-muted)' }}>
          <Cpu size={12} />
          <span>ZERO-CONTENT INSPECTION</span>
        </div>
      </div>
    </header>
  );
};
