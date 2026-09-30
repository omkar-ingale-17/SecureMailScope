import React from 'react';
import { Database, AlertTriangle } from 'lucide-react';

interface EmptyStateProps {
  title: string;
  description: string;
  actionText?: string;
  onAction?: () => void;
  icon?: React.ReactNode;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  title,
  description,
  actionText,
  onAction,
  icon = <Database size={40} />,
}) => {
  return (
    <div className="empty-state-box">
      <div className="empty-state-icon">{icon}</div>
      <div className="empty-state-title">{title}</div>
      <div className="empty-state-desc">{description}</div>
      {actionText && onAction && (
        <button className="header-btn accent" onClick={onAction}>
          {actionText}
        </button>
      )}
    </div>
  );
};

export const LoadingState: React.FC<{ message?: string }> = ({
  message = 'Executing forensic packet analysis...',
}) => {
  return (
    <div className="empty-state-box" style={{ borderStyle: 'solid' }}>
      <div className="spinner" style={{ marginBottom: 16 }}></div>
      <div className="empty-state-title">{message}</div>
      <div className="empty-state-desc" style={{ fontFamily: 'var(--font-mono)' }}>
        Reconstructing TCP streams & cryptographic handshakes
      </div>
    </div>
  );
};

export const ErrorState: React.FC<{ error: string; onRetry?: () => void }> = ({
  error,
  onRetry,
}) => {
  return (
    <div className="empty-state-box" style={{ borderColor: 'var(--status-critical)' }}>
      <div className="empty-state-icon" style={{ color: 'var(--status-critical)' }}>
        <AlertTriangle size={36} />
      </div>
      <div className="empty-state-title" style={{ color: 'var(--status-critical)' }}>
        FORENSIC SYSTEM ERROR
      </div>
      <div className="empty-state-desc" style={{ color: '#E2E8F0', fontFamily: 'var(--font-mono)' }}>
        {error}
      </div>
      {onRetry && (
        <button className="header-btn" onClick={onRetry}>
          Retry Query
        </button>
      )}
    </div>
  );
};
