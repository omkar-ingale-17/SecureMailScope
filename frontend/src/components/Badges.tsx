import React from 'react';

interface StatusBadgeProps {
  status: string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status }) => {
  let badgeClass = 'badge-neutral';
  const s = (status || '').toUpperCase();

  if (s === 'VALID' || s === 'ANALYZED' || s === 'COMPLETED' || s === 'OFFERED_AND_ACCEPTED') {
    badgeClass = 'badge-secure';
  } else if (s === 'EXPIRED' || s === 'INVALID' || s === 'FAILED' || s === 'NOT_OFFERED') {
    badgeClass = 'badge-critical';
  } else if (s === 'WEAK_KEY' || s === 'WEAK_SIGNATURE' || s === 'OFFERED_NOT_UPGRADED' || s === 'PROCESSING') {
    badgeClass = 'badge-high';
  } else if (s === 'SELF_SIGNED' || s === 'NOT_YET_VALID') {
    badgeClass = 'badge-medium';
  } else if (s === 'UPLOADED' || s === 'DETECTED') {
    badgeClass = 'badge-low';
  }

  return (
    <span className={`badge ${badgeClass}`}>
      <span className="badge-dot" />
      {status.replace(/_/g, ' ')}
    </span>
  );
};

interface RiskBadgeProps {
  level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SECURE' | string;
  score?: number;
}

export const RiskBadge: React.FC<RiskBadgeProps> = ({ level, score }) => {
  let badgeClass = 'badge-neutral';
  const l = (level || '').toUpperCase();

  if (l === 'CRITICAL') badgeClass = 'badge-critical';
  else if (l === 'HIGH') badgeClass = 'badge-high';
  else if (l === 'MEDIUM') badgeClass = 'badge-medium';
  else if (l === 'LOW') badgeClass = 'badge-low';
  else if (l === 'SECURE') badgeClass = 'badge-secure';

  return (
    <span className={`badge ${badgeClass}`}>
      <span className="badge-dot" />
      {level} {score !== undefined ? `(${score})` : ''}
    </span>
  );
};

interface SeverityBadgeProps {
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | string;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity }) => {
  let badgeClass = 'badge-neutral';
  const s = (severity || '').toUpperCase();

  if (s === 'CRITICAL') badgeClass = 'badge-critical';
  else if (s === 'HIGH') badgeClass = 'badge-high';
  else if (s === 'MEDIUM') badgeClass = 'badge-medium';
  else if (s === 'LOW') badgeClass = 'badge-low';
  else if (s === 'INFO') badgeClass = 'badge-neutral';

  return (
    <span className={`badge ${badgeClass}`}>
      <span className="badge-dot" />
      {severity}
    </span>
  );
};
