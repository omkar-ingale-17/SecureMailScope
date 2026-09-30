import React from 'react';

interface MetricCardProps {
  label: string;
  value: number | string;
  subtext?: string;
  icon: React.ReactNode;
  accent?: 'cyan' | 'red' | 'yellow' | 'teal' | 'blue';
}

export const MetricCard: React.FC<MetricCardProps> = ({
  label,
  value,
  subtext,
  icon,
  accent = 'cyan',
}) => {
  return (
    <div className={`metric-card accent-${accent}`}>
      <div className="metric-header">
        <span className="metric-label">{label}</span>
        <div className="metric-icon">{icon}</div>
      </div>
      <div className="metric-value">{value}</div>
      {subtext && <div className="metric-subtext">{subtext}</div>}
    </div>
  );
};
