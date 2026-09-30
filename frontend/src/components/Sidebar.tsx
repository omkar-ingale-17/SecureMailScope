import React from 'react';
import {
  Shield,
  LayoutGrid,
  Database,
  Network,
  AlertTriangle,
  Target,
  FileText,
  Settings,
  ChevronLeft,
  ChevronRight,
  UserCheck,
} from 'lucide-react';

export type NavRoute =
  | 'overview'
  | 'evidence'
  | 'sessions'
  | 'findings'
  | 'risk'
  | 'reports'
  | 'settings';

interface SidebarProps {
  currentRoute: NavRoute;
  onRouteChange: (route: NavRoute) => void;
  collapsed: boolean;
  onToggleCollapse: () => void;
  counts?: {
    evidence?: number;
    sessions?: number;
    findings?: number;
    reports?: number;
  };
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentRoute,
  onRouteChange,
  collapsed,
  onToggleCollapse,
  counts,
}) => {
  return (
    <aside className={`sidebar ${collapsed ? 'collapsed' : ''}`}>
      {/* Top Brand */}
      <div className="sidebar-header">
        <div className="sidebar-brand">
          <div className="brand-icon-box" title="SecureMailScope — Passive Forensics">
            <Shield size={19} />
          </div>
          {!collapsed && (
            <div className="brand-text">
              <span className="brand-title">SecureMailScope</span>
              <span className="brand-subtitle">EMAIL SECURITY FORENSICS</span>
            </div>
          )}
        </div>
        <button
          className="collapse-toggle-btn"
          onClick={onToggleCollapse}
          title={collapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
          aria-label="Toggle navigation sidebar"
        >
          {collapsed ? <ChevronRight size={15} /> : <ChevronLeft size={15} />}
        </button>
      </div>

      {/* Navigation Sections */}
      <div className="sidebar-nav-container">
        {/* OVERVIEW */}
        <div>
          {!collapsed && <div className="nav-group-title">OVERVIEW</div>}
          <div
            className={`nav-item ${currentRoute === 'overview' ? 'active' : ''}`}
            onClick={() => onRouteChange('overview')}
            title="Overview Dashboard"
          >
            <LayoutGrid className="nav-item-icon" />
            {!collapsed && <span className="nav-item-label">Command Center</span>}
          </div>
        </div>

        {/* EVIDENCE */}
        <div>
          {!collapsed && <div className="nav-group-title">EVIDENCE</div>}
          <div
            className={`nav-item ${currentRoute === 'evidence' ? 'active' : ''}`}
            onClick={() => onRouteChange('evidence')}
            title="PCAP Evidence"
          >
            <Database className="nav-item-icon" />
            {!collapsed && <span className="nav-item-label">PCAP Evidence</span>}
            {!collapsed && counts?.evidence !== undefined && counts.evidence > 0 && (
              <span className="nav-badge">{counts.evidence}</span>
            )}
          </div>
        </div>

        {/* ANALYSIS */}
        <div>
          {!collapsed && <div className="nav-group-title">ANALYSIS</div>}
          <div
            className={`nav-item ${currentRoute === 'sessions' ? 'active' : ''}`}
            onClick={() => onRouteChange('sessions')}
            title="Network Sessions"
          >
            <Network className="nav-item-icon" />
            {!collapsed && <span className="nav-item-label">Sessions Explorer</span>}
            {!collapsed && counts?.sessions !== undefined && counts.sessions > 0 && (
              <span className="nav-badge">{counts.sessions}</span>
            )}
          </div>
        </div>

        {/* SECURITY */}
        <div>
          {!collapsed && <div className="nav-group-title">SECURITY</div>}
          <div
            className={`nav-item ${currentRoute === 'findings' ? 'active' : ''}`}
            onClick={() => onRouteChange('findings')}
            title="Security Findings"
          >
            <AlertTriangle className="nav-item-icon" />
            {!collapsed && <span className="nav-item-label">Security Findings</span>}
            {!collapsed && counts?.findings !== undefined && counts.findings > 0 && (
              <span className="nav-badge" style={{ color: 'var(--status-critical)' }}>
                {counts.findings}
              </span>
            )}
          </div>

          <div
            className={`nav-item ${currentRoute === 'risk' ? 'active' : ''}`}
            onClick={() => onRouteChange('risk')}
            title="Risk Analysis"
          >
            <Target className="nav-item-icon" />
            {!collapsed && <span className="nav-item-label">Risk Posture</span>}
          </div>
        </div>

        {/* OUTPUT */}
        <div>
          {!collapsed && <div className="nav-group-title">OUTPUT</div>}
          <div
            className={`nav-item ${currentRoute === 'reports' ? 'active' : ''}`}
            onClick={() => onRouteChange('reports')}
            title="Forensic Reports"
          >
            <FileText className="nav-item-icon" />
            {!collapsed && <span className="nav-item-label">Forensic Reports</span>}
            {!collapsed && counts?.reports !== undefined && counts.reports > 0 && (
              <span className="nav-badge">{counts.reports}</span>
            )}
          </div>
        </div>

        {/* SYSTEM */}
        <div>
          {!collapsed && <div className="nav-group-title">SYSTEM</div>}
          <div
            className={`nav-item ${currentRoute === 'settings' ? 'active' : ''}`}
            onClick={() => onRouteChange('settings')}
            title="Settings & Engine Health"
          >
            <Settings className="nav-item-icon" />
            {!collapsed && <span className="nav-item-label">Engine Health</span>}
          </div>
        </div>
      </div>

      {/* Authenticated Analyst Footer */}
      {!collapsed && (
        <div className="sidebar-analyst-footer">
          <div className="analyst-avatar">
            <UserCheck size={16} />
          </div>
          <div className="analyst-info">
            <span className="analyst-title">SOC Analyst Console</span>
            <div className="analyst-status">
              <span className="status-dot-pulse"></span>
              <span>Active Session</span>
            </div>
          </div>
        </div>
      )}
    </aside>
  );
};
