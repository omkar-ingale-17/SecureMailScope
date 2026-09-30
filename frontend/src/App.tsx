import React, { useState, useEffect, useCallback } from 'react';
import { Sidebar } from './components/Sidebar';
import type { NavRoute } from './components/Sidebar';
import { TopHeader } from './components/TopHeader';
import { CommandPalette } from './components/CommandPalette';
import { OverviewPage } from './pages/OverviewPage';
import { EvidencePage } from './pages/EvidencePage';
import { SessionsPage } from './pages/SessionsPage';
import { SessionInvestigationView } from './pages/SessionInvestigationView';
import { FindingsPage } from './pages/FindingsPage';
import { RiskPage } from './pages/RiskPage';
import { ReportsPage } from './pages/ReportsPage';
import { SettingsPage } from './pages/SettingsPage';
import { api } from './services/api';
import type {
  OverviewMetrics,
  EvidenceRecord,
  SessionRecord,
  Finding,
  RiskPosture,
  ReportRecord,
} from './services/api';

// Helper to parse route from URL
const getInitialRoute = (): NavRoute => {
  const segment = window.location.pathname.replace(/^\/+/, '').split('/')[0].toLowerCase();
  if (segment === 'evidence') return 'evidence';
  if (segment === 'sessions') return 'sessions';
  if (segment === 'findings') return 'findings';
  if (segment === 'risk') return 'risk';
  if (segment === 'reports') return 'reports';
  if (segment === 'settings') return 'settings';
  return 'overview';
};

export const App: React.FC = () => {
  const [currentRoute, setCurrentRoute] = useState<NavRoute>(getInitialRoute);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [isCmdPaletteOpen, setIsCmdPaletteOpen] = useState(false);

  // Data states
  const [metrics, setMetrics] = useState<OverviewMetrics | null>(null);
  const [evidenceList, setEvidenceList] = useState<EvidenceRecord[]>([]);
  const [sessions, setSessions] = useState<SessionRecord[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [riskPosture, setRiskPosture] = useState<RiskPosture | null>(null);
  const [reports, setReports] = useState<ReportRecord[]>([]);

  // Navigation / Selection states
  const [selectedSession, setSelectedSession] = useState<SessionRecord | null>(null);
  const [scopedEvidenceId, setScopedEvidenceId] = useState<string | null>(null);

  // Async states
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Fetch all forensic data from backend APIs
  const refreshAllData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [m, evs, sess, fnds, risk, reps] = await Promise.all([
        api.getOverview(),
        api.listEvidence(),
        api.listSessions(),
        api.listFindings(),
        api.getRiskPosture(),
        api.listReports(),
      ]);

      setMetrics(m);
      setEvidenceList(evs);
      setSessions(sess);
      setFindings(fnds);
      setRiskPosture(risk);
      setReports(reps);

      // Deep linking: check if path contains a specific session ID e.g. /sessions/777A39F3-SESS-006
      const pathParts = window.location.pathname.replace(/^\/+/, '').split('/');
      if (pathParts[0].toLowerCase() === 'sessions' && pathParts[1]) {
        const found = sess.find((s) => s.session_id.toLowerCase() === pathParts[1].toLowerCase());
        if (found) setSelectedSession(found);
      } else if (selectedSession) {
        const updated = sess.find((s) => s.session_id === selectedSession.session_id);
        if (updated) setSelectedSession(updated);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to connect to SecureMailScope backend.');
    } finally {
      setLoading(false);
    }
  }, [selectedSession]);

  useEffect(() => {
    refreshAllData();
  }, []);

  // Listen to browser popstate (back / forward buttons)
  useEffect(() => {
    const handlePopState = () => {
      const route = getInitialRoute();
      setCurrentRoute(route);
      const pathParts = window.location.pathname.replace(/^\/+/, '').split('/');
      if (pathParts[0].toLowerCase() === 'sessions' && pathParts[1]) {
        const found = sessions.find((s) => s.session_id.toLowerCase() === pathParts[1].toLowerCase());
        setSelectedSession(found || null);
      } else {
        setSelectedSession(null);
      }
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, [sessions]);

  // Global Ctrl+K / Cmd+K listener for Command Palette
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setIsCmdPaletteOpen((prev) => !prev);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  // Handlers
  const handleRouteChange = (route: NavRoute) => {
    setCurrentRoute(route);
    setSelectedSession(null);
    const newPath = route === 'overview' ? '/' : `/${route}`;
    if (window.location.pathname !== newPath) {
      window.history.pushState(null, '', newPath);
    }
  };

  const handleNavigateToSession = (sessionId: string) => {
    const s = sessions.find((x) => x.session_id === sessionId);
    if (s) {
      setSelectedSession(s);
      setCurrentRoute('sessions');
      window.history.pushState(null, '', `/sessions/${sessionId}`);
    }
  };

  const handleNavigateToSessionsForEvidence = (evidenceId: string) => {
    setScopedEvidenceId(evidenceId);
    setSelectedSession(null);
    setCurrentRoute('sessions');
    window.history.pushState(null, '', '/sessions');
  };

  // Compute status text
  let statusText = 'READY';
  if (loading) {
    statusText = 'PROCESSING';
  } else if (evidenceList.length > 0) {
    statusText = 'EVIDENCE IN CUSTODY';
  }

  // Page titles and subtitles
  const routeMeta: Record<NavRoute, { title: string; subtitle: string }> = {
    overview: {
      title: 'Investigation Command Center',
      subtitle: 'Passive email network traffic forensics & cryptographic security posture',
    },
    evidence: {
      title: 'PCAP Evidence Management',
      subtitle: 'Chain of custody, SHA-256 evidence digests, and packet capture intake',
    },
    sessions: {
      title: selectedSession ? `Forensic Stream Inspection #${selectedSession.session_id}` : 'Network Sessions Explorer',
      subtitle: selectedSession
        ? 'Deterministic TCP reassembly, TLS handshake extraction, and X.509 certificates'
        : 'Reassembled email protocol streams and cryptographic parameters',
    },
    findings: {
      title: 'Security Findings Console',
      subtitle: 'Deterministic rule-based vulnerability detections & risk attribution',
    },
    risk: {
      title: 'Explainable Risk Posture',
      subtitle: 'Transparent cryptographic scoring and contributing factor breakdown',
    },
    reports: {
      title: 'Forensic Investigation Reports',
      subtitle: 'Official audit reports in PDF, HTML, and JSON formats',
    },
    settings: {
      title: 'Engine Health & Telemetry',
      subtitle: 'Analysis core capabilities, parser bindings, and runtime status',
    },
  };

  const currentMeta = routeMeta[currentRoute];

  return (
    <div className="app-shell">
      {/* Fixed Left Sidebar */}
      <Sidebar
        currentRoute={currentRoute}
        onRouteChange={handleRouteChange}
        collapsed={sidebarCollapsed}
        onToggleCollapse={() => setSidebarCollapsed(!sidebarCollapsed)}
        counts={{
          evidence: evidenceList.length,
          sessions: sessions.length,
          findings: findings.length,
          reports: reports.length,
        }}
      />

      {/* Main Content Area */}
      <div className="main-wrapper">
        <TopHeader
          title={currentMeta.title}
          subtitle={currentMeta.subtitle}
          statusText={statusText}
          onOpenCommandPalette={() => setIsCmdPaletteOpen(true)}
        />

        <main className="main-scroll-area">
          {currentRoute === 'overview' && (
            <OverviewPage
              metrics={metrics}
              loading={loading}
              error={error}
              onRetry={refreshAllData}
              onNavigateToEvidence={() => setCurrentRoute('evidence')}
              onNavigateToSessions={() => setCurrentRoute('sessions')}
              onNavigateToSession={handleNavigateToSession}
            />
          )}

          {currentRoute === 'evidence' && (
            <EvidencePage
              evidenceList={evidenceList}
              loading={loading}
              error={error}
              onRefresh={refreshAllData}
              onNavigateToSessionsForEvidence={handleNavigateToSessionsForEvidence}
            />
          )}

          {currentRoute === 'sessions' && (
            selectedSession ? (
              <SessionInvestigationView
                session={selectedSession}
                onBack={() => setSelectedSession(null)}
              />
            ) : (
              <SessionsPage
                sessions={sessions}
                loading={loading}
                selectedEvidenceId={scopedEvidenceId}
                onClearEvidenceFilter={() => setScopedEvidenceId(null)}
                onSelectSession={(s) => setSelectedSession(s)}
              />
            )
          )}

          {currentRoute === 'findings' && (
            <FindingsPage
              findings={findings}
              sessions={sessions}
              totalSessionsCount={sessions.length}
              loading={loading}
              onNavigateToSession={handleNavigateToSession}
            />
          )}

          {currentRoute === 'risk' && (
            <RiskPage
              riskPosture={riskPosture}
              loading={loading}
              onNavigateToEvidenceSessions={handleNavigateToSessionsForEvidence}
            />
          )}

          {currentRoute === 'reports' && (
            <ReportsPage reports={reports} loading={loading} />
          )}

          {currentRoute === 'settings' && <SettingsPage />}
        </main>
      </div>

      {/* Global Command Palette (Ctrl+K) */}
      <CommandPalette
        isOpen={isCmdPaletteOpen}
        onClose={() => setIsCmdPaletteOpen(false)}
        onNavigate={handleRouteChange}
        onTriggerUpload={() => {
          setCurrentRoute('evidence');
          setIsCmdPaletteOpen(false);
        }}
      />
    </div>
  );
};

export default App;
