import React, { useState, useEffect, useRef } from 'react';
import type { NavRoute } from './Sidebar';
import {
  LayoutGrid,
  Database,
  Network,
  AlertTriangle,
  Target,
  FileText,
  Settings,
  Search,
  X,
  UploadCloud,
  ArrowRight,
} from 'lucide-react';

interface CommandPaletteProps {
  isOpen: boolean;
  onClose: () => void;
  onNavigate: (route: NavRoute) => void;
  onTriggerUpload?: () => void;
}

interface CommandItem {
  id: string;
  title: string;
  category: string;
  icon: React.ReactNode;
  action: () => void;
  shortcut?: string;
}

export const CommandPalette: React.FC<CommandPaletteProps> = ({
  isOpen,
  onClose,
  onNavigate,
  onTriggerUpload,
}) => {
  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const items: CommandItem[] = [
    {
      id: 'nav-overview',
      title: 'Overview Dashboard',
      category: 'Navigation',
      icon: <LayoutGrid size={16} />,
      action: () => {
        onNavigate('overview');
        onClose();
      },
    },
    {
      id: 'nav-evidence',
      title: 'PCAP Evidence Management',
      category: 'Navigation',
      icon: <Database size={16} />,
      action: () => {
        onNavigate('evidence');
        onClose();
      },
    },
    {
      id: 'action-upload',
      title: 'Upload Forensic PCAP Capture',
      category: 'Actions',
      icon: <UploadCloud size={16} />,
      action: () => {
        onNavigate('evidence');
        onClose();
        if (onTriggerUpload) onTriggerUpload();
      },
    },
    {
      id: 'nav-sessions',
      title: 'Network Forensics Sessions Explorer',
      category: 'Navigation',
      icon: <Network size={16} />,
      action: () => {
        onNavigate('sessions');
        onClose();
      },
    },
    {
      id: 'nav-findings',
      title: 'Security Findings Console',
      category: 'Navigation',
      icon: <AlertTriangle size={16} />,
      action: () => {
        onNavigate('findings');
        onClose();
      },
    },
    {
      id: 'nav-risk',
      title: 'Explainable Risk Posture & Factors',
      category: 'Navigation',
      icon: <Target size={16} />,
      action: () => {
        onNavigate('risk');
        onClose();
      },
    },
    {
      id: 'nav-reports',
      title: 'Forensic Reports (JSON, HTML, PDF)',
      category: 'Navigation',
      icon: <FileText size={16} />,
      action: () => {
        onNavigate('reports');
        onClose();
      },
    },
    {
      id: 'nav-settings',
      title: 'Engine Health & System Telemetry',
      category: 'Navigation',
      icon: <Settings size={16} />,
      action: () => {
        onNavigate('settings');
        onClose();
      },
    },
  ];

  const filtered = items.filter((item) =>
    item.title.toLowerCase().includes(query.toLowerCase()) ||
    item.category.toLowerCase().includes(query.toLowerCase())
  );

  useEffect(() => {
    if (isOpen) {
      setQuery('');
      setSelectedIndex(0);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [isOpen]);

  useEffect(() => {
    setSelectedIndex(0);
  }, [query]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedIndex((prev) => (prev + 1) % (filtered.length || 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelectedIndex((prev) => (prev - 1 + (filtered.length || 1)) % (filtered.length || 1));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (filtered[selectedIndex]) {
        filtered[selectedIndex].action();
      }
    } else if (e.key === 'Escape') {
      onClose();
    }
  };

  if (!isOpen) return null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="cmd-palette-box" onClick={(e) => e.stopPropagation()}>
        <div className="cmd-input-wrapper">
          <Search size={16} style={{ color: 'var(--text-muted)' }} />
          <input
            ref={inputRef}
            type="text"
            className="cmd-input"
            placeholder="Type a command or jump to page... (ESC to exit)"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
          />
          <button
            onClick={onClose}
            style={{
              background: 'transparent',
              border: 'none',
              color: 'var(--text-muted)',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
            }}
          >
            <X size={16} />
          </button>
        </div>

        <div className="cmd-list">
          {filtered.length === 0 ? (
            <div style={{ padding: '24px 16px', textAlign: 'center', color: 'var(--text-muted)', fontSize: 12 }}>
              No matching commands or navigation routes.
            </div>
          ) : (
            filtered.map((item, idx) => {
              const isSelected = idx === selectedIndex;
              return (
                <div
                  key={item.id}
                  className={`cmd-item ${isSelected ? 'selected' : ''}`}
                  onClick={item.action}
                  onMouseEnter={() => setSelectedIndex(idx)}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <div style={{ color: isSelected ? 'var(--accent-cyan)' : 'var(--text-muted)' }}>
                      {item.icon}
                    </div>
                    <span style={{ fontSize: 13, color: isSelected ? '#FFFFFF' : 'var(--text-primary)', fontWeight: isSelected ? 600 : 500 }}>
                      {item.title}
                    </span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span style={{ fontSize: 10.5, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                      {item.category}
                    </span>
                    <ArrowRight size={12} style={{ color: isSelected ? 'var(--accent-cyan)' : 'var(--border-highlight)' }} />
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
};
