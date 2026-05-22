import { useState, useEffect, useRef } from 'react';
import {
  LayoutDashboard, Monitor, BarChart3, ShieldAlert, FileText, GitBranch,
  Shield, ShieldBan, TrendingUp, Zap, Network, Menu, X,
  Terminal, Radio, Cpu, Lock
} from 'lucide-react';
import { wsManager } from './services/api';
import ErrorBoundary from './components/ErrorBoundary';
import Dashboard from './components/Dashboard';
import TrafficMonitor from './components/TrafficMonitor';
import AnalyticsCharts from './components/AnalyticsCharts';
import ThreatPanel from './components/ThreatPanel';
import AttackLogs from './components/AttackLogs';
import NetworkGraph from './components/NetworkGraph';
import PipelineFlow from './components/PipelineFlow';
import ResponsePanel from './components/ResponsePanel';
import ImpactPanel from './components/ImpactPanel';
import SimulatorPanel from './components/SimulatorPanel';
import './index.css';

// ── Nav structure with section grouping ──
const NAV = [
  {
    section: 'OPERATIONS',
    items: [
      { id: 'dashboard',  label: 'Overview',        icon: LayoutDashboard },
      { id: 'pipeline',   label: 'AI Pipeline',     icon: GitBranch },
      { id: 'threats',    label: 'Threat Feed',     icon: ShieldAlert },
    ]
  },
  {
    section: 'RESPONSE',
    items: [
      { id: 'response',   label: 'Block Engine',    icon: ShieldBan },
      { id: 'impact',     label: 'Impact Metrics',  icon: TrendingUp },
      { id: 'simulator',  label: 'Attack Sim',      icon: Zap },
    ]
  },
  {
    section: 'INTELLIGENCE',
    items: [
      { id: 'traffic',    label: 'Traffic Monitor', icon: Monitor },
      { id: 'analytics',  label: 'Analytics',       icon: BarChart3 },
      { id: 'logs',       label: 'Event Log',       icon: FileText },
      { id: 'network',    label: 'Network Map',     icon: Network },
    ]
  },
];

const panels = {
  dashboard: Dashboard,
  pipeline:  PipelineFlow,
  threats:   ThreatPanel,
  response:  ResponsePanel,
  impact:    ImpactPanel,
  simulator: SimulatorPanel,
  traffic:   TrafficMonitor,
  analytics: AnalyticsCharts,
  logs:      AttackLogs,
  network:   NetworkGraph,
};

const PAGE_LABELS = {
  dashboard: 'OVERVIEW',
  pipeline:  'AI PIPELINE',
  threats:   'THREAT FEED',
  response:  'BLOCK ENGINE',
  impact:    'IMPACT METRICS',
  simulator: 'ATTACK SIMULATOR',
  traffic:   'TRAFFIC MONITOR',
  analytics: 'ANALYTICS',
  logs:      'EVENT LOG',
  network:   'NETWORK MAP',
};

// ── Ticking clock for topbar ──
function ClockWidget() {
  const [time, setTime] = useState('');
  useEffect(() => {
    const tick = () => setTime(new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC');
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);
  return (
    <span style={{
      fontFamily: 'var(--font-mono)',
      fontSize: '0.62rem',
      color: 'var(--txt-dim)',
      letterSpacing: '0.04em',
    }}>
      {time}
    </span>
  );
}

// ── Threat counter badge in sidebar ──
function ThreatCounter({ count }) {
  if (!count) return null;
  return <span className="nav-badge">{count}</span>;
}

export default function App() {
  const [activeTab, setActiveTab]   = useState('dashboard');
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [wsStatus, setWsStatus]     = useState('connecting');
  const [threatCount, setThreatCount] = useState(0);
  const [blockedCount, setBlockedCount] = useState(0);
  const [activityLog, setActivityLog] = useState([]);

  useEffect(() => {
    wsManager.connect();
    setWsStatus('connected');

    const unsub = wsManager.subscribe('app', (data) => {
      const t = new Date().toLocaleTimeString('en-GB', { hour12: false });
      if (data.type === 'threat_alert' && data.threats) {
        setThreatCount(n => n + (data.threats.length || 0));
        setActivityLog(prev => [
          { time: t, msg: `${data.threats.length} THREAT${data.threats.length > 1 ? 'S' : ''} DETECTED`, sev: 'err' },
          ...prev,
        ].slice(0, 8));
      }
      if (data.type === 'update') {
        if (data.response_stats?.total_blocked) {
          setBlockedCount(data.response_stats.total_blocked);
          setActivityLog(prev => [
            { time: t, msg: `${data.response_stats.total_blocked} IP(S) BLOCKED`, sev: 'warn' },
            ...prev,
          ].slice(0, 8));
        }
      }
    });

    return () => { wsManager.disconnect(); unsub(); setWsStatus('disconnected'); };
  }, []);

  const ActivePanel = panels[activeTab] || Dashboard;

  return (
    <div className="app-layout">
      {/* ── Sidebar ── */}
      <aside className={`sidebar${sidebarOpen ? '' : ' sidebar-collapsed'}`} aria-label="Navigation">

        {/* Logo */}
        <div className="sidebar-logo">
          <div className="logo-icon">
            <Shield size={20} color="var(--phos-100)" />
          </div>
          <div>
            <h1>A.I.R.S</h1>
            <p>Autonomous IDS · v2.0</p>
          </div>
        </div>

        {/* Status bar under logo */}
        <div style={{
          padding: '0.5rem 1rem',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          borderBottom: '1px solid var(--border-dim)',
          background: 'rgba(0,0,0,0.2)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <div className="live-dot" style={{ width: 5, height: 5 }} />
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.58rem', color: wsStatus === 'connected' ? 'var(--phos-100)' : 'var(--threat-critical)', letterSpacing: '0.06em' }}>
              {wsStatus === 'connected' ? 'ONLINE' : 'OFFLINE'}
            </span>
          </div>
          <div style={{ display: 'flex', gap: '0.6rem' }}>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.56rem', color: 'var(--threat-critical)' }}>
              ⚠ {threatCount} THR
            </span>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.56rem', color: 'var(--sig-amber)' }}>
              🛡 {blockedCount} BLK
            </span>
          </div>
        </div>

        {/* Navigation */}
        <nav className="sidebar-nav" aria-label="Main navigation">
          {NAV.map(({ section, items }) => (
            <div key={section}>
              <div className="nav-section-label">{section}</div>
              {items.map(({ id, label, icon: Icon }) => (
                <button
                  key={id}
                  id={`nav-${id}`}
                  aria-current={activeTab === id ? 'page' : undefined}
                  className={`nav-item${activeTab === id ? ' active' : ''}`}
                  onClick={() => setActiveTab(id)}
                >
                  <Icon size={14} />
                  {label}
                  {id === 'threats' && <ThreatCounter count={threatCount} />}
                  {id === 'response' && blockedCount > 0 && (
                    <span className="nav-badge" style={{ background: 'rgba(245,158,11,0.15)', color: 'var(--sig-amber)', borderColor: 'rgba(245,158,11,0.3)' }}>
                      {blockedCount}
                    </span>
                  )}
                </button>
              ))}
            </div>
          ))}
        </nav>

        {/* Activity Log */}
        <div style={{
          padding: '0.75rem 1rem',
          borderTop: '1px solid var(--border-dim)',
          maxHeight: '130px',
          overflowY: 'auto',
        }}>
          <div style={{
            fontFamily: 'var(--font-mono)',
            fontSize: '0.58rem',
            color: 'var(--txt-dim)',
            letterSpacing: '0.1em',
            marginBottom: '0.4rem',
            textTransform: 'uppercase',
            display: 'flex',
            alignItems: 'center',
            gap: '0.3rem',
          }}>
            <Terminal size={9} />
            ACTIVITY LOG
          </div>
          {activityLog.length === 0 ? (
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.6rem', color: 'var(--txt-dim)', opacity: 0.5 }}>
              &gt; awaiting events...
            </div>
          ) : (
            activityLog.map((entry, i) => (
              <div key={i} style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '0.6rem',
                display: 'flex',
                gap: '0.4rem',
                marginBottom: '0.2rem',
                opacity: Math.max(0.2, 1 - i * 0.11),
              }}>
                <span style={{ color: 'var(--txt-dim)', flexShrink: 0 }}>{entry.time}</span>
                <span style={{ color: entry.sev === 'err' ? 'var(--threat-critical)' : entry.sev === 'warn' ? 'var(--sig-amber)' : 'var(--phos-100)' }}>
                  {entry.msg}
                </span>
              </div>
            ))
          )}
        </div>

        {/* Footer */}
        <div style={{
          padding: '0.6rem 1rem',
          borderTop: '1px solid var(--border-dim)',
          display: 'flex',
          flexDirection: 'column',
          gap: '0.2rem',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <Cpu size={9} color="var(--txt-dim)" />
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.56rem', color: 'var(--txt-dim)', letterSpacing: '0.06em' }}>
              ML ENGINE · RF + IF + LSTM
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <Lock size={9} color="var(--txt-dim)" />
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.56rem', color: 'var(--txt-dim)', letterSpacing: '0.06em' }}>
              MITRE ATT&CK · SHAP · CLAUDE
            </span>
          </div>
        </div>
      </aside>

      {/* ── Main Content ── */}
      <main
        className="main-content"
        style={{ marginLeft: sidebarOpen ? '248px' : '0', transition: 'margin-left 0.25s cubic-bezier(0.4,0,0.2,1)' }}
        aria-label="Main content"
      >
        {/* Top Bar */}
        <div className="topbar">
          <div className="topbar-left">
            <button
              className="hamburger"
              aria-label="Toggle sidebar"
              onClick={() => setSidebarOpen(o => !o)}
            >
              {sidebarOpen ? <X size={16} /> : <Menu size={16} />}
            </button>

            {/* Breadcrumb */}
            <div className="topbar-breadcrumb">
              A.I.R.S &nbsp;/&nbsp; <span>{PAGE_LABELS[activeTab] || activeTab.toUpperCase()}</span>
            </div>
          </div>

          <div className="topbar-right">
            <ClockWidget />

            <div className="topbar-pill demo">
              <Radio size={9} />
              DEMO MODE
            </div>

            <div className={`topbar-pill ${wsStatus === 'connected' ? 'live' : 'warn'}`}>
              <div className="live-dot" style={{ width: 5, height: 5 }} />
              {wsStatus === 'connected' ? 'ML ACTIVE' : 'OFFLINE'}
            </div>
          </div>
        </div>

        {/* Page Content */}
        <div className="page-content">
          <ErrorBoundary>
            <ActivePanel />
          </ErrorBoundary>
        </div>
      </main>
    </div>
  );
}
