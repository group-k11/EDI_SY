import { useState, useEffect } from 'react';
import {
  LayoutDashboard, Monitor, BarChart3, ShieldAlert, FileText, GitBranch,
  Shield, ShieldBan, TrendingUp, Zap, Network, Menu, X
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

const navItems = [
  { id: 'dashboard',  label: 'Dashboard',        icon: LayoutDashboard },
  { id: 'pipeline',   label: 'Pipeline Flow',     icon: GitBranch },
  { id: 'threats',    label: 'Threat Detection',  icon: ShieldAlert },
  { id: 'response',   label: 'Response Engine',   icon: ShieldBan },
  { id: 'impact',     label: 'Impact',            icon: TrendingUp },
  { id: 'simulator',  label: 'Simulator',         icon: Zap },
  { id: 'traffic',    label: 'Traffic Monitor',   icon: Monitor },
  { id: 'analytics',  label: 'Analytics',         icon: BarChart3 },
  { id: 'logs',       label: 'Attack Logs',       icon: FileText },
  { id: 'network',    label: 'Network Map',       icon: Network },
];

const panels = {
  dashboard:  Dashboard,
  pipeline:   PipelineFlow,
  threats:    ThreatPanel,
  response:   ResponsePanel,
  impact:     ImpactPanel,
  simulator:  SimulatorPanel,
  traffic:    TrafficMonitor,
  analytics:  AnalyticsCharts,
  logs:       AttackLogs,
  network:    NetworkGraph,
};

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [activityLog, setActivityLog] = useState([]);
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [wsStatus, setWsStatus] = useState('connecting');

  useEffect(() => {
    wsManager.connect();
    setWsStatus('connected');

    const unsub = wsManager.subscribe('activity', (data) => {
      const timestamp = new Date().toLocaleTimeString();
      if (data.type === 'threat_alert') {
        setActivityLog(prev => [
          `${timestamp} — 🚨 ${data.threats?.length || 0} threats`,
          ...prev,
        ].slice(0, 6));
      } else if (data.type === 'update') {
        const blocked = data.response_stats?.total_blocked;
        if (blocked && blocked > 0) {
          setActivityLog(prev => {
            const entry = `${timestamp} — 🛡 ${blocked} IPs blocked`;
            if (prev[0] === entry) return prev;
            return [entry, ...prev].slice(0, 6);
          });
        }
      }
    });

    return () => {
      wsManager.disconnect();
      unsub();
      setWsStatus('disconnected');
    };
  }, []);

  const ActivePanel = panels[activeTab] || Dashboard;

  return (
    <div className="app-layout">
      {/* Mobile overlay */}
      {!sidebarOpen && (
        <div
          style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', zIndex: 40, display: 'none' }}
          onClick={() => setSidebarOpen(false)}
          className="mobile-overlay"
        />
      )}

      {/* Sidebar */}
      <aside className={`sidebar${sidebarOpen ? '' : ' sidebar-collapsed'}`}>
        <div className="sidebar-logo">
          <div className="logo-icon">
            <Shield size={22} color="white" />
          </div>
          <div>
            <h1>A.I.R.S</h1>
            <p>Autonomous IDS v2.0</p>
          </div>
        </div>

        <nav className="sidebar-nav">
          {navItems.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              id={`nav-${id}`}
              aria-current={activeTab === id ? 'page' : undefined}
              className={`nav-item ${activeTab === id ? 'active' : ''}`}
              onClick={() => setActiveTab(id)}
            >
              <Icon size={18} />
              {label}
            </button>
          ))}
        </nav>

        {/* Activity Log */}
        <div style={{
          padding: '1rem',
          borderTop: '1px solid var(--border-color)',
          fontSize: '0.7rem',
          color: 'var(--text-muted)',
          maxHeight: '140px',
          overflowY: 'auto',
        }}>
          <div style={{ fontWeight: 600, marginBottom: '0.5rem', color: 'var(--text-secondary)' }}>
            Recent Activity
          </div>
          {activityLog.length === 0 ? (
            <div style={{ opacity: 0.5 }}>Monitoring…</div>
          ) : (
            activityLog.map((log, i) => (
              <div key={i} style={{ marginBottom: '0.25rem', opacity: 1 - i * 0.14 }}>
                {log}
              </div>
            ))
          )}
        </div>

        {/* Sidebar Footer */}
        <div style={{
          padding: '1rem',
          borderTop: '1px solid var(--border-color)',
          fontSize: '0.72rem',
          color: 'var(--text-muted)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
            <div style={{
              width: 8, height: 8, borderRadius: '50%',
              background: wsStatus === 'connected' ? 'var(--accent-green)' : '#ef4444',
            }} />
            {wsStatus === 'connected' ? 'System Operational' : 'Reconnecting…'}
          </div>
          <div>v2.0.0 · ML Engine Active</div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="main-content" style={{ display: 'flex', flexDirection: 'column', padding: 0 }}>
        {/* Top Bar */}
        <div style={{
          background: 'rgba(15, 23, 42, 0.6)',
          backdropFilter: 'blur(12px)',
          WebkitBackdropFilter: 'blur(12px)',
          borderBottom: '1px solid rgba(56, 189, 248, 0.2)',
          padding: '0.75rem 2rem',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          fontSize: '0.75rem',
          position: 'sticky',
          top: 0,
          zIndex: 10,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <button
              aria-label="Toggle sidebar"
              onClick={() => setSidebarOpen(o => !o)}
              style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: 4 }}
            >
              {sidebarOpen ? <X size={18} /> : <Menu size={18} />}
            </button>
            <span style={{ color: 'var(--accent-cyan)', fontWeight: 600, letterSpacing: '0.5px' }}>
              🔬 DEMO MODE — Auto-generating network traffic
            </span>
            <span style={{ color: 'var(--text-muted)' }}>
              Install Npcap + run as Admin for live capture
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <div className="live-dot" style={{ width: 8, height: 8 }} />
            <span style={{ color: 'var(--accent-green)' }}>ML Engine Active</span>
          </div>
        </div>

        <div style={{ padding: '2rem', flex: 1 }}>
          <ErrorBoundary>
            <ActivePanel />
          </ErrorBoundary>
        </div>
      </main>
    </div>
  );
}
