import { useState, useEffect } from 'react';
import {
  LayoutDashboard, Monitor, BarChart3, ShieldAlert, FileText, GitBranch, Shield
} from 'lucide-react';
import { wsManager } from './services/api';
import Dashboard from './components/Dashboard';
import TrafficMonitor from './components/TrafficMonitor';
import AnalyticsCharts from './components/AnalyticsCharts';
import ThreatPanel from './components/ThreatPanel';
import AttackLogs from './components/AttackLogs';
import NetworkGraph from './components/NetworkGraph';
import './index.css';

const navItems = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'traffic', label: 'Traffic Monitor', icon: Monitor },
  { id: 'analytics', label: 'Analytics', icon: BarChart3 },
  { id: 'threats', label: 'Threat Detection', icon: ShieldAlert },
  { id: 'logs', label: 'Attack Logs', icon: FileText },
  { id: 'network', label: 'Network Map', icon: GitBranch },
];

const panels = {
  dashboard: Dashboard,
  traffic: TrafficMonitor,
  analytics: AnalyticsCharts,
  threats: ThreatPanel,
  logs: AttackLogs,
  network: NetworkGraph,
};

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [activityLog, setActivityLog] = useState([]);

  useEffect(() => {
    wsManager.connect();
    
    // Activity logger
    const unsub = wsManager.subscribe('activity', (data) => {
      const timestamp = new Date().toLocaleTimeString();
      if (data.type === 'threat_alert') {
        setActivityLog(prev => [
          `${timestamp} - 🚨 ${data.threats?.length || 0} threats detected`,
          ...prev
        ].slice(0, 5));
      } else if (data.type === 'update') {
        const packets = data.traffic?.capture?.packets_captured || 0;
        if (packets > 0 && packets % 100 === 0) {
          setActivityLog(prev => [
            `${timestamp} - 📊 Processed ${packets} packets`,
            ...prev
          ].slice(0, 5));
        }
      }
    });
    
    return () => { wsManager.disconnect(); unsub(); };
  }, []);

  const ActivePanel = panels[activeTab] || Dashboard;

  return (
    <div className="app-layout">
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="sidebar-logo">
          <div className="logo-icon">
            <Shield size={22} color="white" />
          </div>
          <div>
            <h1>NetGuard AI</h1>
            <p>Intrusion Detection System</p>
          </div>
        </div>

        <nav className="sidebar-nav">
          {navItems.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
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
          maxHeight: '150px',
          overflowY: 'auto',
        }}>
          <div style={{ fontWeight: 600, marginBottom: '0.5rem', color: 'var(--text-secondary)' }}>
            Recent Activity
          </div>
          {activityLog.length === 0 ? (
            <div style={{ opacity: 0.5 }}>Monitoring...</div>
          ) : (
            activityLog.map((log, i) => (
              <div key={i} style={{ marginBottom: '0.25rem', opacity: 1 - (i * 0.15) }}>
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
            <div style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--accent-green)' }} />
            System Operational
          </div>
          <div>v1.0.0 · ML Engine Active</div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="main-content" style={{ display: 'flex', flexDirection: 'column', padding: 0 }}>
        {/* Demo Mode Banner */}
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
            <span style={{ color: 'var(--accent-cyan)', fontWeight: 600, letterSpacing: '0.5px' }}>
              🔬 DEMO MODE: Auto-generating network traffic for demonstration
            </span>
            <span style={{ color: 'var(--text-muted)' }}>
              Install Npcap + run as Admin for live capture
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <div className="live-dot" style={{ width: 8, height: 8 }}></div>
            <span style={{ color: 'var(--accent-green)' }}>ML Engine Active</span>
          </div>
        </div>

        <div style={{ padding: '2rem', flex: 1 }}>
          <ActivePanel />
        </div>
      </main>
    </div>
  );
}
