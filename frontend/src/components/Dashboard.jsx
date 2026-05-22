import { useState, useEffect, useCallback } from 'react';
import { Shield, Activity, AlertTriangle, Zap, Server, Wifi } from 'lucide-react';
import { fetchTraffic, fetchSystemStatus, runSimulation, wsManager } from '../services/api';

const statConfig = [
  { key: 'packets', label: 'Packets Captured', icon: Activity, color: 'blue', format: (v) => v.toLocaleString() },
  { key: 'flows', label: 'Active Flows', icon: Wifi, color: 'cyan', format: (v) => v.toLocaleString() },
  { key: 'threats', label: 'Threats Detected', icon: AlertTriangle, color: 'red', format: (v) => v.toLocaleString() },
  { key: 'bytes', label: 'Data Volume', icon: Zap, color: 'purple', format: (v) => formatBytes(v) },
  { key: 'status', label: 'System Status', icon: Server, color: 'green', format: () => 'Operational' },
  { key: 'models', label: 'ML Engine', icon: Shield, color: 'orange', format: (v) => v ? 'Active' : 'Inactive' },
];

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

export default function Dashboard() {
  const [stats, setStats] = useState({
    packets: 0, flows: 0, threats: 0, bytes: 0, status: true, models: true,
    driftLevel: 'warming', driftScore: null, mlThreshold: null,
    allowlistCount: 0, blocklistCount: 0, intelLastRefresh: null,
  });
  const [simulating, setSimulating] = useState(null);
  const [isLoading, setIsLoading] = useState(true);

  const refreshStats = useCallback(async () => {
    try {
      const [traffic, status] = await Promise.all([fetchTraffic(), fetchSystemStatus()]);
      setStats({
        packets: traffic.capture?.packets_captured || 0,
        flows: traffic.flows?.active_flows || 0,
        threats: status.threats?.total_threats_detected || 0,
        bytes: traffic.capture?.bytes_total || 0,
        status: status.status === 'operational',
        models: status.ml_engine?.models_trained || false,
        driftLevel: status.drift?.drift_level || 'warming',
        driftScore: status.drift?.psi_avg ?? null,
        mlThreshold: status.threats?.ml_confidence_threshold ?? null,
        allowlistCount: status.intel?.allowlist || 0,
        blocklistCount: status.intel?.blocklist || 0,
        intelLastRefresh: status.intel?.last_refresh || null,
      });
      setIsLoading(false);
    } catch (e) {
      console.error('Stats fetch error:', e);
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshStats();
    const interval = setInterval(refreshStats, 5000);

    const unsub = wsManager.subscribe('dashboard', (data) => {
      if (data.type === 'update') {
        setStats(prev => ({
          ...prev,
          packets: data.traffic?.capture?.packets_captured || prev.packets,
          flows: data.traffic?.flows?.active_flows || prev.flows,
          bytes: data.traffic?.capture?.bytes_total || prev.bytes,
        }));
      }
      if (data.type === 'threat_alert') {
        setStats(prev => ({ ...prev, threats: prev.threats + data.threats.length }));
      }
    });

    return () => { clearInterval(interval); unsub(); };
  }, [refreshStats]);

  const handleSimulate = async (type) => {
    setSimulating(type);
    try {
      await runSimulation(type);
      setTimeout(refreshStats, 2000);
    } catch (e) {
      console.error('Simulation error:', e);
    }
    setTimeout(() => setSimulating(null), 1500);
  };

  if (isLoading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '80vh', flexDirection: 'column', gap: '1rem' }}>
        <div className="live-dot" style={{ width: 40, height: 40 }}></div>
        <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>Initializing IDS Engine...</p>
      </div>
    );
  }

  return (
    <div>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.5rem' }}>
        <div>
          <h2 style={{ fontSize: '1.5rem', fontWeight: 700 }}>System Overview</h2>
          <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
            Real-time network security monitoring · Auto-generating demo traffic
          </p>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '0.25rem' }}>
          <div className="live-indicator">
            <span className="live-dot"></span>
            LIVE MONITORING
          </div>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
            {stats.packets.toLocaleString()} packets analyzed
          </div>
        </div>
      </div>

      {/* Stat Cards */}
      <div className="stats-grid">
        {statConfig.map(({ key, label, icon: Icon, color, format }) => (
          <div key={key} className={`stat-card ${color}`}>
            <div className="stat-icon">
              <Icon size={22} style={{ color: `var(--accent-${color})` }} />
            </div>
            <div className="stat-value" style={{ color: `var(--accent-${color})` }}>
              {format(stats[key])}
            </div>
            <div className="stat-label">{label}</div>
          </div>
        ))}
      </div>

      {/* Drift + Intel */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
        gap: '1rem',
        marginTop: '1.5rem',
      }}>
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Activity size={16} style={{ color: 'var(--accent-cyan)' }} />
              Model Drift
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <div style={{
              padding: '0.35rem 0.6rem',
              borderRadius: '999px',
              fontSize: '0.72rem',
              background: stats.driftLevel === 'high'
                ? 'rgba(248, 113, 113, 0.15)'
                : stats.driftLevel === 'medium'
                  ? 'rgba(251, 191, 36, 0.15)'
                  : 'rgba(56, 189, 248, 0.12)',
              color: stats.driftLevel === 'high'
                ? 'var(--accent-red)'
                : stats.driftLevel === 'medium'
                  ? 'var(--accent-orange)'
                  : 'var(--accent-cyan)'
            }}>
              {stats.driftLevel?.toUpperCase()}
            </div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
              PSI: {stats.driftScore === null ? '—' : stats.driftScore.toFixed(3)}
            </div>
          </div>
          <div style={{ marginTop: '0.6rem', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Adaptive ML threshold: {stats.mlThreshold === null ? '—' : stats.mlThreshold.toFixed(2)}
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Shield size={16} style={{ color: 'var(--accent-green)' }} />
              Threat Intel
            </div>
          </div>
          <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
              Blocklist: <span style={{ color: 'var(--accent-red)', fontWeight: 700 }}>{stats.blocklistCount}</span>
            </div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
              Allowlist: <span style={{ color: 'var(--accent-green)', fontWeight: 700 }}>{stats.allowlistCount}</span>
            </div>
          </div>
          <div style={{ marginTop: '0.6rem', fontSize: '0.7rem', color: 'var(--text-muted)' }}>
            Last refresh: {stats.intelLastRefresh ? new Date(stats.intelLastRefresh).toLocaleString() : '—'}
          </div>
        </div>
      </div>

      {/* Attack Simulation Panel */}
      <div className="card" style={{ marginTop: '1.5rem' }}>
        <div className="card-header">
          <div className="card-title">
            <Zap size={16} style={{ color: 'var(--accent-orange)' }} />
            Attack Simulation & Testing
          </div>
        </div>
        <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>
          Inject synthetic attack patterns to test ML detection capabilities
        </p>
        <div style={{ 
          background: 'rgba(56, 189, 248, 0.05)', 
          border: '1px solid rgba(56, 189, 248, 0.2)',
          borderRadius: '8px',
          padding: '1rem',
          marginBottom: '1.25rem',
          fontSize: '0.8rem',
          color: 'var(--text-secondary)'
        }}>
          <span style={{ color: 'var(--accent-cyan)', fontWeight: 600 }}>💡 Demo Mode:</span> System auto-generates traffic every 12 seconds. Click buttons below to manually trigger specific attack patterns.
        </div>
        <div className="sim-buttons">
          {[
            { type: 'port_scan', label: '🔍 Port Scan', cls: 'btn-outline', desc: '80 packets, sequential ports' },
            { type: 'ddos', label: '💥 DDoS Attack', cls: 'btn-danger', desc: '200 packets, high volume' },
            { type: 'bruteforce', label: '🔑 Brute Force', cls: 'btn-outline', desc: '60 packets, failed auth' },
            { type: 'mixed', label: '🎲 Mixed Traffic', cls: 'btn-primary', desc: '100 packets, normal + attack' },
          ].map(({ type, label, cls, desc }) => (
            <div key={type} style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
              <button
                className={`btn ${cls}`}
                onClick={() => handleSimulate(type)}
                disabled={!!simulating}
              >
                {simulating === type ? '⏳ Injecting...' : label}
              </button>
              <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)', textAlign: 'center' }}>
                {desc}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
