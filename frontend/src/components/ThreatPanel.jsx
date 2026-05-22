import { useState, useEffect } from 'react';
import { ShieldAlert, AlertTriangle, Clock } from 'lucide-react';
import { fetchThreats, wsManager } from '../services/api';

const severityConfig = {
  critical: { class: 'badge-critical', icon: '🔴', priority: 0 },
  high: { class: 'badge-high', icon: '🟠', priority: 1 },
  medium: { class: 'badge-medium', icon: '🟡', priority: 2 },
  low: { class: 'badge-low', icon: '🔵', priority: 3 },
  info: { class: 'badge-info', icon: '⚪', priority: 4 },
};

const attackIcons = {
  port_scan: '🔍', dos: '💥', brute_force: '🔑', suspicious: '⚠️', unknown: '❓',
};

export default function ThreatPanel() {
  const [threats, setThreats] = useState([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const load = async () => {
      try {
        const data = await fetchThreats();
        setThreats(data.threats || []);
        setIsLoading(false);
      } catch (e) { 
        console.error(e);
        setIsLoading(false);
      }
    };
    load();

    const unsub = wsManager.subscribe('threats', (data) => {
      if (data.type === 'threat_alert' && data.threats) {
        setThreats(prev => [...data.threats, ...prev].slice(0, 50));
      }
      if (data.type === 'update' && data.threats) {
        setThreats(data.threats);
      }
    });

    const interval = setInterval(load, 5000);
    return () => { clearInterval(interval); unsub(); };
  }, []);

  const sorted = [...threats].sort((a, b) => {
    const pa = severityConfig[a.severity]?.priority ?? 5;
    const pb = severityConfig[b.severity]?.priority ?? 5;
    return pa - pb;
  });

  if (isLoading) {
    return (
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <ShieldAlert size={16} style={{ color: 'var(--accent-red)' }} />
            Threat Detection
          </div>
        </div>
        <div style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)' }}>
          <div className="live-dot" style={{ width: 30, height: 30, margin: '0 auto 1rem' }}></div>
          <p style={{ fontSize: '0.85rem' }}>Analyzing network traffic...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="card">
      <div className="card-header">
        <div className="card-title">
          <ShieldAlert size={16} style={{ color: 'var(--accent-red)' }} />
          Threat Detection
        </div>
        <span className="badge badge-critical" style={{ fontSize: '0.7rem' }}>
          <AlertTriangle size={12} /> {threats.length} Active
        </span>
      </div>

      <div style={{ 
        background: 'rgba(239, 68, 68, 0.1)', 
        border: '1px solid rgba(239, 68, 68, 0.3)',
        borderRadius: '6px',
        padding: '0.75rem',
        marginBottom: '1rem',
        fontSize: '0.75rem',
        color: 'var(--accent-red)'
      }}>
        🛡️ <strong>ML Detection:</strong> Threats detected using Isolation Forest (anomaly detection) + Random Forest (attack classification) with rule-based validation. Confidence scores vary based on detection certainty.
      </div>

      <div style={{ maxHeight: '450px', overflowY: 'auto' }}>
        {sorted.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
            <ShieldAlert size={32} style={{ opacity: 0.3, marginBottom: '0.5rem' }} />
            <p style={{ fontSize: '0.85rem' }}>No threats detected</p>
            <p style={{ fontSize: '0.75rem' }}>System is monitoring for anomalies</p>
            <p style={{ fontSize: '0.7rem', marginTop: '0.5rem', color: 'var(--accent-blue)' }}>
              💡 Click "Attack Simulation" buttons to test detection
            </p>
          </div>
        ) : (
          sorted.map((threat, i) => {
            const sev = severityConfig[threat.severity] || severityConfig.info;
            return (
              <div key={i} className="threat-item" style={{
                padding: '0.85rem',
                borderBottom: '1px solid var(--border-color)',
                borderLeft: `3px solid var(--severity-${threat.severity})`,
                marginBottom: '0.25rem',
                borderRadius: '4px',
              }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.4rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span>{attackIcons[threat.attack_type] || '❓'}</span>
                    <span style={{ fontWeight: 600, fontSize: '0.85rem', textTransform: 'uppercase' }}>
                      {threat.attack_type?.replace(/_/g, ' ')}
                    </span>
                    <span className={`badge ${sev.class}`}>{threat.severity}</span>
                  </div>
                  <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                    <Clock size={10} />
                    {threat.timestamp ? new Date(threat.timestamp).toLocaleTimeString() : '—'}
                  </span>
                </div>
                <div style={{ display: 'flex', gap: '1.5rem', fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                  <span>
                    <span style={{ color: 'var(--text-muted)' }}>Source: </span>
                    <span style={{ fontFamily: 'monospace', color: 'var(--accent-red)' }}>{threat.source_ip}</span>
                  </span>
                  <span>→</span>
                  <span>
                    <span style={{ color: 'var(--text-muted)' }}>Target: </span>
                    <span style={{ fontFamily: 'monospace', color: 'var(--accent-cyan)' }}>{threat.target_ip}</span>
                  </span>
                </div>
                {/* Confidence Bar */}
                <div style={{ marginTop: '0.5rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem', marginBottom: '0.2rem' }}>
                    <span style={{ color: 'var(--text-muted)' }}>ML Confidence (varies by detection strength)</span>
                    <span style={{ color: 'var(--text-secondary)' }}>{(threat.confidence * 100).toFixed(1)}%</span>
                  </div>
                  <div className="confidence-bar">
                    <div className="confidence-fill" style={{
                      width: `${threat.confidence * 100}%`,
                      background: threat.confidence > 0.8
                        ? 'linear-gradient(90deg, var(--accent-red), #f87171)'
                        : threat.confidence > 0.6
                          ? 'linear-gradient(90deg, var(--accent-orange), #fbbf24)'
                          : 'linear-gradient(90deg, var(--accent-blue), var(--accent-cyan))',
                    }} />
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
