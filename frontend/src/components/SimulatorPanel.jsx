/**
 * SimulatorPanel — Attack Simulator controls
 * For live demo: "Launch attack and watch it get caught"
 */
import { useState, useEffect, useRef } from 'react';
import { Play, Square, Zap, AlertCircle, CheckCircle, Loader2, RefreshCw } from 'lucide-react';
import { runSimulationOneShot, stopSimulator } from '../services/api';
import { wsManager } from '../services/api';

const ATTACK_CONFIGS = [
  {
    id: 'ddos',
    label: 'DDoS Attack',
    icon: '🌊',
    desc: 'Distributed flood of packets overwhelming target bandwidth',
    color: '#ef4444',
    technique: 'T1498',
    severity: 'CRITICAL',
  },
  {
    id: 'port_scan',
    label: 'Port Scan',
    icon: '🔍',
    desc: 'Systematic probe of ports to enumerate open services',
    color: '#f97316',
    technique: 'T1046',
    severity: 'MEDIUM',
  },
  {
    id: 'brute_force',
    label: 'Brute Force',
    icon: '🔨',
    desc: 'Repeated credential attempts against authentication service',
    color: '#f59e0b',
    technique: 'T1110',
    severity: 'HIGH',
  },
  {
    id: 'suspicious',
    label: 'Suspicious Traffic',
    icon: '👁️',
    desc: 'Anomalous traffic pattern not matching known attack signatures',
    color: '#8b5cf6',
    technique: 'T1595',
    severity: 'MEDIUM',
  },
];

function ResultEntry({ result, index }) {
  const severityColor = result.severity?.color || '#94a3b8';
  const age = Date.now() - (result._ts || Date.now());

  return (
    <div style={{
      padding: '0.875rem 1rem',
      borderBottom: '1px solid rgba(255,255,255,0.04)',
      display: 'flex',
      alignItems: 'flex-start',
      gap: '0.75rem',
      animation: 'slideInRight 0.3s ease',
      opacity: Math.max(0.4, 1 - index * 0.12),
    }}>
      <div style={{
        width: 8, height: 8, borderRadius: '50%',
        background: severityColor,
        marginTop: 5,
        flexShrink: 0,
        boxShadow: `0 0 6px ${severityColor}`,
      }} />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center', marginBottom: '0.25rem' }}>
          <span style={{ fontWeight: 700, color: severityColor, fontSize: '0.8rem' }}>
            {result.prediction || 'UNKNOWN'}
          </span>
          <span style={{
            padding: '1px 6px', borderRadius: 4,
            background: `${severityColor}18`,
            color: severityColor, fontSize: '0.7rem', fontWeight: 600,
          }}>
            {result.severity?.level || '—'}
          </span>
          {result.response_action?.action && (
            <span style={{
              padding: '1px 6px', borderRadius: 4,
              background: result.response_action.action === 'BLOCKED'
                ? 'rgba(239,68,68,0.15)' : 'rgba(245,158,11,0.12)',
              color: result.response_action.action === 'BLOCKED' ? '#ef4444' : '#f59e0b',
              fontSize: '0.7rem', fontWeight: 600,
            }}>
              {result.response_action.action}
            </span>
          )}
        </div>
        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'monospace' }}>
          {result.source_ip || '—'} → {((result.confidence || 0) * 100).toFixed(0)}% confidence
          {result.mitre?.technique_id && ` · ${result.mitre.technique_id}`}
        </div>
      </div>
      <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', fontFamily: 'monospace', flexShrink: 0 }}>
        {new Date().toLocaleTimeString()}
      </div>
    </div>
  );
}

export default function SimulatorPanel() {
  const [selected, setSelected] = useState('ddos');
  const [running, setRunning] = useState(false);
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState([]);
  const [error, setError] = useState(null);
  const feedRef = useRef(null);

  // Listen for WebSocket threat alerts — they populate the results feed
  useEffect(() => {
    const unsub = wsManager.subscribe('simulator-panel', (data) => {
      if (data.type === 'threat_alert' && data.threats?.length) {
        setResults(prev => [
          ...data.threats.map(t => ({ ...t, _ts: Date.now() })),
          ...prev,
        ].slice(0, 20));
      }
    });
    return unsub;
  }, []);

  // Auto-scroll feed to top on new results
  useEffect(() => {
    if (feedRef.current) feedRef.current.scrollTop = 0;
  }, [results.length]);

  const handleLaunch = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await runSimulationOneShot(selected);
      setRunning(true);
      // If the response contains analysis data, add to feed immediately
      if (res.prediction || res.alert_id) {
        setResults(prev => [{ ...res, _ts: Date.now() }, ...prev].slice(0, 20));
      }
      // Auto-stop indicator after 30s
      setTimeout(() => setRunning(false), 30000);
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Simulation failed');
    } finally {
      setLoading(false);
    }
  };

  const handleStop = async () => {
    try { await stopSimulator(); } catch { /* ok */ }
    setRunning(false);
  };

  const selectedConfig = ATTACK_CONFIGS.find(a => a.id === selected);

  return (
    <div>
      <div style={{ marginBottom: '2rem' }}>
        <h2 style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '0.25rem' }}>
          Attack Simulator
        </h2>
        <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>
          Generate synthetic attack traffic and watch A.I.R.S detect and respond in real-time
        </p>
      </div>

      {/* Attack Type Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem', marginBottom: '1.5rem' }}>
        {ATTACK_CONFIGS.map(attack => (
          <button
            key={attack.id}
            onClick={() => setSelected(attack.id)}
            style={{
              padding: '1.25rem',
              borderRadius: 12,
              border: `2px solid ${selected === attack.id ? attack.color : 'var(--border-color)'}`,
              background: selected === attack.id ? `${attack.color}12` : 'var(--card-bg)',
              textAlign: 'left',
              cursor: 'pointer',
              transition: 'all 0.2s',
              boxShadow: selected === attack.id ? `0 0 20px ${attack.color}22` : 'none',
            }}
          >
            <div style={{ fontSize: '1.75rem', marginBottom: '0.5rem' }}>{attack.icon}</div>
            <div style={{ fontWeight: 700, color: selected === attack.id ? attack.color : 'var(--text-primary)', fontSize: '0.9rem', marginBottom: '0.25rem' }}>
              {attack.label}
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', lineHeight: 1.4, marginBottom: '0.75rem' }}>
              {attack.desc}
            </div>
            <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
              <span style={{
                padding: '2px 6px', borderRadius: 4,
                background: `${attack.color}18`, color: attack.color,
                fontSize: '0.65rem', fontWeight: 600, fontFamily: 'monospace',
              }}>
                {attack.technique}
              </span>
              <span style={{
                padding: '2px 6px', borderRadius: 4,
                background: 'rgba(255,255,255,0.05)', color: 'var(--text-muted)',
                fontSize: '0.65rem', fontWeight: 600,
              }}>
                {attack.severity}
              </span>
            </div>
          </button>
        ))}
      </div>

      {/* Control Bar */}
      <div className="card" style={{ padding: '1.25rem', marginBottom: '1.5rem', display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-primary)' }}>
            {selectedConfig?.icon} {selectedConfig?.label}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.15rem' }}>
            {selectedConfig?.desc}
          </div>
        </div>

        {running && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <div className="live-dot" style={{ width: 8, height: 8 }} />
            <span style={{ fontSize: '0.8rem', color: 'var(--accent-green)' }}>Simulation running</span>
          </div>
        )}

        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <button
            id="simulator-launch-btn"
            onClick={handleLaunch}
            disabled={loading}
            style={{
              padding: '0.5rem 1.5rem',
              borderRadius: 8, border: 'none',
              background: loading ? 'var(--border-color)' : `linear-gradient(135deg, ${selectedConfig?.color || '#ef4444'}, #6366f1)`,
              color: '#fff', fontWeight: 600, fontSize: '0.875rem',
              cursor: loading ? 'not-allowed' : 'pointer',
              display: 'flex', alignItems: 'center', gap: '0.5rem',
              transition: 'opacity 0.2s',
            }}
          >
            {loading ? <Loader2 size={16} style={{ animation: 'spin 1s linear infinite' }} /> : <Zap size={16} />}
            {loading ? 'Launching…' : 'Launch Attack'}
          </button>

          {running && (
            <button
              id="simulator-stop-btn"
              onClick={handleStop}
              style={{
                padding: '0.5rem 1rem',
                borderRadius: 8, border: '1px solid #ef4444',
                background: 'rgba(239,68,68,0.1)', color: '#ef4444',
                fontWeight: 600, fontSize: '0.875rem',
                cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '0.5rem',
              }}
            >
              <Square size={14} />
              Stop
            </button>
          )}
        </div>
      </div>

      {error && (
        <div className="card" style={{ padding: '0.875rem', borderColor: '#ef4444', background: 'rgba(239,68,68,0.07)', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <AlertCircle size={16} color="#ef4444" />
          <span style={{ fontSize: '0.875rem', color: '#ef4444' }}>{error}</span>
        </div>
      )}

      {/* Live Results Feed */}
      <div className="card">
        <div style={{ padding: '1rem 1.25rem', borderBottom: '1px solid var(--border-color)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Zap size={16} color="var(--accent-cyan)" />
          <span style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '0.9rem' }}>
            Live Detection Feed
          </span>
          <span style={{ marginLeft: 'auto', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            {results.length} detections
          </span>
          {results.length > 0 && (
            <button
              onClick={() => setResults([])}
              style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}
            >
              <RefreshCw size={12} /> Clear
            </button>
          )}
        </div>

        <div ref={feedRef} style={{ maxHeight: 380, overflowY: 'auto' }}>
          {results.length === 0 ? (
            <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.875rem' }}>
              <Zap size={32} style={{ opacity: 0.3, marginBottom: '0.75rem', display: 'block', margin: '0 auto 0.75rem' }} />
              Launch an attack above — detections will appear here live via WebSocket
            </div>
          ) : (
            results.map((r, i) => (
              <ResultEntry key={`${r._ts}-${i}`} result={r} index={i} />
            ))
          )}
        </div>
      </div>
    </div>
  );
}
