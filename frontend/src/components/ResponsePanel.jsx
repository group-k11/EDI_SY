/**
 * ResponsePanel — Response Engine management
 * Shows: blocked IPs, rate-limited IPs, impact counters, manual unblock
 * Critical for presentation: "Show the blocking"
 */
import { useState, useEffect, useCallback } from 'react';
import { Shield, ShieldOff, Activity, RefreshCw, Trash2, AlertTriangle, Loader2 } from 'lucide-react';
import { fetchBlocked, unblockIP, fetchResponseStats } from '../services/api';
import { wsManager } from '../services/api';

function StatCard({ label, value, sub, color = 'var(--accent-cyan)', icon: Icon }) {
  return (
    <div className="card" style={{ padding: '1.25rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.4rem' }}>
            {label}
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color, fontFamily: 'monospace' }}>
            {value ?? '—'}
          </div>
          {sub && <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>{sub}</div>}
        </div>
        {Icon && <Icon size={24} color={color} style={{ opacity: 0.6 }} />}
      </div>
    </div>
  );
}

function CountdownBadge({ expiresAt }) {
  const [remaining, setRemaining] = useState('');

  useEffect(() => {
    if (!expiresAt) { setRemaining('∞'); return; }
    const update = () => {
      const diff = new Date(expiresAt) - Date.now();
      if (diff <= 0) { setRemaining('Expired'); return; }
      const m = Math.floor(diff / 60000);
      const s = Math.floor((diff % 60000) / 1000);
      setRemaining(`${m}m ${s}s`);
    };
    update();
    const id = setInterval(update, 1000);
    return () => clearInterval(id);
  }, [expiresAt]);

  return (
    <span style={{
      fontSize: '0.75rem',
      fontFamily: 'monospace',
      color: remaining === 'Expired' ? '#ef4444' : 'var(--text-muted)',
    }}>
      {remaining}
    </span>
  );
}

export default function ResponsePanel() {
  const [blocked, setBlocked] = useState([]);
  const [rateLimited, setRateLimited] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [unblocking, setUnblocking] = useState(null);
  const [error, setError] = useState(null);

  const loadData = useCallback(async () => {
    try {
      const data = await fetchBlocked();
      setBlocked(data.blocked || []);
      setRateLimited(data.rate_limited || []);
      setStats({
        total_blocked: data.total_blocked ?? 0,
        total_packets_blocked: data.total_packets_blocked ?? 0,
        active_rate_limits: data.active_rate_limits ?? 0,
      });
      setError(null);
    } catch (err) {
      setError('Failed to fetch response data');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 5000);

    // Live updates from WebSocket
    const unsub = wsManager.subscribe('response-panel', (data) => {
      if (data.blocked) setBlocked(data.blocked);
      if (data.response_stats) setStats(data.response_stats);
    });

    return () => { clearInterval(interval); unsub(); };
  }, [loadData]);

  const handleUnblock = async (ip) => {
    setUnblocking(ip);
    try {
      await unblockIP(ip);
      setBlocked(prev => prev.filter(b => b.ip !== ip));
    } catch {
      setError(`Failed to unblock ${ip}`);
    } finally {
      setUnblocking(null);
    }
  };

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem' }}>
        <div>
          <h2 style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '0.25rem' }}>
            Response Engine
          </h2>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>
            Active IP blocks, rate limits, and automated response actions
          </p>
        </div>
        <button
          onClick={loadData}
          style={{
            display: 'flex', alignItems: 'center', gap: '0.4rem',
            background: 'none', border: '1px solid var(--border-color)',
            borderRadius: 8, padding: '0.4rem 0.875rem',
            color: 'var(--text-muted)', cursor: 'pointer', fontSize: '0.8rem',
          }}
        >
          <RefreshCw size={14} />
          Refresh
        </button>
      </div>

      {error && (
        <div className="card" style={{ padding: '0.875rem', borderColor: '#ef4444', background: 'rgba(239,68,68,0.07)', marginBottom: '1.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <AlertTriangle size={16} color="#ef4444" />
          <span style={{ fontSize: '0.875rem', color: '#ef4444' }}>{error}</span>
        </div>
      )}

      {/* Stats Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem', marginBottom: '2rem' }}>
        <StatCard label="IPs Blocked" value={stats?.total_blocked ?? 0} icon={Shield} color="#ef4444" sub="All time" />
        <StatCard label="Packets Dropped" value={stats?.total_packets_blocked?.toLocaleString() ?? 0} icon={ShieldOff} color="#f97316" sub="Total blocked" />
        <StatCard label="Rate Limits" value={stats?.active_rate_limits ?? 0} icon={Activity} color="#f59e0b" sub="Currently active" />
        <StatCard label="Active Blocks" value={blocked.length} icon={Shield} color="var(--accent-cyan)" sub="Right now" />
      </div>

      {/* Blocked IPs Table */}
      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <div style={{ padding: '1rem 1.25rem', borderBottom: '1px solid var(--border-color)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Shield size={16} color="#ef4444" />
          <span style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '0.9rem' }}>
            Blocked IPs
          </span>
          <span style={{
            marginLeft: 'auto',
            background: blocked.length > 0 ? 'rgba(239,68,68,0.15)' : 'var(--border-color)',
            color: blocked.length > 0 ? '#ef4444' : 'var(--text-muted)',
            fontSize: '0.75rem',
            fontWeight: 600,
            padding: '2px 8px',
            borderRadius: 4,
          }}>
            {blocked.length}
          </span>
        </div>

        {loading ? (
          <div style={{ padding: '3rem', display: 'flex', justifyContent: 'center' }}>
            <Loader2 size={24} color="var(--text-muted)" style={{ animation: 'spin 1s linear infinite' }} />
          </div>
        ) : blocked.length === 0 ? (
          <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.875rem' }}>
            No IPs currently blocked — system is monitoring
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.825rem' }}>
              <thead>
                <tr>
                  {['IP Address', 'Reason', 'Blocked At', 'Expires', 'Pkts Blocked', 'Action'].map(h => (
                    <th key={h} style={{ padding: '0.75rem 1rem', textAlign: 'left', color: 'var(--text-muted)', fontWeight: 600, fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.05em', borderBottom: '1px solid var(--border-color)' }}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {blocked.map((b, i) => (
                  <tr key={b.ip || i} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                    <td style={{ padding: '0.75rem 1rem', color: '#ef4444', fontFamily: 'monospace', fontWeight: 600 }}>
                      {b.ip}
                    </td>
                    <td style={{ padding: '0.75rem 1rem', color: 'var(--text-secondary)' }}>
                      <span style={{
                        padding: '2px 8px', borderRadius: 4,
                        background: 'rgba(239,68,68,0.1)',
                        color: '#fca5a5', fontSize: '0.75rem',
                      }}>
                        {b.reason || 'auto'}
                      </span>
                    </td>
                    <td style={{ padding: '0.75rem 1rem', color: 'var(--text-muted)', fontFamily: 'monospace', fontSize: '0.75rem' }}>
                      {b.blocked_at ? new Date(b.blocked_at).toLocaleTimeString() : '—'}
                    </td>
                    <td style={{ padding: '0.75rem 1rem' }}>
                      <CountdownBadge expiresAt={b.expires_at} />
                    </td>
                    <td style={{ padding: '0.75rem 1rem', color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                      {(b.packets_blocked || 0).toLocaleString()}
                    </td>
                    <td style={{ padding: '0.75rem 1rem' }}>
                      <button
                        id={`unblock-${b.ip}`}
                        onClick={() => handleUnblock(b.ip)}
                        disabled={unblocking === b.ip}
                        style={{
                          background: 'none',
                          border: '1px solid rgba(239,68,68,0.4)',
                          borderRadius: 6,
                          padding: '3px 10px',
                          color: '#ef4444',
                          fontSize: '0.75rem',
                          cursor: unblocking === b.ip ? 'not-allowed' : 'pointer',
                          display: 'flex', alignItems: 'center', gap: '0.3rem',
                          opacity: unblocking === b.ip ? 0.5 : 1,
                        }}
                      >
                        {unblocking === b.ip
                          ? <Loader2 size={12} style={{ animation: 'spin 1s linear infinite' }} />
                          : <Trash2 size={12} />
                        }
                        Unblock
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Rate-Limited IPs Table */}
      {rateLimited.length > 0 && (
        <div className="card">
          <div style={{ padding: '1rem 1.25rem', borderBottom: '1px solid var(--border-color)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Activity size={16} color="#f59e0b" />
            <span style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '0.9rem' }}>
              Rate-Limited IPs
            </span>
            <span style={{
              marginLeft: 'auto',
              background: 'rgba(245,158,11,0.12)',
              color: '#f59e0b',
              fontSize: '0.75rem',
              fontWeight: 600,
              padding: '2px 8px',
              borderRadius: 4,
            }}>
              {rateLimited.length}
            </span>
          </div>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.825rem' }}>
              <thead>
                <tr>
                  {['IP Address', 'Reason', 'Since', 'Expires'].map(h => (
                    <th key={h} style={{ padding: '0.75rem 1rem', textAlign: 'left', color: 'var(--text-muted)', fontWeight: 600, fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.05em', borderBottom: '1px solid var(--border-color)' }}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rateLimited.map((r, i) => (
                  <tr key={r.ip || i} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                    <td style={{ padding: '0.75rem 1rem', color: '#f59e0b', fontFamily: 'monospace', fontWeight: 600 }}>{r.ip}</td>
                    <td style={{ padding: '0.75rem 1rem', color: 'var(--text-muted)', fontSize: '0.8rem' }}>{r.reason || 'rate_limit'}</td>
                    <td style={{ padding: '0.75rem 1rem', color: 'var(--text-muted)', fontFamily: 'monospace', fontSize: '0.75rem' }}>
                      {r.since ? new Date(r.since).toLocaleTimeString() : '—'}
                    </td>
                    <td style={{ padding: '0.75rem 1rem' }}>
                      <CountdownBadge expiresAt={r.expires_at} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
