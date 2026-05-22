import { useState, useEffect } from 'react';
import { FileText, Filter, Download } from 'lucide-react';
import { fetchLogs } from '../services/api';

const attackTypes = ['all', 'port_scan', 'dos', 'brute_force', 'suspicious'];

export default function AttackLogs() {
  const [logs, setLogs] = useState([]);
  const [summary, setSummary] = useState({});
  const [filter, setFilter] = useState('all');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      try {
        const data = await fetchLogs(200, filter === 'all' ? null : filter);
        setLogs(data.logs || []);
        setSummary(data.summary || {});
      } catch (e) { console.error(e); }
      setLoading(false);
    };
    load();
    const interval = setInterval(load, 10000);
    return () => clearInterval(interval);
  }, [filter]);

  const exportCSV = () => {
    const headers = ['Timestamp', 'Source IP', 'Target IP', 'Attack Type', 'Severity', 'Confidence', 'Packet Count', 'Flow Duration'];
    const rows = logs.map(l => [l.timestamp, l.source_ip, l.target_ip, l.attack_type, l.severity, l.confidence, l.packet_count, l.flow_duration]);
    const csv = [headers, ...rows].map(r => r.join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `attack_logs_${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="card">
      <div className="card-header">
        <div className="card-title">
          <FileText size={16} style={{ color: 'var(--accent-orange)' }} />
          Attack Logs
        </div>
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          <button className="btn btn-outline" onClick={exportCSV} style={{ padding: '0.35rem 0.65rem' }}>
            <Download size={14} /> CSV
          </button>
        </div>
      </div>

      {/* Summary Bar */}
      <div style={{ display: 'flex', gap: '1rem', marginBottom: '1rem', flexWrap: 'wrap' }}>
        <div style={{ background: 'var(--bg-primary)', padding: '0.5rem 1rem', borderRadius: '8px', fontSize: '0.78rem' }}>
          <span style={{ color: 'var(--text-muted)' }}>Total: </span>
          <span style={{ fontWeight: 700, color: 'var(--accent-blue)' }}>{summary.total_threats || 0}</span>
        </div>
        {summary.by_severity && Object.entries(summary.by_severity).map(([sev, count]) => (
          <div key={sev} style={{ background: 'var(--bg-primary)', padding: '0.5rem 1rem', borderRadius: '8px', fontSize: '0.78rem' }}>
            <span className={`badge badge-${sev}`} style={{ marginRight: '0.4rem' }}>{sev}</span>
            <span style={{ fontWeight: 600 }}>{count}</span>
          </div>
        ))}
      </div>

      {/* Filter */}
      <div style={{ display: 'flex', gap: '0.35rem', marginBottom: '1rem', flexWrap: 'wrap' }}>
        <Filter size={14} style={{ color: 'var(--text-muted)', marginTop: '0.35rem' }} />
        {attackTypes.map(type => (
          <button
            key={type}
            className={`btn ${filter === type ? 'btn-primary' : 'btn-outline'}`}
            style={{ padding: '0.3rem 0.7rem', fontSize: '0.75rem' }}
            onClick={() => setFilter(type)}
          >
            {type.replace(/_/g, ' ')}
          </button>
        ))}
      </div>

      {/* Table */}
      <div style={{ overflowX: 'auto', maxHeight: '400px', overflowY: 'auto' }}>
        <table className="data-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Source IP</th>
              <th>Target IP</th>
              <th>Attack Type</th>
              <th>Severity</th>
              <th>Confidence</th>
              <th>Packets</th>
              <th>Duration</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={8} style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>Loading...</td></tr>
            ) : logs.length === 0 ? (
              <tr><td colSpan={8} style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>No attack logs yet</td></tr>
            ) : (
              logs.map((log, i) => (
                <tr key={log.id || i}>
                  <td style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    {log.timestamp ? new Date(log.timestamp).toLocaleString() : '—'}
                  </td>
                  <td style={{ fontFamily: 'monospace', color: 'var(--accent-red)' }}>{log.source_ip}</td>
                  <td style={{ fontFamily: 'monospace', color: 'var(--accent-cyan)' }}>{log.target_ip}</td>
                  <td>
                    <span className="badge badge-attack">{log.attack_type?.replace(/_/g, ' ')}</span>
                  </td>
                  <td>
                    <span className={`badge badge-${log.severity}`}>{log.severity}</span>
                  </td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <div className="confidence-bar" style={{ width: '60px' }}>
                        <div className="confidence-fill" style={{
                          width: `${(log.confidence || 0) * 100}%`,
                          background: 'var(--accent-blue)',
                        }} />
                      </div>
                      <span style={{ fontSize: '0.7rem' }}>{((log.confidence || 0) * 100).toFixed(0)}%</span>
                    </div>
                  </td>
                  <td>{log.packet_count || 0}</td>
                  <td>{(log.flow_duration || 0).toFixed(2)}s</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
