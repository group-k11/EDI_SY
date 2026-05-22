import { useState, useEffect } from 'react';
import { Monitor, ArrowUpDown } from 'lucide-react';
import { fetchTraffic, wsManager } from '../services/api';

const protocolColors = {
  TCP: '#3b82f6',
  UDP: '#8b5cf6',
  ICMP: '#f59e0b',
  Other: '#6b7280',
};

export default function TrafficMonitor() {
  const [packets, setPackets] = useState([]);

  useEffect(() => {
    const load = async () => {
      try {
        const data = await fetchTraffic();
        setPackets(data.recent_packets || []);
      } catch (e) { console.error(e); }
    };
    load();

    const unsub = wsManager.subscribe('traffic', (data) => {
      if (data.type === 'update' && data.traffic?.recent_packets) {
        setPackets(data.traffic.recent_packets);
      }
    });

    const interval = setInterval(load, 4000);
    return () => { clearInterval(interval); unsub(); };
  }, []);

  return (
    <div className="card">
      <div className="card-header">
        <div className="card-title">
          <Monitor size={16} style={{ color: 'var(--accent-blue)' }} />
          Live Traffic Monitor
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '0.25rem' }}>
          <div className="live-indicator">
            <span className="live-dot"></span>
            {packets.length} packets
          </div>
          <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>
            Last 30 packets · Updates every 4s
          </div>
        </div>
      </div>

      <div style={{ 
        background: 'rgba(139, 92, 246, 0.05)', 
        border: '1px solid rgba(139, 92, 246, 0.2)',
        borderRadius: '8px',
        padding: '1rem',
        marginBottom: '1.25rem',
        fontSize: '0.8rem',
        color: 'var(--text-secondary)'
      }}>
        <span style={{ color: 'var(--accent-purple)', fontWeight: 600 }}>📡 Packet Stream:</span> Displaying network packets captured and analyzed by the IDS engine. Each row shows source/destination IPs, protocol, ports, and TCP flags.
      </div>

      <div style={{ overflowX: 'auto', maxHeight: '400px', overflowY: 'auto' }}>
        <table className="data-table">
          <thead>
            <tr>
              <th><ArrowUpDown size={12} /> Source IP</th>
              <th>Dest IP</th>
              <th>Protocol</th>
              <th>Src Port</th>
              <th>Dst Port</th>
              <th>Size</th>
              <th>Flags</th>
              <th>Time</th>
            </tr>
          </thead>
          <tbody>
            {packets.slice(-30).reverse().map((pkt, i) => (
              <tr key={i}>
                <td style={{ fontFamily: 'monospace', color: 'var(--accent-cyan)' }}>{pkt.source_ip}</td>
                <td style={{ fontFamily: 'monospace', color: 'var(--accent-blue)' }}>{pkt.destination_ip}</td>
                <td>
                  <span className="badge badge-protocol" style={{ borderColor: protocolColors[pkt.protocol] || '#6b7280', color: protocolColors[pkt.protocol] || '#6b7280' }}>
                    {pkt.protocol}
                  </span>
                </td>
                <td>{pkt.source_port}</td>
                <td>{pkt.destination_port}</td>
                <td>{pkt.packet_length} B</td>
                <td style={{ fontFamily: 'monospace', color: 'var(--accent-orange)' }}>{pkt.tcp_flags || '—'}</td>
                <td style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  {pkt.timestamp ? new Date(pkt.timestamp).toLocaleTimeString() : '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {packets.length === 0 && (
          <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
            <div className="live-dot" style={{ width: 20, height: 20, margin: '0 auto 0.5rem' }}></div>
            <p>Waiting for network traffic...</p>
            <p style={{ fontSize: '0.75rem', marginTop: '0.5rem' }}>Auto-simulation will generate packets shortly</p>
          </div>
        )}
      </div>
    </div>
  );
}
