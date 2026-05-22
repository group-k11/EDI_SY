import { useState, useEffect, useCallback } from 'react';
import { BarChart3 } from 'lucide-react';
import {
  LineChart, Line, AreaChart, Area, PieChart, Pie, Cell,
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from 'recharts';
import { fetchTraffic, wsManager } from '../services/api';

const COLORS = ['#3b82f6', '#8b5cf6', '#f59e0b', '#6b7280', '#ef4444', '#10b981'];

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: 8, padding: '0.5rem 0.75rem', fontSize: '0.75rem' }}>
      <p style={{ color: 'var(--text-muted)', marginBottom: '0.25rem' }}>{label}</p>
      {payload.map((p, i) => (
        <p key={i} style={{ color: p.color }}>{p.name}: {typeof p.value === 'number' ? p.value.toLocaleString() : p.value}</p>
      ))}
    </div>
  );
};

export default function AnalyticsCharts() {
  const [trafficHistory, setTrafficHistory] = useState([]);
  const [protocols, setProtocols] = useState([]);
  const [topIPs, setTopIPs] = useState([]);

  const processData = useCallback((data) => {
    // Protocol distribution
    const proto = data.capture?.protocols || {};
    const protoData = Object.entries(proto)
      .filter(([, v]) => v > 0)
      .map(([name, value]) => ({ name, value }));
    setProtocols(protoData);

    // Traffic history (append new data point)
    const newPoint = {
      time: new Date().toLocaleTimeString(),
      packets: data.capture?.packets_captured || 0,
      flows: data.flows?.active_flows || 0,
      bytes: Math.round((data.capture?.bytes_total || 0) / 1024),
    };
    setTrafficHistory(prev => {
      const next = [...prev, newPoint];
      return next.length > 20 ? next.slice(-20) : next;
    });

    // Top source IPs from recent packets
    const ipCount = {};
    (data.recent_packets || []).forEach(pkt => {
      ipCount[pkt.source_ip] = (ipCount[pkt.source_ip] || 0) + 1;
    });
    const sorted = Object.entries(ipCount)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 8)
      .map(([ip, count]) => ({ ip: ip.length > 12 ? '...' + ip.slice(-10) : ip, count, fullIp: ip }));
    setTopIPs(sorted);
  }, []);

  useEffect(() => {
    const load = async () => {
      try {
        const data = await fetchTraffic();
        processData(data);
      } catch (e) { console.error(e); }
    };
    load();

    const unsub = wsManager.subscribe('analytics', (data) => {
      if (data.type === 'update') processData(data.traffic);
    });
    const interval = setInterval(load, 6000);
    return () => { clearInterval(interval); unsub(); };
  }, [processData]);

  return (
    <div>
      <div className="card-header" style={{ marginBottom: '1rem' }}>
        <div className="card-title">
          <BarChart3 size={16} style={{ color: 'var(--accent-purple)' }} />
          Traffic Analytics
        </div>
      </div>

      <div className="dashboard-grid">
        {/* Traffic Trend */}
        <div className="card">
          <div className="card-title" style={{ marginBottom: '0.75rem', fontSize: '0.82rem' }}>
            📈 Network Traffic Trend
          </div>
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={trafficHistory}>
              <defs>
                <linearGradient id="colorPackets" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="colorBytes" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(45,55,72,0.5)" />
              <XAxis dataKey="time" tick={{ fill: '#64748b', fontSize: 10 }} />
              <YAxis tick={{ fill: '#64748b', fontSize: 10 }} />
              <Tooltip content={<CustomTooltip />} />
              <Area type="monotone" dataKey="packets" stroke="#3b82f6" fillOpacity={1} fill="url(#colorPackets)" name="Packets" />
              <Area type="monotone" dataKey="bytes" stroke="#06b6d4" fillOpacity={1} fill="url(#colorBytes)" name="KB" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Protocol Distribution */}
        <div className="card">
          <div className="card-title" style={{ marginBottom: '0.75rem', fontSize: '0.82rem' }}>
            🔵 Protocol Distribution
          </div>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie
                data={protocols}
                cx="50%"
                cy="50%"
                innerRadius={55}
                outerRadius={85}
                paddingAngle={3}
                dataKey="value"
              >
                {protocols.map((_, i) => (
                  <Cell key={i} fill={COLORS[i % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip content={<CustomTooltip />} />
              <Legend wrapperStyle={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }} />
            </PieChart>
          </ResponsiveContainer>
          {protocols.length === 0 && (
            <div style={{ textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.8rem' }}>
              No protocol data yet
            </div>
          )}
        </div>

        {/* Top Source IPs */}
        <div className="card full-width">
          <div className="card-title" style={{ marginBottom: '0.75rem', fontSize: '0.82rem' }}>
            🌐 Top Source IPs
          </div>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={topIPs} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(45,55,72,0.5)" />
              <XAxis type="number" tick={{ fill: '#64748b', fontSize: 10 }} />
              <YAxis dataKey="ip" type="category" width={100} tick={{ fill: '#94a3b8', fontSize: 10, fontFamily: 'monospace' }} />
              <Tooltip content={<CustomTooltip />} />
              <Bar dataKey="count" name="Packets" radius={[0, 4, 4, 0]}>
                {topIPs.map((_, i) => (
                  <Cell key={i} fill={COLORS[i % COLORS.length]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
          {topIPs.length === 0 && (
            <div style={{ textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.8rem', padding: '1rem' }}>
              No source IP data yet
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
