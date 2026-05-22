/**
 * Dashboard — War Room Overview
 * Fixed API keys + Live data-flow animation + Packet visualization + Cybersecurity background
 */
import { useState, useEffect, useCallback, useRef } from 'react';
import {
  Shield, Activity, AlertTriangle, Zap, Wifi,
  Cpu, Brain, Eye, Lock, Radio, Server, Database
} from 'lucide-react';
import { fetchTraffic, fetchSystemStatus, fetchThreats, fetchBlocked, runSimulationOneShot, wsManager } from '../services/api';

// ─── Cybersecurity background canvas ───────────────────────────────────────
function CyberBackground() {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let animId;
    let W = canvas.offsetWidth;
    let H = canvas.offsetHeight;
    canvas.width = W;
    canvas.height = H;

    const resize = () => {
      W = canvas.offsetWidth; H = canvas.offsetHeight;
      canvas.width = W; canvas.height = H;
    };
    window.addEventListener('resize', resize);

    // Nodes: random IP-looking dots
    const NODE_COUNT = 28;
    const nodes = Array.from({ length: NODE_COUNT }, (_, i) => ({
      x: Math.random() * W,
      y: Math.random() * H,
      vx: (Math.random() - 0.5) * 0.3,
      vy: (Math.random() - 0.5) * 0.3,
      r: 2 + Math.random() * 2,
      color: i < 4
        ? 'rgba(255,48,48,0.9)'        // red = threat nodes
        : i < 10
          ? 'rgba(0,212,255,0.8)'      // cyan = scanning nodes
          : 'rgba(0,255,136,0.6)',     // green = normal
      label: i < 4
        ? `${10 + i}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`
        : `192.168.${Math.floor(Math.random()*5)}.${Math.floor(Math.random()*255)}`,
      pulse: Math.random() * Math.PI * 2,
    }));

    // Moving data packets along connections
    const packets = [];
    const spawnPacket = () => {
      const src = Math.floor(Math.random() * NODE_COUNT);
      let dst = Math.floor(Math.random() * NODE_COUNT);
      while (dst === src) dst = Math.floor(Math.random() * NODE_COUNT);
      packets.push({
        src, dst, t: 0,
        speed: 0.004 + Math.random() * 0.006,
        color: nodes[src].color,
        size: 2.5,
      });
    };

    const draw = () => {
      ctx.clearRect(0, 0, W, H);

      // Update nodes
      nodes.forEach(n => {
        n.x += n.vx; n.y += n.vy;
        n.pulse += 0.04;
        if (n.x < 0 || n.x > W) n.vx *= -1;
        if (n.y < 0 || n.y > H) n.vy *= -1;
      });

      // Draw edges (connections between close nodes)
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const dx = nodes[j].x - nodes[i].x;
          const dy = nodes[j].y - nodes[i].y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 200) {
            const alpha = (1 - dist / 200) * 0.12;
            ctx.beginPath();
            ctx.moveTo(nodes[i].x, nodes[i].y);
            ctx.lineTo(nodes[j].x, nodes[j].y);
            ctx.strokeStyle = `rgba(0,255,136,${alpha})`;
            ctx.lineWidth = 0.5;
            ctx.stroke();
          }
        }
      }

      // Draw nodes
      nodes.forEach(n => {
        // Pulse ring
        const pr = n.r + 4 + Math.sin(n.pulse) * 3;
        ctx.beginPath();
        ctx.arc(n.x, n.y, pr, 0, Math.PI * 2);
        ctx.strokeStyle = n.color.replace(/[\d.]+\)$/, '0.12)');
        ctx.lineWidth = 1;
        ctx.stroke();

        // Core dot
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
        ctx.fillStyle = n.color;
        ctx.fill();
      });

      // Move packets
      if (packets.length < 20 && Math.random() < 0.04) spawnPacket();

      packets.forEach((p, idx) => {
        p.t += p.speed;
        if (p.t >= 1) { packets.splice(idx, 1); return; }
        const sx = nodes[p.src].x, sy = nodes[p.src].y;
        const dx = nodes[p.dst].x, dy = nodes[p.dst].y;
        const px = sx + (dx - sx) * p.t;
        const py = sy + (dy - sy) * p.t;

        // Packet trail
        ctx.beginPath();
        const trail = 0.06;
        const tx = sx + (dx - sx) * Math.max(0, p.t - trail);
        const ty = sy + (dy - sy) * Math.max(0, p.t - trail);
        const grad = ctx.createLinearGradient(tx, ty, px, py);
        grad.addColorStop(0, p.color.replace(/[\d.]+\)$/, '0)'));
        grad.addColorStop(1, p.color);
        ctx.moveTo(tx, ty);
        ctx.lineTo(px, py);
        ctx.strokeStyle = grad;
        ctx.lineWidth = 1.5;
        ctx.stroke();

        // Packet dot
        ctx.beginPath();
        ctx.arc(px, py, p.size, 0, Math.PI * 2);
        ctx.fillStyle = p.color;
        ctx.fill();
      });

      animId = requestAnimationFrame(draw);
    };

    draw();
    return () => { cancelAnimationFrame(animId); window.removeEventListener('resize', resize); };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      style={{
        position: 'fixed',
        inset: 0,
        width: '100%',
        height: '100%',
        zIndex: 0,
        pointerEvents: 'none',
        opacity: 0.35,
      }}
    />
  );
}

// ─── Live data-flow animation along pipeline ────────────────────────────────
function PipelineDataFlow({ steps, activeStep }) {
  const [packetPos, setPacketPos] = useState(0);

  useEffect(() => {
    const id = setInterval(() => {
      setPacketPos(p => (p + 1) % steps.length);
    }, 1400);
    return () => clearInterval(id);
  }, [steps.length]);

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 0, overflowX: 'auto', paddingBottom: '0.5rem' }}>
      {steps.map((step, i) => {
        const Icon = step.icon;
        const isActive = i === packetPos;
        const isDone = i < packetPos;
        return (
          <div key={step.id} style={{ display: 'flex', alignItems: 'center', flex: 1, minWidth: 120 }}>
            {/* Step card */}
            <div style={{
              flex: 1,
              background: isActive
                ? `${step.color}18`
                : isDone ? 'rgba(0,255,136,0.04)' : 'rgba(6,15,26,0.8)',
              border: `1px solid ${isActive ? step.color : isDone ? 'rgba(0,255,136,0.15)' : 'var(--border-dim)'}`,
              borderRadius: '6px',
              padding: '0.9rem 0.5rem',
              transition: 'all 0.4s cubic-bezier(0.16,1,0.3,1)',
              boxShadow: isActive ? `0 0 16px ${step.color}25` : 'none',
              minHeight: 110,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              textAlign: 'center',
              gap: '0.4rem',
              position: 'relative',
              overflow: 'hidden',
            }}>
              {/* Active sweep line */}
              {isActive && (
                <div style={{
                  position: 'absolute',
                  top: 0, left: '-100%',
                  width: '200%', height: '100%',
                  background: `linear-gradient(90deg, transparent 0%, ${step.color}15 50%, transparent 100%)`,
                  animation: 'sweep 1.4s linear infinite',
                  pointerEvents: 'none',
                }} />
              )}

              <div style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '0.52rem',
                color: isActive ? step.color : 'var(--txt-dim)',
                letterSpacing: '0.1em',
                transition: 'color 0.3s',
              }}>
                STEP {i + 1}
              </div>

              <Icon
                size={20}
                color={isActive ? step.color : isDone ? 'rgba(0,255,136,0.5)' : 'var(--txt-dim)'}
                style={{ transition: 'color 0.3s' }}
              />

              <div style={{
                fontFamily: 'var(--font-ui)',
                fontSize: '0.67rem',
                fontWeight: 700,
                color: isActive ? step.color : isDone ? 'var(--txt-mid)' : 'var(--txt-dim)',
                textTransform: 'uppercase',
                letterSpacing: '0.04em',
                lineHeight: 1.2,
                transition: 'color 0.3s',
              }}>
                {step.label}
              </div>

              {/* Status chip */}
              <div style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '0.56rem',
                padding: '1px 6px',
                borderRadius: '3px',
                background: isActive
                  ? `${step.color}20`
                  : isDone ? 'rgba(0,255,136,0.08)' : 'transparent',
                color: isActive ? step.color : isDone ? 'var(--phos-100)' : 'var(--txt-dim)',
                border: `1px solid ${isActive ? step.color : isDone ? 'rgba(0,255,136,0.15)' : 'transparent'}`,
                letterSpacing: '0.06em',
                transition: 'all 0.3s',
              }}>
                {isActive ? 'PROCESSING' : isDone ? '✓ DONE' : 'WAITING'}
              </div>

              {/* Description (always visible, small) */}
              <div style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '0.57rem',
                color: 'var(--txt-dim)',
                lineHeight: 1.45,
                padding: '0 4px',
                marginTop: '2px',
              }}>
                {step.desc}
              </div>
            </div>

            {/* Connector with animated packet dot */}
            {i < steps.length - 1 && (
              <div style={{ position: 'relative', width: 28, flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                {/* Line */}
                <div style={{
                  width: '100%',
                  height: 1,
                  background: i < packetPos
                    ? 'linear-gradient(90deg, rgba(0,255,136,0.4), rgba(0,255,136,0.1))'
                    : 'var(--border-dim)',
                  transition: 'background 0.4s',
                }} />
                {/* Arrow */}
                <div style={{
                  position: 'absolute',
                  right: 2,
                  color: i < packetPos ? 'var(--phos-100)' : 'var(--txt-dim)',
                  fontSize: '0.7rem',
                  lineHeight: 1,
                  transition: 'color 0.3s',
                }}>›</div>
                {/* Moving packet */}
                {i === packetPos - 1 && (
                  <div style={{
                    position: 'absolute',
                    width: 6, height: 6,
                    borderRadius: '50%',
                    background: steps[i].color,
                    boxShadow: `0 0 6px ${steps[i].color}`,
                    animation: 'packet-cross 1.4s linear',
                    left: 0,
                  }} />
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ─── Stat card ─────────────────────────────────────────────────────────────
function StatCard({ label, value, icon: Icon, color, sub }) {
  const colorMap = {
    cyan: 'var(--sig-cyan)', red: 'var(--threat-critical)',
    blue: 'var(--sig-blue)', orange: 'var(--threat-high)',
    purple: 'var(--sig-purple)', green: 'var(--phos-100)',
  };
  const c = colorMap[color] || 'var(--phos-100)';
  return (
    <div className={`stat-card ${color}`} style={{ position: 'relative', overflow: 'hidden' }}>
      <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 1, background: `linear-gradient(90deg, transparent, ${c}60, transparent)` }} />
      <div className="stat-icon"><Icon size={18} color={c} /></div>
      <div className="stat-value" style={{ color: c, fontSize: '1.8rem' }}>{value}</div>
      <div className="stat-label">{label}</div>
      {sub && <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.58rem', color: 'var(--txt-dim)', marginTop: '4px', letterSpacing: '0.04em' }}>{sub}</div>}
    </div>
  );
}

// ─── Pipeline steps ─────────────────────────────────────────────────────────
const PIPELINE_STEPS = [
  { id: 'capture', label: 'Packet Capture', icon: Wifi,    color: 'var(--sig-cyan)',        desc: 'Scapy / synthetic demo flows' },
  { id: 'flow',    label: 'Flow Builder',   icon: Activity, color: 'var(--phos-100)',        desc: '5-tuple bidirectional flows' },
  { id: 'feat',    label: 'Features',       icon: Database, color: 'var(--sig-blue)',        desc: '25 statistical features extracted' },
  { id: 'ml',      label: 'ML Engine',      icon: Brain,    color: 'rgba(124,58,237,0.9)',   desc: 'IF → RF → LSTM models' },
  { id: 'shap',    label: 'SHAP',           icon: Eye,      color: 'var(--sig-purple)',      desc: 'Feature importance explained' },
  { id: 'intel',   label: 'MITRE / LLM',   icon: Shield,   color: 'var(--threat-high)',     desc: 'ATT&CK mapping + Claude analysis' },
  { id: 'score',   label: 'Severity',       icon: Zap,      color: 'var(--threat-med)',      desc: 'Multi-factor threat scoring' },
  { id: 'respond', label: 'Auto-Block',     icon: Lock,     color: 'var(--threat-critical)', desc: 'IP blocked in milliseconds' },
];

const MODEL_STATUS = [
  { name: 'Isolation Forest', role: 'Anomaly Detection',       key: 'isolation_forest', accuracy: '91%' },
  { name: 'Random Forest',    role: 'Attack Classification',   key: 'random_forest',    accuracy: '94%' },
  { name: 'LSTM Network',     role: 'Sequential Patterns',     key: 'lstm',             accuracy: '89%' },
  { name: 'Autoencoder',      role: 'Reconstruction Anomaly',  key: 'autoencoder',      accuracy: '—'   },
  { name: 'Claude LLM',       role: 'Threat Report NLG',       key: null,               accuracy: '—'   },
];

const SIM_ATTACKS = [
  { type: 'ddos',        label: 'DDoS',        icon: '💥', color: 'var(--threat-critical)' },
  { type: 'port_scan',   label: 'Port Scan',   icon: '🔍', color: 'var(--threat-med)'      },
  { type: 'brute_force', label: 'Brute Force', icon: '🔑', color: 'var(--threat-high)'     },
  { type: 'suspicious',  label: 'Suspicious',  icon: '⚠️', color: 'var(--sig-cyan)'        },
];

// ─── Main Dashboard ─────────────────────────────────────────────────────────
export default function Dashboard() {
  const [stats, setStats]           = useState({ packets_captured: 0, threats_detected: 0, flows_analyzed: 0, blocked_ips: 0, avg_confidence: 0 });
  const [models, setModels]         = useState({});
  const [mode, setMode]             = useState('demo');
  const [simulating, setSimulating] = useState(null);
  const [simMsg, setSimMsg]         = useState(null);
  const [uptime, setUptime]         = useState(0);

  const refresh = useCallback(async () => {
    try {
      const [traffic, system, threats, blocked] = await Promise.allSettled([
        fetchTraffic(),
        fetchSystemStatus(),
        fetchThreats(),
        fetchBlocked(),
      ]);

      const t = traffic.status  === 'fulfilled' ? traffic.value  : {};
      const s = system.status   === 'fulfilled' ? system.value   : {};
      const th = threats.status === 'fulfilled' ? threats.value  : [];
      const bl = blocked.status === 'fulfilled' ? blocked.value  : {};

      setModels(s.models || {});
      setMode(s.mode || 'demo');
      setUptime(Math.floor(s.uptime || 0));

      setStats({
        packets_captured: t.packets_captured ?? s.packets_captured ?? 0,
        flows_analyzed:   t.flows_analyzed   ?? s.flows_analyzed   ?? 0,
        threats_detected: Array.isArray(th) ? th.length : (th.total ?? s.threats_detected ?? 0),
        blocked_ips:      bl.total_blocked   ?? bl.blocked_ips     ?? s.response_engine?.total_blocked ?? 0,
        avg_confidence:   t.avg_confidence   ?? 0,
      });
    } catch { /* keep last values */ }
  }, []);

  useEffect(() => {
    refresh();
    const iv = setInterval(refresh, 2000);  // refresh every 2s
    const unsub = wsManager.subscribe('dashboard_main', (data) => {
      if (data.type === 'update' && data.traffic) {
        setStats(s => ({ ...s, ...data.traffic }));
      }
      if (data.type === 'threat_alert') {
        setStats(s => ({ ...s, threats_detected: (s.threats_detected || 0) + (data.threats?.length || 0) }));
      }
    });
    return () => { clearInterval(iv); unsub(); };
  }, [refresh]);

  const handleSim = async (type) => {
    setSimulating(type);
    setSimMsg(null);
    try {
      await runSimulationOneShot(type);
      setSimMsg({ ok: true, text: `${type.replace('_', ' ').toUpperCase()} injected — pipeline processing` });
      setTimeout(refresh, 2500);
    } catch {
      setSimMsg({ ok: false, text: 'Backend not reachable — is uvicorn running?' });
    } finally {
      setTimeout(() => { setSimulating(null); setSimMsg(null); }, 4500);
    }
  };

  const uptimeStr = uptime > 0
    ? `${Math.floor(uptime / 3600)}h ${Math.floor((uptime % 3600) / 60)}m ${uptime % 60}s`
    : '—';

  return (
    <>
      {/* Cybersecurity canvas background */}
      <CyberBackground />

      {/* Content sits above canvas */}
      <div style={{ position: 'relative', zIndex: 1 }}>

        {/* Section header */}
        <div className="section-header" style={{ marginBottom: '1.25rem' }}>
          <h2>OPERATIONS OVERVIEW</h2>
          <div className="section-divider" />
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <div className={`topbar-pill ${mode === 'demo' ? 'demo' : 'live'}`} style={{ padding: '0.15rem 0.5rem', fontSize: '0.58rem' }}>
              <Radio size={8} /> {mode === 'demo' ? 'DEMO MODE' : 'LIVE CAPTURE'}
            </div>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.6rem', color: 'var(--txt-dim)' }}>
              UP {uptimeStr}
            </span>
          </div>
        </div>

        {/* ── Stats Row ── */}
        <div className="stats-grid" style={{ marginBottom: '1.25rem' }}>
          <StatCard label="Packets Captured" value={stats.packets_captured?.toLocaleString() || '0'} icon={Wifi}          color="cyan"   sub="raw network packets" />
          <StatCard label="Flows Analyzed"   value={stats.flows_analyzed?.toLocaleString()   || '0'} icon={Activity}       color="blue"   sub="bidirectional flows" />
          <StatCard label="Threats Detected" value={stats.threats_detected?.toLocaleString() || '0'} icon={AlertTriangle}  color="red"    sub="by ML pipeline" />
          <StatCard label="IPs Blocked"      value={stats.blocked_ips?.toLocaleString()      || '0'} icon={Shield}         color="orange" sub="auto-response engine" />
          <StatCard label="Avg Confidence"   value={stats.avg_confidence ? `${(stats.avg_confidence * 100).toFixed(0)}%` : '—'} icon={Cpu} color="purple" sub="classification score" />
          <StatCard label="ML Models"        value={Object.values(models).filter(Boolean).length || '5'} icon={Brain}      color="green"  sub="active & trained" />
        </div>

        {/* ── Live Pipeline Data-Flow ── */}
        <div className="card" style={{ marginBottom: '1.25rem' }}>
          <div className="card-header">
            <div className="card-title">
              <Radio size={13} color="var(--phos-100)" />
              <span className="card-title-accent">LIVE</span>
              <span>9-STEP AI DETECTION PIPELINE — REAL-TIME DATA FLOW</span>
            </div>
            <div className="live-indicator">
              <div className="live-dot" />
              STREAMING
            </div>
          </div>
          <PipelineDataFlow steps={PIPELINE_STEPS} />
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.58rem', color: 'var(--txt-dim)', textAlign: 'center', marginTop: '0.5rem', letterSpacing: '0.06em' }}>
            EACH PACKET TRAVERSES ALL 8 STAGES IN &lt;50MS · ANIMATED IN REAL-TIME
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>

          {/* ── ML Model Status ── */}
          <div className="card">
            <div className="card-header">
              <div className="card-title"><Cpu size={13} color="var(--phos-100)" />ML MODEL STATUS</div>
              <div className="status-tag ok">
                <div className="live-dot" style={{ width: 5, height: 5 }} />
                {Object.values(models).filter(Boolean).length}/5 ACTIVE
              </div>
            </div>
            {MODEL_STATUS.map((m, i) => {
              const active = m.key ? (models[m.key] === true) : true;
              return (
                <div key={i} style={{
                  display: 'grid', gridTemplateColumns: '1fr auto auto',
                  alignItems: 'center', gap: '0.75rem',
                  padding: '0.5rem 0',
                  borderBottom: i < MODEL_STATUS.length - 1 ? '1px solid var(--border-dim)' : 'none',
                }}>
                  <div>
                    <div style={{ fontFamily: 'var(--font-ui)', fontWeight: 700, fontSize: '0.78rem', color: 'var(--txt-bright)' }}>{m.name}</div>
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.57rem', color: 'var(--txt-dim)', marginTop: 1 }}>{m.role}</div>
                  </div>
                  {m.accuracy !== '—' && (
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--phos-100)' }}>{m.accuracy}</div>
                  )}
                  <div style={{
                    padding: '2px 7px', borderRadius: '3px',
                    fontFamily: 'var(--font-mono)', fontSize: '0.55rem', letterSpacing: '0.08em',
                    background: active ? 'rgba(0,255,136,0.08)' : 'rgba(255,106,0,0.08)',
                    color: active ? 'var(--phos-100)' : 'var(--threat-high)',
                    border: `1px solid ${active ? 'rgba(0,255,136,0.2)' : 'rgba(255,106,0,0.2)'}`,
                    transition: 'all 0.3s',
                  }}>
                    {active ? 'ACTIVE' : 'OFFLINE'}
                  </div>
                </div>
              );
            })}
          </div>

          {/* ── Attack Simulator ── */}
          <div className="card">
            <div className="card-header">
              <div className="card-title"><Zap size={13} color="var(--threat-critical)" />ATTACK SIMULATOR</div>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.57rem', color: 'var(--txt-dim)' }}>INJECT → DETECT → BLOCK</span>
            </div>

            <div style={{
              fontFamily: 'var(--font-mono)', fontSize: '0.6rem',
              color: 'var(--txt-dim)', background: 'rgba(0,0,0,0.3)',
              border: '1px solid var(--border-dim)', borderRadius: '4px',
              padding: '0.5rem 0.7rem', lineHeight: 1.7, marginBottom: '0.875rem',
            }}>
              {'>'} Injects synthetic attack flows into the live pipeline<br />
              {'>'} Watch the pipeline animation above react in real-time<br />
              {'>'} Blocked IPs appear in Block Engine within seconds
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
              {SIM_ATTACKS.map(({ type, label, icon, color }) => (
                <button
                  key={type}
                  className="btn"
                  disabled={simulating !== null}
                  onClick={() => handleSim(type)}
                  style={{
                    justifyContent: 'flex-start',
                    background: simulating === type ? `${color}15` : 'rgba(6,15,26,0.7)',
                    border: `1px solid ${simulating === type ? color : 'var(--border-dim)'}`,
                    color: simulating === type ? color : 'var(--txt-mid)',
                    padding: '0.55rem 0.75rem',
                    fontSize: '0.72rem',
                    transition: 'all 0.2s ease',
                    opacity: simulating !== null && simulating !== type ? 0.5 : 1,
                  }}
                >
                  <span style={{ fontSize: '1rem' }}>{icon}</span>
                  <div>
                    <div style={{ fontWeight: 700, letterSpacing: '0.06em' }}>{label}</div>
                    <div style={{ fontSize: '0.56rem', fontFamily: 'var(--font-mono)', opacity: 0.7, marginTop: 1 }}>
                      {simulating === type ? 'INJECTING...' : 'LAUNCH'}
                    </div>
                  </div>
                </button>
              ))}
            </div>

            {simMsg && (
              <div style={{
                marginTop: '0.75rem', padding: '0.5rem 0.7rem', borderRadius: '4px',
                fontFamily: 'var(--font-mono)', fontSize: '0.62rem', letterSpacing: '0.03em',
                background: simMsg.ok ? 'rgba(0,255,136,0.07)' : 'rgba(255,32,32,0.07)',
                border: `1px solid ${simMsg.ok ? 'rgba(0,255,136,0.2)' : 'rgba(255,32,32,0.25)'}`,
                color: simMsg.ok ? 'var(--phos-100)' : 'var(--threat-critical)',
                animation: 'slideInRight 0.2s ease',
              }}>
                {'>'} {simMsg.text}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Keyframes injected inline */}
      <style>{`
        @keyframes sweep {
          from { transform: translateX(-50%); }
          to   { transform: translateX(50%); }
        }
        @keyframes packet-cross {
          from { left: 0; opacity: 1; }
          to   { left: 100%; opacity: 0; }
        }
      `}</style>
    </>
  );
}
