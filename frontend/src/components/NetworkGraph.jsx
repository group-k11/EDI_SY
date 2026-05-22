import { useState, useEffect, useRef, useCallback } from 'react';
import { GitBranch } from 'lucide-react';
import { fetchNetworkMap } from '../services/api';

const roleColors = {
  attacker: '#ef4444',
  target: '#3b82f6',
  both: '#f59e0b',
};

const severityEdgeColors = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#f59e0b',
  low: '#3b82f6',
};

export default function NetworkGraph() {
  const canvasRef = useRef(null);
  const [graphData, setGraphData] = useState({ nodes: [], edges: [] });
  const [hoveredNode, setHoveredNode] = useState(null);
  const animRef = useRef(null);
  const nodePositions = useRef({});

  const loadData = useCallback(async () => {
    try {
      const data = await fetchNetworkMap();
      setGraphData(data);
    } catch (e) { console.error(e); }
  }, []);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 8000);
    return () => clearInterval(interval);
  }, [loadData]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * window.devicePixelRatio;
    canvas.height = rect.height * window.devicePixelRatio;
    ctx.scale(window.devicePixelRatio, window.devicePixelRatio);

    const W = rect.width;
    const H = rect.height;

    const { nodes, edges } = graphData;
    if (nodes.length === 0) {
      ctx.clearRect(0, 0, W, H);
      ctx.fillStyle = '#64748b';
      ctx.font = '14px Inter, sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText('No network connections yet', W / 2, H / 2 - 10);
      ctx.font = '12px Inter, sans-serif';
      ctx.fillText('Run a simulation to see attack graphs', W / 2, H / 2 + 10);
      return;
    }

    // Initialize positions if new nodes appear
    const cx = W / 2;
    const cy = H / 2;
    nodes.forEach((n, i) => {
      if (!nodePositions.current[n.id]) {
        const angle = (2 * Math.PI * i) / nodes.length;
        const radius = Math.min(W, H) * 0.32;
        nodePositions.current[n.id] = {
          x: cx + radius * Math.cos(angle) + (Math.random() - 0.5) * 40,
          y: cy + radius * Math.sin(angle) + (Math.random() - 0.5) * 40,
          vx: 0, vy: 0,
        };
      }
    });

    let frame = 0;

    const draw = () => {
      frame++;
      ctx.clearRect(0, 0, W, H);

      // Simple force simulation step
      const positions = nodePositions.current;
      nodes.forEach(n1 => {
        nodes.forEach(n2 => {
          if (n1.id === n2.id) return;
          const p1 = positions[n1.id];
          const p2 = positions[n2.id];
          if (!p1 || !p2) return;
          const dx = p2.x - p1.x;
          const dy = p2.y - p1.y;
          const dist = Math.sqrt(dx * dx + dy * dy) || 1;
          const repulse = -200 / (dist * dist);
          p1.vx += (dx / dist) * repulse * 0.1;
          p1.vy += (dy / dist) * repulse * 0.1;
        });
        // Center gravity
        const p = positions[n1.id];
        if (p) {
          p.vx += (cx - p.x) * 0.001;
          p.vy += (cy - p.y) * 0.001;
        }
      });

      // Edge attraction
      edges.forEach(e => {
        const p1 = positions[e.source];
        const p2 = positions[e.target];
        if (!p1 || !p2) return;
        const dx = p2.x - p1.x;
        const dy = p2.y - p1.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const attract = (dist - 120) * 0.005;
        p1.vx += (dx / dist) * attract;
        p1.vy += (dy / dist) * attract;
        p2.vx -= (dx / dist) * attract;
        p2.vy -= (dy / dist) * attract;
      });

      // Update positions with damping
      nodes.forEach(n => {
        const p = positions[n.id];
        if (!p) return;
        p.vx *= 0.85;
        p.vy *= 0.85;
        p.x += p.vx;
        p.y += p.vy;
        p.x = Math.max(30, Math.min(W - 30, p.x));
        p.y = Math.max(30, Math.min(H - 30, p.y));
      });

      // Draw edges
      edges.forEach(e => {
        const p1 = positions[e.source];
        const p2 = positions[e.target];
        if (!p1 || !p2) return;

        const color = severityEdgeColors[e.severity] || '#3b82f6';

        ctx.beginPath();
        ctx.moveTo(p1.x, p1.y);
        ctx.lineTo(p2.x, p2.y);
        ctx.strokeStyle = color;
        ctx.lineWidth = Math.min(e.count || 1, 4);
        ctx.globalAlpha = 0.5 + Math.sin(frame * 0.02) * 0.15;
        ctx.stroke();
        ctx.globalAlpha = 1;

        // Arrow
        const angle = Math.atan2(p2.y - p1.y, p2.x - p1.x);
        const mx = (p1.x + p2.x) / 2;
        const my = (p1.y + p2.y) / 2;
        ctx.beginPath();
        ctx.moveTo(mx + 8 * Math.cos(angle), my + 8 * Math.sin(angle));
        ctx.lineTo(mx - 5 * Math.cos(angle - 0.4), my - 5 * Math.sin(angle - 0.4));
        ctx.lineTo(mx - 5 * Math.cos(angle + 0.4), my - 5 * Math.sin(angle + 0.4));
        ctx.closePath();
        ctx.fillStyle = color;
        ctx.fill();
      });

      // Draw nodes
      nodes.forEach(n => {
        const p = positions[n.id];
        if (!p) return;
        const color = roleColors[n.role] || '#6b7280';
        const isHovered = hoveredNode === n.id;
        const radius = isHovered ? 14 : 10;

        // Glow
        ctx.beginPath();
        ctx.arc(p.x, p.y, radius + 4, 0, 2 * Math.PI);
        ctx.fillStyle = color + '30';
        ctx.fill();

        // Node
        ctx.beginPath();
        ctx.arc(p.x, p.y, radius, 0, 2 * Math.PI);
        ctx.fillStyle = color;
        ctx.fill();
        ctx.strokeStyle = '#1a1f2e';
        ctx.lineWidth = 2;
        ctx.stroke();

        // Label
        ctx.font = '10px monospace';
        ctx.fillStyle = '#e2e8f0';
        ctx.textAlign = 'center';
        ctx.fillText(n.id, p.x, p.y + radius + 14);
      });

      // Legend
      ctx.font = '11px Inter, sans-serif';
      const legendY = 20;
      [
        { color: '#ef4444', label: '● Attacker' },
        { color: '#3b82f6', label: '● Target' },
        { color: '#f59e0b', label: '● Both' },
      ].forEach(({ color, label }, i) => {
        ctx.fillStyle = color;
        ctx.textAlign = 'left';
        ctx.fillText(label, 10, legendY + i * 18);
      });

      animRef.current = requestAnimationFrame(draw);
    };

    draw();

    // Mouse hover
    const handleMove = (e) => {
      const r = canvas.getBoundingClientRect();
      const mx = e.clientX - r.left;
      const my = e.clientY - r.top;
      let found = null;
      graphData.nodes.forEach(n => {
        const p = nodePositions.current[n.id];
        if (!p) return;
        const dist = Math.sqrt((mx - p.x) ** 2 + (my - p.y) ** 2);
        if (dist < 15) found = n.id;
      });
      setHoveredNode(found);
      canvas.style.cursor = found ? 'pointer' : 'default';
    };
    canvas.addEventListener('mousemove', handleMove);

    return () => {
      if (animRef.current) cancelAnimationFrame(animRef.current);
      canvas.removeEventListener('mousemove', handleMove);
    };
  }, [graphData, hoveredNode]);

  return (
    <div className="card">
      <div className="card-header">
        <div className="card-title">
          <GitBranch size={16} style={{ color: 'var(--accent-green)' }} />
          Network Attack Map
        </div>
        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
          {graphData.nodes.length} nodes · {graphData.edges.length} connections
        </span>
      </div>
      <canvas
        ref={canvasRef}
        style={{
          width: '100%',
          height: '350px',
          borderRadius: '8px',
          background: 'var(--bg-primary)',
          border: '1px solid var(--border-color)',
        }}
      />
    </div>
  );
}
