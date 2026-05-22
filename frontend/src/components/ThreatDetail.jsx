/**
 * ThreatDetail — Expandable threat detail modal
 * Shows: SHAP bar chart, MITRE ATT&CK badge, LLM report, severity gauge
 */
import { useState, useEffect } from 'react';
import { X, ExternalLink, BarChart2, Shield, MessageSquare, TrendingUp } from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
} from 'recharts';

function SeverityGauge({ score = 0, color = '#94a3b8', level = 'LOW' }) {
  const radius = 60;
  const circumference = Math.PI * radius;
  const progress = (score / 100) * circumference;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.5rem' }}>
      <svg width="140" height="80" viewBox="0 0 140 80">
        {/* Background arc */}
        <path
          d="M 10 70 A 60 60 0 0 1 130 70"
          fill="none"
          stroke="rgba(255,255,255,0.08)"
          strokeWidth="10"
          strokeLinecap="round"
        />
        {/* Progress arc */}
        <path
          d="M 10 70 A 60 60 0 0 1 130 70"
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={`${progress} ${circumference}`}
          style={{ transition: 'stroke-dasharray 0.8s ease' }}
        />
        {/* Score text */}
        <text x="70" y="65" textAnchor="middle" fill={color} fontSize="22" fontWeight="700" fontFamily="monospace">
          {score.toFixed(0)}
        </text>
        <text x="70" y="78" textAnchor="middle" fill="#64748b" fontSize="9" fontFamily="monospace">
          /100
        </text>
      </svg>
      <span style={{
        fontSize: '0.875rem',
        fontWeight: 700,
        color,
        letterSpacing: '0.05em',
        padding: '2px 10px',
        borderRadius: 4,
        background: `${color}18`,
      }}>
        {level}
      </span>
    </div>
  );
}

const CustomTooltip = ({ active, payload }) => {
  if (active && payload?.length) {
    const d = payload[0].payload;
    return (
      <div style={{
        background: 'var(--card-bg)',
        border: '1px solid var(--border-color)',
        borderRadius: 8,
        padding: '0.75rem',
        fontSize: '0.8rem',
      }}>
        <div style={{ color: 'var(--text-primary)', fontWeight: 600, marginBottom: '0.25rem' }}>
          {d.human_label}
        </div>
        <div style={{ color: d.direction === '+' ? '#10b981' : '#ef4444' }}>
          {d.direction}{(d.contribution * 100).toFixed(3)}
        </div>
      </div>
    );
  }
  return null;
};

export default function ThreatDetail({ threat, onClose }) {
  if (!threat) return null;

  const shap = threat.shap_features || [];
  const mitre = threat.mitre || {};
  const severity = threat.severity || {};
  const factors = severity.factors || [];
  const responseAction = threat.response_action || {};

  const shapData = shap.map(f => ({
    ...f,
    display_label: f.human_label || f.feature,
    bar_value: parseFloat((f.abs_contribution || f.contribution || 0).toFixed(5)),
  }));

  const severityColor = severity.color || '#94a3b8';

  return (
    <div
      id="threat-detail-overlay"
      style={{
        position: 'fixed', inset: 0,
        background: 'rgba(0,0,0,0.75)',
        backdropFilter: 'blur(6px)',
        zIndex: 1000,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '1rem',
      }}
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div
        style={{
          background: 'var(--sidebar-bg)',
          border: '1px solid var(--border-color)',
          borderRadius: 16,
          width: '100%',
          maxWidth: 860,
          maxHeight: '90vh',
          overflowY: 'auto',
          padding: '2rem',
          position: 'relative',
        }}
      >
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.5rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.4rem' }}>
              <span style={{
                padding: '3px 10px',
                borderRadius: 6,
                fontSize: '0.8rem',
                fontWeight: 700,
                background: `${severityColor}22`,
                color: severityColor,
              }}>
                {severity.level || 'UNKNOWN'}
              </span>
              <span style={{
                padding: '3px 10px',
                borderRadius: 6,
                fontSize: '0.8rem',
                fontWeight: 700,
                background: responseAction.action === 'BLOCKED'
                  ? 'rgba(239,68,68,0.15)' : 'rgba(245,158,11,0.12)',
                color: responseAction.action === 'BLOCKED' ? '#ef4444' : '#f59e0b',
              }}>
                {responseAction.action || 'MONITORED'}
              </span>
            </div>
            <h3 style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
              {(threat.prediction || threat.attack_type || 'Unknown').toUpperCase()} — {threat.source_ip || 'Unknown IP'}
            </h3>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '0.25rem', margin: 0 }}>
              Confidence: {((threat.confidence || 0) * 100).toFixed(1)}% ·
              {threat.timestamp ? ` Detected: ${new Date(threat.timestamp).toLocaleTimeString()}` : ''}
            </p>
          </div>
          <button
            onClick={onClose}
            style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: 4 }}
          >
            <X size={20} />
          </button>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
          {/* Left column */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>

            {/* SHAP Chart */}
            {shapData.length > 0 && (
              <div className="card" style={{ padding: '1.25rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
                  <BarChart2 size={16} color="var(--accent-cyan)" />
                  <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    SHAP — Why it was flagged
                  </span>
                </div>
                <ResponsiveContainer width="100%" height={200}>
                  <BarChart data={shapData} layout="vertical" margin={{ left: 10, right: 10, top: 0, bottom: 0 }}>
                    <XAxis type="number" domain={[0, 'dataMax']} tick={{ fontSize: 10, fill: '#64748b' }} axisLine={false} tickLine={false} />
                    <YAxis type="category" dataKey="display_label" width={110} tick={{ fontSize: 10, fill: '#94a3b8' }} axisLine={false} tickLine={false} />
                    <Tooltip content={<CustomTooltip />} />
                    <Bar dataKey="bar_value" radius={[0, 4, 4, 0]}>
                      {shapData.map((entry, i) => (
                        <Cell key={i} fill={entry.direction === '+' ? '#10b981' : '#ef4444'} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}

            {/* LLM Report */}
            {threat.llm_report && (
              <div className="card" style={{ padding: '1.25rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
                  <MessageSquare size={16} color="var(--accent-cyan)" />
                  <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    AI Analyst Report
                  </span>
                </div>
                <p style={{
                  fontSize: '0.825rem',
                  color: 'var(--text-secondary)',
                  lineHeight: 1.7,
                  borderLeft: '3px solid var(--accent-cyan)',
                  paddingLeft: '0.75rem',
                  margin: 0,
                }}>
                  {threat.llm_report}
                </p>
              </div>
            )}
          </div>

          {/* Right column */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>

            {/* Severity Gauge */}
            <div className="card" style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem', alignSelf: 'flex-start' }}>
                <TrendingUp size={16} color="var(--accent-cyan)" />
                <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  Severity Score
                </span>
              </div>
              <SeverityGauge
                score={severity.score || 0}
                color={severityColor}
                level={severity.level || 'LOW'}
              />
              {factors.length > 0 && (
                <div style={{ width: '100%', marginTop: '1rem' }}>
                  {factors.map((f, i) => (
                    <div key={i} style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      padding: '0.35rem 0',
                      borderBottom: i < factors.length - 1 ? '1px solid var(--border-color)' : 'none',
                      fontSize: '0.775rem',
                    }}>
                      <span style={{ color: 'var(--text-muted)' }}>{f.name}</span>
                      <span style={{ color: 'var(--text-secondary)', fontWeight: 600 }}>+{(f.contribution || 0).toFixed(1)} pts</span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* MITRE ATT&CK */}
            {mitre.technique_id && (
              <div className="card" style={{ padding: '1.25rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
                  <Shield size={16} color="var(--accent-cyan)" />
                  <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    MITRE ATT&CK
                  </span>
                </div>

                <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '0.75rem' }}>
                  <span style={{
                    padding: '4px 10px',
                    borderRadius: 6,
                    background: 'rgba(56,189,248,0.12)',
                    color: 'var(--accent-cyan)',
                    fontSize: '0.875rem',
                    fontWeight: 700,
                    fontFamily: 'monospace',
                  }}>
                    {mitre.technique_id}
                  </span>
                  <span style={{
                    padding: '4px 10px',
                    borderRadius: 6,
                    background: 'rgba(139,92,246,0.12)',
                    color: '#a78bfa',
                    fontSize: '0.8rem',
                    fontWeight: 600,
                  }}>
                    {mitre.tactic}
                  </span>
                </div>

                <div style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.5rem' }}>
                  {mitre.technique_name}
                </div>

                {mitre.description && (
                  <p style={{ fontSize: '0.775rem', color: 'var(--text-muted)', lineHeight: 1.6, margin: '0 0 0.75rem' }}>
                    {mitre.description}
                  </p>
                )}

                {mitre.reference_url && (
                  <a
                    href={mitre.reference_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '0.25rem',
                      fontSize: '0.75rem',
                      color: 'var(--accent-cyan)',
                      textDecoration: 'none',
                    }}
                  >
                    View on MITRE ATT&CK <ExternalLink size={12} />
                  </a>
                )}
              </div>
            )}

            {/* Recommended Action */}
            {(threat.recommended_action || threat.severity?.recommended_action) && (
              <div className="card" style={{ padding: '1.25rem', borderColor: severityColor }}>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.5rem' }}>
                  Recommended Action
                </div>
                <p style={{ fontSize: '0.825rem', color: 'var(--text-secondary)', lineHeight: 1.6, margin: 0 }}>
                  {threat.recommended_action || threat.severity?.recommended_action}
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
