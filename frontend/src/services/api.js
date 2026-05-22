/**
 * API Service — Axios HTTP client + WebSocket manager
 * Handles all communication with the FastAPI backend
 */

import axios from 'axios';

const API_BASE = '/api';
// Dynamically derive WS port — works for both dev (5173→8000) and production
const WS_PORT = window.location.hostname === 'localhost' ? '8000' : window.location.port;
const WS_BASE = `ws://${window.location.hostname}:${WS_PORT}/api/ws`;

// ─── HTTP Client ──────────────────────────────────────────────────

const api = axios.create({
  baseURL: API_BASE,
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
});

// ─── Existing Endpoints ───────────────────────────────────────────

export const fetchTraffic = () => api.get('/traffic').then(r => r.data);
export const fetchThreats = () => api.get('/threats').then(r => r.data);
export const fetchLogs = (limit = 100, attackType = null) => {
  const params = { limit };
  if (attackType) params.attack_type = attackType;
  return api.get('/logs', { params }).then(r => r.data);
};
export const fetchNetworkMap = () => api.get('/network-map').then(r => r.data);
export const fetchSystemStatus = () => api.get('/system-status').then(r => r.data);
export const fetchAnalytics = () => api.get('/analytics').then(r => r.data);

// ─── A.I.R.S Core Pipeline ───────────────────────────────────────

/** Run full 9-step A.I.R.S analysis pipeline on a flow/attack payload */
export const analyzeFlow = (payload) => api.post('/analyze', payload).then(r => r.data);

/** Get SHAP explanation for a feature vector */
export const explainFeatures = (payload) => api.post('/explain', payload).then(r => r.data);

// ─── Response Engine ─────────────────────────────────────────────

/** Get all currently blocked + rate-limited IPs */
export const fetchBlocked = () => api.get('/blocked').then(r => r.data);

/** Manually unblock an IP */
export const unblockIP = (ip) => api.delete(`/blocked/${encodeURIComponent(ip)}`).then(r => r.data);

/** Get response engine statistics */
export const fetchResponseStats = () => api.get('/response/stats').then(r => r.data);

/** Get real-world impact metrics */
export const fetchImpact = () => api.get('/impact').then(r => r.data);

// ─── Attack Simulator ────────────────────────────────────────────

/** Start a continuous background simulation */
export const startSimulator = (config) => api.post('/simulate', config).then(r => r.data);

/** Stop a running simulation */
export const stopSimulator = () => api.get('/simulate/stop').then(r => r.data);

/** Run a single one-shot attack simulation by type */
export const runSimulationOneShot = (type) =>
  api.post(`/simulate/${encodeURIComponent(type)}`).then(r => r.data);

// ─── Intelligence & Intel ────────────────────────────────────────

/** Get model drift status */
export const fetchDrift = () => api.get('/drift').then(r => r.data);

/** Get reputation data for a specific IP */
export const fetchIPIntel = (ip) => api.get(`/ip-intel/${encodeURIComponent(ip)}`).then(r => r.data);

/** Get all blocklist/allowlist entries */
export const fetchIPList = () => api.get('/ip-list').then(r => r.data);

/** Add an IP to the blocklist or allowlist */
export const addToIPList = (entry) => api.post('/ip-list', entry).then(r => r.data);

/** Delete an IP list entry by ID */
export const deleteFromIPList = (id) => api.delete(`/ip-list/${id}`).then(r => r.data);

/** Trigger refresh of external threat intelligence feeds */
export const refreshFeeds = () => api.post('/intel/refresh-feeds').then(r => r.data);

/** Trigger model retraining (mode: "synthetic" | "real" | "hybrid") */
export const triggerRetrain = (mode = 'synthetic') =>
  api.post(`/retrain?mode=${mode}`).then(r => r.data);

// ─── WebSocket Manager ────────────────────────────────────────────

class WebSocketManager {
  constructor() {
    this.ws = null;
    this.listeners = new Map();
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 10;
    this.reconnectDelay = 2000;
  }

  connect() {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) return;

    try {
      this.ws = new WebSocket(WS_BASE);

      this.ws.onopen = () => {
        console.log('[WS] Connected');
        this.reconnectAttempts = 0;
      };

      this.ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          this.listeners.forEach((callback) => callback(data));
        } catch (e) {
          console.error('[WS] Parse error:', e);
        }
      };

      this.ws.onclose = () => {
        console.log('[WS] Disconnected');
        this._reconnect();
      };

      this.ws.onerror = (error) => {
        console.error('[WS] Error:', error);
      };
    } catch (e) {
      console.error('[WS] Connection failed:', e);
      this._reconnect();
    }
  }

  _reconnect() {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) return;
    this.reconnectAttempts++;
    setTimeout(() => this.connect(), this.reconnectDelay * this.reconnectAttempts);
  }

  subscribe(id, callback) {
    this.listeners.set(id, callback);
    return () => this.listeners.delete(id);
  }

  disconnect() {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }
}

export const wsManager = new WebSocketManager();
export default api;
