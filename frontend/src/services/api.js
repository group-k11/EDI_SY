/**
 * API Service — Axios HTTP client + WebSocket manager
 * Handles all communication with the FastAPI backend
 */

import axios from 'axios';

const API_BASE = '/api';
const WS_BASE = `ws://${window.location.hostname}:8000/api/ws`;

// ─── HTTP Client ──────────────────────────────────────────────────

const api = axios.create({
  baseURL: API_BASE,
  timeout: 10000,
  headers: { 'Content-Type': 'application/json' },
});

export const fetchTraffic = () => api.get('/traffic').then(r => r.data);
export const fetchThreats = () => api.get('/threats').then(r => r.data);
export const fetchLogs = (limit = 100, attackType = null) => {
  const params = { limit };
  if (attackType) params.attack_type = attackType;
  return api.get('/logs', { params }).then(r => r.data);
};
export const fetchNetworkMap = () => api.get('/network-map').then(r => r.data);
export const fetchSystemStatus = () => api.get('/system-status').then(r => r.data);
export const runSimulation = (attackType) => api.post(`/simulate/${attackType}`).then(r => r.data);

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
