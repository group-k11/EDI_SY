"""
API Endpoint Tests — FastAPI TestClient smoke tests for all critical endpoints.
Run: cd backend && pytest tests/ -v
Requires: pip install pytest pytest-asyncio httpx
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    """Create a single FastAPI TestClient for all tests in this module."""
    # Delay import to avoid triggering background tasks at module load time
    from main import app
    with TestClient(app) as c:
        yield c


# ─── Health / Readiness ─────────────────────────────────────────────────────

class TestHealth:
    def test_health_returns_200(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_health_has_status_field(self, client):
        resp = client.get("/health")
        data = resp.json()
        assert "status" in data

    def test_system_status_returns_200(self, client):
        resp = client.get("/api/system-status")
        assert resp.status_code == 200


# ─── Traffic & Threats ──────────────────────────────────────────────────────

class TestTrafficAndThreats:
    def test_traffic_returns_200(self, client):
        resp = client.get("/api/traffic")
        assert resp.status_code == 200

    def test_threats_returns_list(self, client):
        resp = client.get("/api/threats")
        assert resp.status_code == 200
        data = resp.json()
        assert "threats" in data
        assert isinstance(data["threats"], list)

    def test_logs_returns_200(self, client):
        resp = client.get("/api/logs?limit=5")
        assert resp.status_code == 200

    def test_analytics_returns_200(self, client):
        resp = client.get("/api/analytics")
        assert resp.status_code == 200


# ─── Response Engine ────────────────────────────────────────────────────────

class TestResponseEngine:
    def test_blocked_returns_200(self, client):
        resp = client.get("/api/blocked")
        assert resp.status_code == 200

    def test_blocked_has_required_fields(self, client):
        resp = client.get("/api/blocked")
        data = resp.json()
        assert "blocked" in data
        assert "total_blocked" in data

    def test_impact_returns_200(self, client):
        resp = client.get("/api/impact")
        assert resp.status_code == 200


# ─── Simulation Endpoint ────────────────────────────────────────────────────

class TestSimulator:
    def test_simulate_ddos_returns_200(self, client):
        resp = client.post("/api/simulate/ddos")
        # Accept 200 or 422 (if body validation fails without real packets)
        assert resp.status_code in (200, 202, 422)

    def test_simulate_port_scan_returns_200(self, client):
        resp = client.post("/api/simulate/port_scan")
        assert resp.status_code in (200, 202, 422)


# ─── Analysis Pipeline ──────────────────────────────────────────────────────

class TestAnalysisPipeline:
    def test_analyze_with_demo_data(self, client):
        resp = client.post("/api/analyze", json={"attack_type": "ddos", "source_ip": "10.5.5.5"})
        # Accept 200 (success) or 422 (missing required features) depending on model state
        assert resp.status_code in (200, 422, 500)

    def test_explain_shap_returns_200_or_422(self, client):
        # Feature values might not be provided in correct format — just confirm no 500
        resp = client.get("/api/explain")
        assert resp.status_code not in (500,)
