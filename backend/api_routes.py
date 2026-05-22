"""
API Routes — FastAPI REST + WebSocket endpoints for the IDS platform.
"""

import asyncio
import json
from datetime import datetime
from typing import Dict, List, Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, Body

from database import (
    add_ip_list_entry,
    delete_ip_list_entry,
    get_ip_intel,
    get_ip_list_summary,
    get_network_map,
    get_threat_summary,
    get_threats,
    list_ip_list,
)
from attack_simulator import SIMULATION_MAP

router = APIRouter(prefix="/api")

# References to global engine instances (set by main.py)
_packet_capture = None
_flow_builder = None
_feature_engine = None
_ml_engine = None
_threat_engine = None
_drift_monitor = None
_threat_intel = None


def init_routes(packet_capture, flow_builder, feature_engine, ml_engine, threat_engine, drift_monitor, threat_intel):
    """Initialize route handlers with engine references."""
    global _packet_capture, _flow_builder, _feature_engine, _ml_engine, _threat_engine, _drift_monitor, _threat_intel
    _packet_capture = packet_capture
    _flow_builder = flow_builder
    _feature_engine = feature_engine
    _ml_engine = ml_engine
    _threat_engine = threat_engine
    _drift_monitor = drift_monitor
    _threat_intel = threat_intel


# ─── REST Endpoints ────────────────────────────────────────────────

@router.get("/traffic")
async def get_traffic():
    """Return current network traffic statistics."""
    capture_stats = _packet_capture.get_stats() if _packet_capture else {}
    flow_stats = _flow_builder.get_stats() if _flow_builder else {}
    recent_packets = _packet_capture.get_packets(50) if _packet_capture else []

    return {
        "capture": capture_stats,
        "flows": flow_stats,
        "recent_packets": recent_packets,
        "timestamp": datetime.now().isoformat(),
    }


@router.get("/threats")
async def get_active_threats():
    """Return currently detected threats."""
    threats = _threat_engine.get_recent_threats(50) if _threat_engine else []
    return {
        "threats": threats,
        "count": len(threats),
        "timestamp": datetime.now().isoformat(),
    }


@router.get("/logs")
async def get_attack_logs(
    limit: int = Query(100, ge=1, le=1000),
    attack_type: Optional[str] = None,
):
    """Return historical attack logs from database."""
    logs = await get_threats(limit=limit, attack_type=attack_type)
    summary = await get_threat_summary()
    return {
        "logs": logs,
        "summary": summary,
        "timestamp": datetime.now().isoformat(),
    }


@router.get("/network-map")
async def get_network_map_data():
    """Return attacker-target relationships for graph visualization."""
    connections = await get_network_map()

    nodes = set()
    edges = []
    for conn in connections:
        src = conn["source_ip"]
        tgt = conn["target_ip"]
        nodes.add(src)
        nodes.add(tgt)
        edges.append({
            "source": src,
            "target": tgt,
            "attack_type": conn["attack_type"],
            "severity": conn.get("severity", "medium"),
            "count": conn["connection_count"],
            "confidence": round(conn.get("avg_confidence", 0), 4),
        })

    node_list = []
    for n in nodes:
        is_attacker = any(e["source"] == n for e in edges)
        is_target = any(e["target"] == n for e in edges)
        role = "attacker" if is_attacker and not is_target else "target" if is_target else "both"
        node_list.append({"id": n, "role": role})

    return {
        "nodes": node_list,
        "edges": edges,
        "timestamp": datetime.now().isoformat(),
    }


@router.get("/system-status")
async def get_system_status():
    """Return system health and component status."""
    intel_summary = await get_ip_list_summary()
    return {
        "capture": _packet_capture.get_stats() if _packet_capture else {},
        "flows": _flow_builder.get_stats() if _flow_builder else {},
        "ml_engine": _ml_engine.get_status() if _ml_engine else {},
        "threats": _threat_engine.get_stats() if _threat_engine else {},
        "drift": _drift_monitor.get_status() if _drift_monitor else {},
        "intel": {
            **intel_summary,
            **(_threat_intel.get_stats() if _threat_intel else {}),
        },
        "timestamp": datetime.now().isoformat(),
        "status": "operational",
    }


@router.get("/drift")
async def get_drift_status():
    """Return current feature drift status."""
    return {
        "drift": _drift_monitor.get_status() if _drift_monitor else {},
        "timestamp": datetime.now().isoformat(),
    }


@router.get("/ip-intel/{ip_value}")
async def get_ip_intel_status(ip_value: str, refresh: bool = Query(False)):
    """Return IP enrichment and reputation details."""
    intel = None
    if refresh and _threat_intel:
        intel = await _threat_intel.enrich_ip(ip_value)
    if not intel:
        intel = await get_ip_intel(ip_value)

    list_status = _threat_intel.check_ip(ip_value) if _threat_intel else {"status": "unknown"}
    return {
        "ip": ip_value,
        "intel": intel,
        "list_status": list_status,
        "timestamp": datetime.now().isoformat(),
    }


@router.get("/ip-list")
async def get_ip_list(list_type: str = Query("blocklist"), limit: int = Query(200, ge=1, le=5000), search: Optional[str] = None):
    """Return blocklist or allowlist entries."""
    items = await list_ip_list(list_type, limit=limit, search=search)
    return {
        "list_type": list_type,
        "items": items,
        "count": len(items),
        "timestamp": datetime.now().isoformat(),
    }


@router.post("/ip-list")
async def add_ip_list(payload: Dict = Body(...)):
    """Add an entry to blocklist/allowlist."""
    entry_id = await add_ip_list_entry(payload)
    if _threat_intel:
        await _threat_intel.refresh_from_db()
    return {
        "status": "ok",
        "id": entry_id,
        "timestamp": datetime.now().isoformat(),
    }


@router.delete("/ip-list/{entry_id}")
async def delete_ip_list(entry_id: int):
    """Delete an entry from blocklist/allowlist."""
    await delete_ip_list_entry(entry_id)
    if _threat_intel:
        await _threat_intel.refresh_from_db()
    return {
        "status": "ok",
        "timestamp": datetime.now().isoformat(),
    }


@router.post("/intel/refresh-feeds")
async def refresh_intel_feeds():
    """Manually refresh reputation feeds."""
    if not _threat_intel:
        return {"status": "error", "error": "intel_unavailable"}
    result = await _threat_intel.refresh_feeds()
    return {
        "status": "ok",
        "result": result,
        "timestamp": datetime.now().isoformat(),
    }


@router.post("/simulate/{attack_type}")
async def run_simulation(attack_type: str):
    """Run an attack simulation for demo/testing."""
    if attack_type not in SIMULATION_MAP:
        return {"error": f"Unknown attack type: {attack_type}", "available": list(SIMULATION_MAP.keys())}

    sim_func = SIMULATION_MAP[attack_type]
    packets = sim_func()

    # Inject into capture pipeline
    if _packet_capture:
        for pkt in packets:
            _packet_capture.inject_packet(pkt)

    return {
        "status": "simulation_started",
        "attack_type": attack_type,
        "packets_injected": len(packets),
        "timestamp": datetime.now().isoformat(),
    }


@router.post("/retrain")
async def retrain_models(mode: str = "hybrid"):
    """
    Retrain ML models on dataset.
    Modes: 'synthetic', 'real', 'hybrid'
    """
    if not _ml_engine:
        return {"error": "ML engine not available"}
    
    try:
        if mode == "hybrid":
            success = _ml_engine.train_hybrid()
            method = "hybrid (synthetic + CICIDS2017)"
        elif mode == "real":
            csv_dir = "MachineLearningCSV/MachineLearningCVE"
            success = _ml_engine.train_on_cicids2017(csv_dir)
            method = "CICIDS2017 dataset"
        else:
            _ml_engine._train()
            success = True
            method = "synthetic data"
        
        return {
            "status": "success" if success else "partial",
            "method": method,
            "accuracy": getattr(_ml_engine, "last_accuracy", 0.0),
            "models_trained": _ml_engine.is_trained,
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "timestamp": datetime.now().isoformat(),
        }


# ─── WebSocket ─────────────────────────────────────────────────────

class ConnectionManager:
    """Manage active WebSocket connections."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, data: dict):
        dead = []
        for connection in self.active_connections:
            try:
                await connection.send_json(data)
            except Exception:
                dead.append(connection)
        for conn in dead:
            self.disconnect(conn)


ws_manager = ConnectionManager()


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time data streaming."""
    await ws_manager.connect(websocket)
    try:
        while True:
            # Send periodic updates
            data = {
                "type": "update",
                "traffic": {
                    "capture": _packet_capture.get_stats() if _packet_capture else {},
                    "flows": _flow_builder.get_stats() if _flow_builder else {},
                    "recent_packets": _packet_capture.get_packets(20) if _packet_capture else [],
                },
                "threats": _threat_engine.get_recent_threats(10) if _threat_engine else [],
                "timestamp": datetime.now().isoformat(),
            }
            await websocket.send_json(data)
            await asyncio.sleep(2)  # Update every 2 seconds
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)
