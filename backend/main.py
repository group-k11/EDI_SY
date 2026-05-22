"""
Main Entry Point — FastAPI application with background processing loops.
Starts packet capture, flow analysis, and threat detection pipelines.
"""

import asyncio
import sys
import os
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Ensure backend directory is in path
sys.path.insert(0, os.path.dirname(__file__))

from database import init_db, insert_threat, insert_traffic_stats
from packet_capture import PacketCapture
from flow_builder import FlowBuilder
from feature_engineering import FeatureEngine
from ml_engine import MLEngine
from threat_engine import ThreatEngine
from drift_monitor import DriftMonitor
from threat_intel import ThreatIntel
from api_routes import router, init_routes, ws_manager

# ─── Global Engine Instances ───────────────────────────────────────

packet_capture = PacketCapture()
flow_builder = FlowBuilder(flow_timeout=30.0)
feature_engine = FeatureEngine(window_seconds=30.0)
ml_engine = MLEngine()
threat_engine = ThreatEngine()
drift_monitor = DriftMonitor(window_size=500, baseline_size=500, bins=10)
threat_intel = ThreatIntel()

# Background task flag
_running = False


# ─── Background Processing Loops ──────────────────────────────────

async def processing_loop():
    """Main processing loop: drain packets → build flows → extract features → detect threats."""
    global _running
    print("[*] Starting processing loop...")
    
    cycle_count = 0

    while _running:
        try:
            cycle_count += 1
            
            # 1. Drain packets from capture queue
            packets = packet_capture.drain_queue()

            if packets:
                # 2. Build flows
                flow_builder.add_packets(packets)
                if cycle_count % 5 == 0:  # Log every 5 cycles
                    print(f"[+] Processing: {len(packets)} packets drained, {flow_builder.get_active_flow_count()} active flows")

            # 3. Expire old flows
            expired = flow_builder.expire_flows()
            if expired and cycle_count % 5 == 0:
                print(f"[+] Expired {len(expired)} flows")

            # 4. Get active flows for analysis
            active_flows = flow_builder.get_all_flows_for_analysis()

            if active_flows:
                # 5. Extract features
                features_list = feature_engine.extract_batch(active_flows)

                # 5.1 Update drift monitor and adaptive thresholds
                drift_status = drift_monitor.update(features_list)
                threat_engine.update_drift(drift_status)

                # 6. ML prediction
                ml_results = ml_engine.predict_batch(features_list)

                # 7. Threat detection
                threats = threat_engine.analyze_batch(features_list, ml_results)

                # 7.1 Enrich threats with intel data
                if threats:
                    await threat_intel.enrich_threats(threats)

                if threats:
                    print(f"[!] THREATS DETECTED: {len(threats)} threats found!")
                    for t in threats[:3]:  # Print first 3
                        print(f"    - {t['attack_type']} from {t['source_ip']} (confidence: {t['confidence']:.2%})")

                # 8. Store threats in database
                for threat in threats:
                    await insert_threat(threat)

                # 9. Broadcast to WebSocket clients
                if threats and ws_manager.active_connections:
                    await ws_manager.broadcast({
                        "type": "threat_alert",
                        "threats": threats,
                        "timestamp": datetime.now().isoformat(),
                    })

            # 10. Periodically log traffic stats
            await insert_traffic_stats({
                "packets_captured": packet_capture.get_stats().get("packets_captured", 0),
                "active_flows": flow_builder.get_active_flow_count(),
                "bytes_total": packet_capture.get_stats().get("bytes_total", 0),
                "protocols": packet_capture.get_stats().get("protocols", {}),
            })

        except Exception as e:
            print(f"[!] Processing loop error: {e}")
            import traceback
            traceback.print_exc()

        await asyncio.sleep(3)  # Process every 3 seconds


async def auto_simulation_loop():
    """Generate periodic demo traffic for visualization."""
    from attack_simulator import simulate_mixed_traffic, simulate_port_scan, simulate_ddos, simulate_bruteforce
    print("[*] Starting auto-simulation loop for demo traffic...")
    
    attack_types = [simulate_mixed_traffic, simulate_port_scan, simulate_ddos, simulate_bruteforce]
    cycle = 0

    while _running:
        try:
            # Rotate through different attack types for variety
            attack_func = attack_types[cycle % len(attack_types)]
            num_packets = 50 if cycle % 4 == 0 else 30  # Vary packet count
            
            packets = attack_func(num_packets=num_packets)
            for pkt in packets:
                packet_capture.inject_packet(pkt)
            
            cycle += 1
            print(f"[+] Auto-simulation: Generated {len(packets)} packets ({attack_func.__name__})")
        except Exception as e:
            print(f"[!] Simulation loop error: {e}")

        await asyncio.sleep(12)  # Generate traffic every 12 seconds


async def intel_refresh_loop():
    """Refresh reputation feeds on a schedule."""
    while _running:
        try:
            await threat_intel.refresh_feeds()
        except Exception as e:
            print(f"[!] Intel refresh error: {e}")
        await asyncio.sleep(60 * 30)


# ─── App Lifecycle ─────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle."""
    # Startup
    await init_db()
    print("[+] Database initialized.")

    await threat_intel.refresh_from_db()
    print("[+] Threat intel cache warmed.")

    threat_engine.set_intel(threat_intel)
    print("[+] Threat intel linked to engine.")

    init_routes(packet_capture, flow_builder, feature_engine, ml_engine, threat_engine, drift_monitor, threat_intel)
    print("[+] Routes initialized with engine references.")

    # Try to start live capture (requires admin + Npcap)
    capture_started = packet_capture.start()
    if capture_started:
        print("[+] Live packet capture started.")
    else:
        print("[!] Live capture unavailable — using simulator for demo.")

    # Start background tasks
    global _running
    _running = True
    task1 = asyncio.create_task(processing_loop())
    task2 = asyncio.create_task(auto_simulation_loop())
    task3 = asyncio.create_task(intel_refresh_loop())
    print("[+] Background processing started.")
    print("[+] System is operational — dashboard at http://localhost:8000")

    yield

    # Shutdown
    global _running
    _running = False
    packet_capture.stop()
    task1.cancel()
    task2.cancel()
    task3.cancel()
    print("[*] System shutdown complete.")


# ─── FastAPI App ───────────────────────────────────────────────────

app = FastAPI(
    title="AI-Driven Network Intrusion Detection System",
    description="Real-time network traffic monitoring, ML-based intrusion detection, and cybersecurity dashboard.",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routes
app.include_router(router)


# Root endpoint
@app.get("/")
async def root():
    return {
        "name": "AI-Driven Network Intrusion Detection System",
        "status": "operational",
        "version": "1.0.0",
        "endpoints": {
            "traffic": "/api/traffic",
            "threats": "/api/threats",
            "logs": "/api/logs",
            "network_map": "/api/network-map",
            "system_status": "/api/system-status",
            "websocket": "/api/ws",
            "docs": "/docs",
        },
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
