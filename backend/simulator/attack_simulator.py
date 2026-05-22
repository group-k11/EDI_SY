"""
Attack Simulator — A.I.R.S Backend
Generates synthetic attack flows and sends them to the /analyze endpoint.
Uses realistic CICIDS2017-inspired feature ranges mapped to our 25-feature schema.
"""

import argparse
import random
import time
import sys
import json
import threading
from typing import Dict, List, Optional

try:
    import requests
except ImportError:
    requests = None

# ─── Feature Order (must match MLEngine FEATURE_COLUMNS exactly) ─────
FEATURE_COLUMNS = [
    "flow_duration", "packet_count", "byte_count",
    "packets_per_second", "bytes_per_second", "avg_packet_size",
    "connection_rate", "syn_packet_ratio", "unique_ports_contacted",
    "failed_connection_attempts", "burst_rate", "syn_count",
    "rst_count", "unique_targets",
    "fwd_packet_count", "bwd_packet_count", "fwd_byte_count", "bwd_byte_count",
    "iat_mean", "iat_std", "iat_max", "iat_min",
    "is_lateral", "is_outbound", "is_inbound",
]

# ─── Attack Profiles (min, max) per feature ──────────────────────────
ATTACK_PROFILES: Dict[str, Dict[str, tuple]] = {
    "DDoS": {
        "flow_duration":              (0.1,    2.0),
        "packet_count":               (500,    2000),
        "byte_count":                 (500000, 2000000),
        "packets_per_second":         (800,    1200),
        "bytes_per_second":           (800000, 1200000),
        "avg_packet_size":            (800,    1500),
        "connection_rate":            (50.0,   120.0),
        "syn_packet_ratio":           (0.7,    0.99),
        "unique_ports_contacted":     (1,      3),
        "failed_connection_attempts": (0,      2),
        "burst_rate":                 (800,    1200),
        "syn_count":                  (400,    1800),
        "rst_count":                  (5,      50),
        "unique_targets":             (1,      2),
        "fwd_packet_count":           (450,    1900),
        "bwd_packet_count":           (0,      50),
        "fwd_byte_count":             (450000, 1900000),
        "bwd_byte_count":             (0,      5000),
        "iat_mean":                   (0.0005, 0.002),
        "iat_std":                    (0.0001, 0.001),
        "iat_max":                    (0.005,  0.02),
        "iat_min":                    (0.0001, 0.0005),
        "is_lateral":                 (0,      0),
        "is_outbound":                (0,      0),
        "is_inbound":                 (1,      1),
    },
    "PortScan": {
        "flow_duration":              (0.001,  0.05),
        "packet_count":               (1,      3),
        "byte_count":                 (40,     120),
        "packets_per_second":         (20,     80),
        "bytes_per_second":           (800,    4000),
        "avg_packet_size":            (40,     60),
        "connection_rate":            (10.0,   50.0),
        "syn_packet_ratio":           (0.9,    1.0),
        "unique_ports_contacted":     (50,     500),
        "failed_connection_attempts": (1,      3),
        "burst_rate":                 (20,     80),
        "syn_count":                  (1,      3),
        "rst_count":                  (1,      3),
        "unique_targets":             (1,      5),
        "fwd_packet_count":           (1,      3),
        "bwd_packet_count":           (0,      1),
        "fwd_byte_count":             (40,     120),
        "bwd_byte_count":             (0,      20),
        "iat_mean":                   (0.01,   0.5),
        "iat_std":                    (0.001,  0.1),
        "iat_max":                    (0.1,    2.0),
        "iat_min":                    (0.001,  0.01),
        "is_lateral":                 (0,      0),
        "is_outbound":                (0,      0),
        "is_inbound":                 (1,      1),
    },
    "BruteForce": {
        "flow_duration":              (1.0,    30.0),
        "packet_count":               (100,    500),
        "byte_count":                 (5000,   50000),
        "packets_per_second":         (10,     30),
        "bytes_per_second":           (1000,   5000),
        "avg_packet_size":            (50,     150),
        "connection_rate":            (5.0,    20.0),
        "syn_packet_ratio":           (0.5,    0.8),
        "unique_ports_contacted":     (1,      3),
        "failed_connection_attempts": (20,     100),
        "burst_rate":                 (10,     30),
        "syn_count":                  (50,     250),
        "rst_count":                  (40,     200),
        "unique_targets":             (1,      2),
        "fwd_packet_count":           (50,     250),
        "bwd_packet_count":           (50,     250),
        "fwd_byte_count":             (2500,   25000),
        "bwd_byte_count":             (2500,   25000),
        "iat_mean":                   (0.05,   0.5),
        "iat_std":                    (0.01,   0.1),
        "iat_max":                    (0.5,    5.0),
        "iat_min":                    (0.01,   0.1),
        "is_lateral":                 (0,      0),
        "is_outbound":                (0,      0),
        "is_inbound":                 (1,      1),
    },
    "Suspicious": {
        "flow_duration":              (5.0,    60.0),
        "packet_count":               (20,     200),
        "byte_count":                 (1000,   20000),
        "packets_per_second":         (2,      15),
        "bytes_per_second":           (100,    2000),
        "avg_packet_size":            (50,     200),
        "connection_rate":            (1.0,    10.0),
        "syn_packet_ratio":           (0.2,    0.6),
        "unique_ports_contacted":     (5,      30),
        "failed_connection_attempts": (2,      10),
        "burst_rate":                 (2,      15),
        "syn_count":                  (10,     100),
        "rst_count":                  (5,      40),
        "unique_targets":             (3,      15),
        "fwd_packet_count":           (10,     100),
        "bwd_packet_count":           (10,     100),
        "fwd_byte_count":             (500,    10000),
        "bwd_byte_count":             (500,    10000),
        "iat_mean":                   (0.1,    2.0),
        "iat_std":                    (0.05,   1.0),
        "iat_max":                    (1.0,    10.0),
        "iat_min":                    (0.01,   0.5),
        "is_lateral":                 (1,      1),
        "is_outbound":                (0,      0),
        "is_inbound":                 (0,      0),
    },
    "Benign": {
        "flow_duration":              (5.0,    300.0),
        "packet_count":               (10,     100),
        "byte_count":                 (1000,   100000),
        "packets_per_second":         (0.5,    5.0),
        "bytes_per_second":           (50,     5000),
        "avg_packet_size":            (200,    1200),
        "connection_rate":            (0.1,    1.0),
        "syn_packet_ratio":           (0.05,   0.2),
        "unique_ports_contacted":     (1,      5),
        "failed_connection_attempts": (0,      1),
        "burst_rate":                 (0.5,    5.0),
        "syn_count":                  (2,      20),
        "rst_count":                  (0,      3),
        "unique_targets":             (1,      3),
        "fwd_packet_count":           (5,      60),
        "bwd_packet_count":           (5,      60),
        "fwd_byte_count":             (500,    50000),
        "bwd_byte_count":             (500,    50000),
        "iat_mean":                   (0.5,    10.0),
        "iat_std":                    (0.1,    3.0),
        "iat_max":                    (2.0,    30.0),
        "iat_min":                    (0.1,    2.0),
        "is_lateral":                 (0,      1),
        "is_outbound":                (0,      1),
        "is_inbound":                 (0,      1),
    },
}

ATTACK_TYPES = list(ATTACK_PROFILES.keys())


def generate_flow(attack_type: str = "random") -> Dict:
    """
    Generate a synthetic network flow feature dict.

    Args:
        attack_type: One of ATTACK_PROFILES keys or "random"

    Returns:
        Dict of {feature_name: float} matching FEATURE_COLUMNS order.
    """
    if attack_type == "random":
        attack_type = random.choice(ATTACK_TYPES)

    profile = ATTACK_PROFILES.get(attack_type, ATTACK_PROFILES["Benign"])
    flow = {}

    for feature in FEATURE_COLUMNS:
        if feature in profile:
            lo, hi = profile[feature]
            # Add ±10% random variation within the range
            base = random.uniform(lo, hi)
            variation = base * random.uniform(-0.10, 0.10)
            value = max(0.0, base + variation)
            # Binary features stay 0 or 1
            if feature in ("is_lateral", "is_outbound", "is_inbound"):
                value = round(value)
            flow[feature] = round(value, 4)
        else:
            flow[feature] = 0.0

    return flow


# ─── Simulator State ─────────────────────────────────────────────────
_sim_running = False
_sim_thread: Optional[threading.Thread] = None


def _sim_loop(attack_type: str, rate: int, duration: int, host: str):
    """Background simulation loop."""
    global _sim_running
    end_time = time.time() + duration
    total = 0
    critical = 0
    summary: Dict[str, int] = {}

    while _sim_running and time.time() < end_time:
        flow = generate_flow(attack_type)
        source_ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

        payload = {"features": flow, "source_ip": source_ip}

        for attempt in range(3):
            try:
                assert requests is not None, "requests not installed"
                resp = requests.post(
                    f"{host}/analyze",
                    json=payload,
                    timeout=10,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    pred = data.get("prediction", "unknown")
                    sev = data.get("severity", {}).get("level", "?") if isinstance(data.get("severity"), dict) else "?"
                    action = data.get("response_action", {}).get("action", "?")
                    summary[pred] = summary.get(pred, 0) + 1
                    if sev == "CRITICAL":
                        critical += 1
                    total += 1

                    # Colored output
                    color = {
                        "CRITICAL": "\033[91m",
                        "HIGH":     "\033[93m",
                        "MEDIUM":   "\033[94m",
                        "LOW":      "\033[96m",
                    }.get(sev, "\033[0m")
                    print(
                        f"{color}[{pred}] Severity: {sev} | "
                        f"Action: {action} | IP: {source_ip}\033[0m"
                    )
                break
            except Exception as e:
                if attempt < 2:
                    time.sleep(1)
                else:
                    print(f"\033[91m[ERROR] Could not reach {host}: {e}\033[0m")

        time.sleep(1.0 / max(rate, 1))

    print(f"\n{'='*60}")
    print(f"Simulation complete. Total flows: {total} | Critical alerts: {critical}")
    print(f"Breakdown: {summary}")
    print(f"{'='*60}")
    _sim_running = False


def start_simulation(attack_type: str = "random", rate: int = 2,
                     duration: int = 60, host: str = "http://localhost:8000") -> bool:
    """Start simulation in background thread. Returns True if started."""
    global _sim_running, _sim_thread
    if _sim_running:
        return False
    _sim_running = True
    _sim_thread = threading.Thread(
        target=_sim_loop,
        args=(attack_type, rate, duration, host),
        daemon=True,
    )
    _sim_thread.start()
    return True


def stop_simulation() -> bool:
    """Stop running simulation. Returns True if was running."""
    global _sim_running
    if _sim_running:
        _sim_running = False
        return True
    return False


def is_simulation_running() -> bool:
    return _sim_running


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="A.I.R.S Attack Simulator")
    parser.add_argument("--type",     default="random",               help="Attack type (DDoS/PortScan/BruteForce/Suspicious/Benign/random)")
    parser.add_argument("--rate",     type=int,   default=2,          help="Flows per second")
    parser.add_argument("--duration", type=int,   default=60,         help="Duration in seconds")
    parser.add_argument("--host",     default="http://localhost:8000", help="Backend host URL")
    args = parser.parse_args()

    if requests is None:
        print("ERROR: requests library not installed. Run: pip install requests")
        sys.exit(1)

    print(f"Starting A.I.R.S simulator: {args.type} | {args.rate} flows/sec | {args.duration}s")
    print(f"Targeting: {args.host}/analyze")
    print("="*60)

    _sim_running = True
    _sim_loop(args.type, args.rate, args.duration, args.host)
