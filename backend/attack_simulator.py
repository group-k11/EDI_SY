"""
Attack Simulator — Generates synthetic attack patterns for testing.
Injects simulated packets into the capture pipeline without real network attacks.
"""

import random
import time
from datetime import datetime
from typing import Dict, List, Optional


def _random_ip() -> str:
    """Generate a random IP address."""
    return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def _internal_ip() -> str:
    """Generate an internal/target IP."""
    return f"192.168.1.{random.randint(1, 254)}"


def simulate_port_scan(target_ip: Optional[str] = None, num_packets: int = 80) -> List[Dict]:
    """
    Simulate a port scan attack.
    Characteristics: single source, many destination ports, SYN packets, small size.
    """
    attacker_ip = _random_ip()
    target = target_ip or _internal_ip()
    packets = []

    ports = random.sample(range(1, 65535), min(num_packets, 1000))

    for port in ports[:num_packets]:
        packets.append({
            "source_ip": attacker_ip,
            "destination_ip": target,
            "source_port": random.randint(49152, 65535),
            "destination_port": port,
            "protocol": "TCP",
            "packet_length": random.randint(40, 80),
            "tcp_flags": "S",
            "timestamp": datetime.now().isoformat(),
        })
        time.sleep(random.uniform(0.001, 0.01))

    return packets


def simulate_ddos(target_ip: Optional[str] = None, num_packets: int = 200) -> List[Dict]:
    """
    Simulate a DDoS attack.
    Characteristics: high packet rate, large volume, from multiple sources.
    """
    target = target_ip or _internal_ip()
    attacker_ips = [_random_ip() for _ in range(random.randint(3, 8))]
    packets = []

    for _ in range(num_packets):
        src = random.choice(attacker_ips)
        packets.append({
            "source_ip": src,
            "destination_ip": target,
            "source_port": random.randint(1024, 65535),
            "destination_port": random.choice([80, 443, 8080]),
            "protocol": random.choice(["TCP", "UDP"]),
            "packet_length": random.randint(512, 1500),
            "tcp_flags": random.choice(["S", "SA", "A", ""]),
            "timestamp": datetime.now().isoformat(),
        })
        time.sleep(random.uniform(0.001, 0.005))

    return packets


def simulate_bruteforce(target_ip: Optional[str] = None, num_packets: int = 60) -> List[Dict]:
    """
    Simulate a brute force attack.
    Characteristics: same port (SSH/RDP), many connections, RST responses.
    """
    attacker_ip = _random_ip()
    target = target_ip or _internal_ip()
    target_port = random.choice([22, 3389, 3306, 5432])
    packets = []

    for i in range(num_packets):
        # SYN attempt
        packets.append({
            "source_ip": attacker_ip,
            "destination_ip": target,
            "source_port": random.randint(49152, 65535),
            "destination_port": target_port,
            "protocol": "TCP",
            "packet_length": random.randint(64, 256),
            "tcp_flags": "S",
            "timestamp": datetime.now().isoformat(),
        })

        # RST response (failed auth)
        if random.random() > 0.2:
            packets.append({
                "source_ip": target,
                "destination_ip": attacker_ip,
                "source_port": target_port,
                "destination_port": random.randint(49152, 65535),
                "protocol": "TCP",
                "packet_length": random.randint(40, 60),
                "tcp_flags": "R",
                "timestamp": datetime.now().isoformat(),
            })

        time.sleep(random.uniform(0.01, 0.05))

    return packets


def simulate_mixed_traffic(num_packets: int = 100) -> List[Dict]:
    """Generate mixed normal + attack traffic for realistic demo."""
    packets = []

    # Normal traffic
    for _ in range(num_packets // 2):
        packets.append({
            "source_ip": _internal_ip(),
            "destination_ip": _random_ip(),
            "source_port": random.randint(49152, 65535),
            "destination_port": random.choice([80, 443, 53, 8080, 3000]),
            "protocol": random.choice(["TCP", "UDP", "TCP", "TCP"]),
            "packet_length": random.randint(64, 1500),
            "tcp_flags": random.choice(["S", "SA", "A", "PA", "FA", ""]),
            "timestamp": datetime.now().isoformat(),
        })

    # Sprinkle in some attack packets
    attack_funcs = [simulate_port_scan, simulate_ddos, simulate_bruteforce]
    chosen = random.choice(attack_funcs)
    packets.extend(chosen(num_packets=num_packets // 4))

    random.shuffle(packets)
    return packets


SIMULATION_MAP = {
    "port_scan": simulate_port_scan,
    "ddos": simulate_ddos,
    "dos": simulate_ddos,
    "bruteforce": simulate_bruteforce,
    "brute_force": simulate_bruteforce,
    "mixed": simulate_mixed_traffic,
}
