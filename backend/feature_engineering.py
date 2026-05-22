"""
Feature Engineering — Computes security behavior indicators from network flows.
Analyzes per-source-IP behavior patterns to feed ML detection engine.
"""

import os
import time
from typing import Dict, List
from collections import defaultdict
import ipaddress


class FeatureEngine:
    """Extracts security-relevant features from network flows."""

    def __init__(self, window_seconds: float = 30.0):
        self.window_seconds = window_seconds
        
        # Parse internal subnets from environment
        subnets_str = os.getenv("INTERNAL_SUBNETS", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16")
        self.internal_subnets = []
        for subnet in subnets_str.split(','):
            try:
                self.internal_subnets.append(ipaddress.ip_network(subnet.strip(), strict=False))
            except ValueError:
                pass

        # Per-IP tracking
        self.ip_connections = defaultdict(list)       # timestamps
        self.ip_ports = defaultdict(set)              # unique dest ports
        self.ip_syn_counts = defaultdict(int)
        self.ip_packet_counts = defaultdict(int)
        self.ip_byte_counts = defaultdict(int)
        self.ip_rst_counts = defaultdict(int)         # failed connections
        self.ip_targets = defaultdict(set)            # unique targets
        self.ip_packet_sizes = defaultdict(list)

    def update_from_flows(self, flows) -> None:
        """Update tracking stats from a list of NetworkFlow objects."""
        now = time.time()
        for flow in flows:
            src = flow.src_ip
            self.ip_connections[src].append(now)
            self.ip_ports[src].add(flow.dst_port)
            self.ip_syn_counts[src] += flow.syn_count
            self.ip_packet_counts[src] += flow.packet_count
            self.ip_byte_counts[src] += flow.byte_count
            self.ip_rst_counts[src] += flow.rst_count
            self.ip_targets[src].add(flow.dst_ip)
            for pkt in flow.packets:
                self.ip_packet_sizes[src].append(pkt.get("packet_length", 0))
                # Cap per-IP packet size history to prevent unbounded growth
                if len(self.ip_packet_sizes[src]) > 1000:
                    self.ip_packet_sizes[src] = self.ip_packet_sizes[src][-1000:]

    def _is_internal(self, ip_str: str) -> bool:
        """Check if an IP address belongs to the internal network."""
        try:
            ip = ipaddress.ip_address(ip_str)
            return any(ip in subnet for subnet in self.internal_subnets)
        except ValueError:
            return False

    def extract_features(self, flow) -> Dict:
        """
        Extract feature vector from a single flow for ML classification.
        Returns a dictionary of features.
        """
        src = flow.src_ip
        dst = flow.dst_ip
        now = time.time()

        # Clean old connection timestamps
        window_start = now - self.window_seconds
        self.ip_connections[src] = [
            t for t in self.ip_connections[src] if t > window_start
        ]

        # Connection rate: connections per second in the window
        conn_count = len(self.ip_connections[src])
        connection_rate = conn_count / self.window_seconds

        # SYN packet ratio
        total_pkts = max(self.ip_packet_counts[src], 1)
        syn_packet_ratio = self.ip_syn_counts[src] / total_pkts

        # Unique ports contacted
        unique_ports = len(self.ip_ports[src])

        # Failed connection attempts (RST packets)
        failed_connections = self.ip_rst_counts[src]

        # Average packet size
        sizes = self.ip_packet_sizes[src]
        avg_packet_size = sum(sizes) / max(len(sizes), 1)

        # Burst rate: packets in short burst window
        burst_rate = flow.packets_per_second

        # Network geometry (Inbound, Outbound, Lateral)
        src_internal = self._is_internal(src)
        dst_internal = self._is_internal(dst)
        
        is_lateral = 1.0 if (src_internal and dst_internal) else 0.0
        is_outbound = 1.0 if (src_internal and not dst_internal) else 0.0
        is_inbound = 1.0 if (not src_internal and dst_internal) else 0.0

        # Additional features for ML
        return {
            "flow_duration": flow.duration,
            "packet_count": flow.packet_count,
            "byte_count": flow.byte_count,
            "fwd_packet_count": flow.fwd_packet_count,
            "bwd_packet_count": flow.bwd_packet_count,
            "fwd_byte_count": flow.fwd_byte_count,
            "bwd_byte_count": flow.bwd_byte_count,
            "packets_per_second": flow.packets_per_second,
            "bytes_per_second": flow.bytes_per_second,
            "avg_packet_size": avg_packet_size,
            "iat_mean": flow.iat_mean,
            "iat_std": flow.iat_std,
            "iat_max": flow.iat_max,
            "iat_min": flow.iat_min,
            "is_lateral": is_lateral,
            "is_outbound": is_outbound,
            "is_inbound": is_inbound,
            "connection_rate": connection_rate,
            "syn_packet_ratio": syn_packet_ratio,
            "unique_ports_contacted": unique_ports,
            "failed_connection_attempts": failed_connections,
            "burst_rate": burst_rate,
            "syn_count": flow.syn_count,
            "rst_count": flow.rst_count,
            "unique_targets": len(self.ip_targets[src]),
            "source_ip": src,
            "destination_ip": dst,
        }

    def extract_batch(self, flows) -> List[Dict]:
        """Extract features from a batch of flows."""
        self.update_from_flows(flows)
        return [self.extract_features(flow) for flow in flows]

    def reset(self):
        """Clear all tracking data."""
        self.ip_connections.clear()
        self.ip_ports.clear()
        self.ip_syn_counts.clear()
        self.ip_packet_counts.clear()
        self.ip_byte_counts.clear()
        self.ip_rst_counts.clear()
        self.ip_targets.clear()
        self.ip_packet_sizes.clear()
