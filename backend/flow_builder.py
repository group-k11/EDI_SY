"""
Flow Builder — Groups packets into network flows using 5-tuple keys.
Computes flow-level metrics: duration, packet count, byte count, rates.
"""

import time
from datetime import datetime
from typing import Dict, List, Optional
from collections import defaultdict


class NetworkFlow:
    """Represents a single bidirectional network flow."""

    def __init__(self, flow_key: tuple, first_packet_src_ip: str):
        self.flow_key = flow_key
        # Keep track of who initiated to determine Forward vs Backward
        self.initiator_ip = first_packet_src_ip
        self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol = flow_key
        self.packets: List[Dict] = []
        self.start_time = time.time()
        self.last_seen = self.start_time
        
        # Bidirectional stats
        self.fwd_packet_count = 0
        self.bwd_packet_count = 0
        self.fwd_byte_count = 0
        self.bwd_byte_count = 0
        
        self.byte_count = 0
        self.packet_count = 0
        self.syn_count = 0
        self.rst_count = 0
        self.fin_count = 0
        self.tcp_flags_list = []
        self.iats: List[float] = []

    def add_packet(self, packet: Dict):
        """Add a packet to this flow."""
        now = time.time()
        
        if self.packet_count > 0:
            self.iats.append(now - self.last_seen)
            
        self.packets.append(packet)
        self.last_seen = now
        
        pkt_len = packet.get("packet_length", 0)
        self.packet_count += 1
        self.byte_count += pkt_len
        
        if packet.get("source_ip") == self.initiator_ip:
            self.fwd_packet_count += 1
            self.fwd_byte_count += pkt_len
        else:
            self.bwd_packet_count += 1
            self.bwd_byte_count += pkt_len

        flags = packet.get("tcp_flags", "")
        if flags:
            self.tcp_flags_list.append(flags)
            if "S" in flags and "A" not in flags:
                self.syn_count += 1
            if "R" in flags:
                self.rst_count += 1
            if "F" in flags:
                self.fin_count += 1

    @property
    def duration(self) -> float:
        """Flow duration in seconds."""
        return max(self.last_seen - self.start_time, 0.001)

    @property
    def packets_per_second(self) -> float:
        return self.packet_count / self.duration

    @property
    def bytes_per_second(self) -> float:
        return self.byte_count / self.duration

    @property
    def avg_packet_size(self) -> float:
        return self.byte_count / max(self.packet_count, 1)

    @property
    def syn_ratio(self) -> float:
        return self.syn_count / max(self.packet_count, 1)

    @property
    def iat_mean(self) -> float:
        return sum(self.iats) / len(self.iats) if self.iats else 0.0

    @property
    def iat_std(self) -> float:
        import math
        if len(self.iats) > 1:
            mean = self.iat_mean
            variance = sum((x - mean) ** 2 for x in self.iats) / (len(self.iats) - 1)
            return math.sqrt(variance)
        return 0.0

    @property
    def iat_max(self) -> float:
        return max(self.iats) if self.iats else 0.0

    @property
    def iat_min(self) -> float:
        return min(self.iats) if self.iats else 0.0

    def to_dict(self) -> Dict:
        """Export flow as dictionary."""
        return {
            "source_ip": self.src_ip,
            "destination_ip": self.dst_ip,
            "source_port": self.src_port,
            "destination_port": self.dst_port,
            "protocol": self.protocol,
            "flow_duration": round(self.duration, 4),
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "fwd_packet_count": self.fwd_packet_count,
            "bwd_packet_count": self.bwd_packet_count,
            "fwd_byte_count": self.fwd_byte_count,
            "bwd_byte_count": self.bwd_byte_count,
            "packets_per_second": round(self.packets_per_second, 2),
            "bytes_per_second": round(self.bytes_per_second, 2),
            "avg_packet_size": round(self.avg_packet_size, 2),
            "syn_count": self.syn_count,
            "rst_count": self.rst_count,
            "fin_count": self.fin_count,
            "syn_ratio": round(self.syn_ratio, 4),
            "iat_mean": round(self.iat_mean, 6),
            "iat_std": round(self.iat_std, 6),
            "iat_max": round(self.iat_max, 6),
            "iat_min": round(self.iat_min, 6),
            "start_time": datetime.fromtimestamp(self.start_time).isoformat(),
            "last_seen": datetime.fromtimestamp(self.last_seen).isoformat(),
        }


class FlowBuilder:
    """Groups packets into network flows using 5-tuple key."""

    def __init__(self, flow_timeout: float = 30.0):
        self.flows: Dict[tuple, NetworkFlow] = {}
        self.completed_flows: List[NetworkFlow] = []
        self.flow_timeout = flow_timeout
        self._total_flows_created = 0

    def _make_key(self, packet: Dict) -> tuple:
        """Create bidirectional 5-tuple flow key from packet."""
        src_ip = packet.get("source_ip", "0.0.0.0")
        dst_ip = packet.get("destination_ip", "0.0.0.0")
        src_port = packet.get("source_port", 0)
        dst_port = packet.get("destination_port", 0)
        protocol = packet.get("protocol", "Other")
        
        # Sort IP and Port deterministically for bidirectional matching
        if src_ip < dst_ip:
            return (src_ip, dst_ip, src_port, dst_port, protocol)
        elif src_ip > dst_ip:
            return (dst_ip, src_ip, dst_port, src_port, protocol)
        else:
            if src_port <= dst_port:
                return (src_ip, dst_ip, src_port, dst_port, protocol)
            else:
                return (dst_ip, src_ip, dst_port, src_port, protocol)

    def add_packet(self, packet: Dict):
        """Add a packet to its corresponding flow."""
        key = self._make_key(packet)

        if key not in self.flows:
            self.flows[key] = NetworkFlow(key, first_packet_src_ip=packet.get("source_ip", "0.0.0.0"))
            self._total_flows_created += 1

        self.flows[key].add_packet(packet)

    def add_packets(self, packets: List[Dict]):
        """Add multiple packets."""
        for pkt in packets:
            self.add_packet(pkt)

    def expire_flows(self) -> List[NetworkFlow]:
        """Move expired flows to completed list and return them."""
        now = time.time()
        expired = []
        active_keys = list(self.flows.keys())

        for key in active_keys:
            flow = self.flows[key]
            if now - flow.last_seen > self.flow_timeout:
                expired.append(flow)
                self.completed_flows.append(flow)
                del self.flows[key]

        return expired

    def get_active_flows(self) -> List[Dict]:
        """Get all currently active flows as dictionaries."""
        return [flow.to_dict() for flow in self.flows.values()]

    def get_active_flow_count(self) -> int:
        return len(self.flows)

    def get_all_flows_for_analysis(self) -> List[NetworkFlow]:
        """Get all active flows for ML analysis (without expiring them)."""
        return list(self.flows.values())

    def get_stats(self) -> Dict:
        return {
            "active_flows": len(self.flows),
            "completed_flows": len(self.completed_flows),
            "total_flows_created": self._total_flows_created,
        }
