"""
Packet Capture Engine — Captures live network packets using Scapy.
Extracts key fields and buffers them in a thread-safe queue for processing.
Requires Administrator/root privileges and Npcap on Windows.
"""

import threading
import time
import queue
from datetime import datetime
from typing import Dict, List, Optional, Any
from collections import deque

# Pre-define symbols to prevent Pyright unbound errors
sniff = None
IP = None
TCP = None
UDP = None
ICMP = None
conf = None

# Try to import scapy, fall back gracefully
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, conf  # type: ignore
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class PacketCapture:
    """Live network packet capture engine."""

    def __init__(self, interface: Optional[str] = None, max_queue_size: int = 10000):
        self.interface = interface
        self.packet_queue = queue.Queue(maxsize=max_queue_size)
        self.recent_packets = deque(maxlen=500)
        self.is_running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # Statistics
        self.stats: Dict[str, Any] = {
            "packets_captured": 0,
            "bytes_total": 0,
            "start_time": None,
            "protocols": {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0},
            "capture_active": False,
        }

    def _process_packet(self, packet):
        """Extract fields from a captured packet."""
        try:
            if not packet.haslayer(IP):
                return

            ip_layer = packet[IP]
            packet_info = {
                "source_ip": ip_layer.src,
                "destination_ip": ip_layer.dst,
                "source_port": 0,
                "destination_port": 0,
                "protocol": "Other",
                "packet_length": len(packet),
                "tcp_flags": "",
                "timestamp": datetime.now().isoformat(),
            }

            if packet.haslayer(TCP):
                tcp = packet[TCP]
                packet_info["source_port"] = tcp.sport
                packet_info["destination_port"] = tcp.dport
                packet_info["protocol"] = "TCP"
                packet_info["tcp_flags"] = str(tcp.flags)
                self.stats["protocols"]["TCP"] += 1
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                packet_info["source_port"] = udp.sport
                packet_info["destination_port"] = udp.dport
                packet_info["protocol"] = "UDP"
                self.stats["protocols"]["UDP"] += 1
            elif packet.haslayer(ICMP):
                packet_info["protocol"] = "ICMP"
                self.stats["protocols"]["ICMP"] += 1
            else:
                self.stats["protocols"]["Other"] += 1

            # Add to queue for flow processing
            try:
                self.packet_queue.put_nowait(packet_info)
            except queue.Full:
                pass  # Drop packet if queue is full

            # Add to recent packets for display
            self.recent_packets.append(packet_info)

            # Update stats
            with self._lock:
                self.stats["packets_captured"] += 1
                self.stats["bytes_total"] += packet_info["packet_length"]

        except Exception:
            pass  # Skip malformed packets

    def start(self):
        """Start packet capture in a background thread."""
        if not SCAPY_AVAILABLE:
            print("[!] Scapy not available. Packet capture disabled.")
            return False

        if self.is_running:
            return True

        self.is_running = True
        self.stats["start_time"] = datetime.now().isoformat()
        self.stats["capture_active"] = True

        self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()
        return True

    def _capture_loop(self):
        """Main capture loop."""
        try:
            if sniff is not None:
                sniff(
                    iface=self.interface,
                    prn=self._process_packet,
                    store=False,
                    stop_filter=lambda _: not self.is_running,
                )
        except PermissionError:
            print("[!] Permission denied — run as Administrator for live capture.")
            self.is_running = False
            self.stats["capture_active"] = False
        except Exception as e:
            print(f"[!] Capture error: {e}")
            self.is_running = False
            self.stats["capture_active"] = False

    def stop(self):
        """Stop packet capture."""
        self.is_running = False
        self.stats["capture_active"] = False

    def get_packets(self, count: int = 50) -> List[Dict]:
        """Get recent packets for display."""
        return list(self.recent_packets)[-count:]

    def drain_queue(self) -> List[Dict]:
        """Drain all packets from the queue for flow processing."""
        packets = []
        while not self.packet_queue.empty():
            try:
                packets.append(self.packet_queue.get_nowait())
            except queue.Empty:
                break
        return packets

    def get_stats(self) -> Dict:
        """Get capture statistics."""
        with self._lock:
            return dict(self.stats)

    def inject_packet(self, packet_info: Dict):
        """Inject a synthetic packet (used by attack simulator)."""
        packet_info.setdefault("timestamp", datetime.now().isoformat())
        try:
            self.packet_queue.put_nowait(packet_info)
        except queue.Full:
            pass
        self.recent_packets.append(packet_info)
        with self._lock:
            self.stats["packets_captured"] += 1
            self.stats["bytes_total"] += packet_info.get("packet_length", 0)
            proto = packet_info.get("protocol", "Other")
            if proto in self.stats["protocols"]:
                self.stats["protocols"][proto] += 1
            else:
                self.stats["protocols"]["Other"] += 1
