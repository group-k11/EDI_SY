"""
Response Engine — Autonomous threat response module for A.I.R.S.
When a threat is detected and analyzed, this engine decides and executes
the appropriate security response automatically.

Response Actions (by severity):
    CRITICAL → block_ip     : Source IP blocked in DB + in-memory set
    HIGH     → rate_limit   : IP flagged for rate limiting, auto-expires
    MEDIUM   → flag         : IP flagged in memory, enhanced monitoring
    LOW      → log          : Logged only, no active response

All blocks and rate-limits auto-expire based on configurable durations.
Manual override supported via unblock_ip() for demo / operator control.
"""

import os
import uuid
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set


# ─── Configuration ─────────────────────────────────────────────────

BLOCK_DURATION_MINUTES    = int(os.getenv("BLOCK_DURATION_MINUTES", "60"))
RATE_LIMIT_DURATION_MINUTES = int(os.getenv("RATE_LIMIT_DURATION_MINUTES", "30"))

# Recommended actions per severity level
_RESPONSE_ACTIONS = {
    "CRITICAL": "block_ip",
    "HIGH":     "rate_limit",
    "MEDIUM":   "flag",
    "LOW":      "log",
    "INFO":     "log",
}

# Human-readable response descriptions
_ACTION_DESCRIPTIONS = {
    "block_ip": "Source IP automatically blocked — all future packets dropped",
    "rate_limit": "Source IP rate-limited — traffic throttled for {duration} minutes",
    "flag": "Source IP flagged for enhanced monitoring",
    "log": "Threat logged — no active response required at this severity level",
}


# ─── Response Entry ─────────────────────────────────────────────────

class ResponseEntry:
    """Tracks a single IP response entry (block, rate-limit, or flag)."""

    def __init__(
        self,
        ip: str,
        action: str,
        reason: str,
        attack_type: str,
        severity_level: str,
        expires_at: datetime,
    ):
        self.id = str(uuid.uuid4())
        self.ip = ip
        self.action = action
        self.reason = reason
        self.attack_type = attack_type
        self.severity_level = severity_level
        self.created_at = datetime.utcnow()
        self.expires_at = expires_at
        self.packets_dropped = 0
        self.bytes_dropped = 0
        self.last_drop_at: Optional[datetime] = None

    def is_expired(self) -> bool:
        return datetime.utcnow() > self.expires_at

    def record_drop(self, packet_size: int = 512):
        self.packets_dropped += 1
        self.bytes_dropped += packet_size
        self.last_drop_at = datetime.utcnow()

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "ip": self.ip,
            "action": self.action,
            "reason": self.reason,
            "attack_type": self.attack_type,
            "severity_level": self.severity_level,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "packets_dropped": self.packets_dropped,
            "bytes_dropped": self.bytes_dropped,
            "bytes_dropped_mb": round(self.bytes_dropped / (1024 * 1024), 3),
            "last_drop_at": self.last_drop_at.isoformat() if self.last_drop_at else None,
            "is_active": not self.is_expired(),
            "time_remaining_minutes": max(
                0,
                int((self.expires_at - datetime.utcnow()).total_seconds() / 60)
            ),
        }


# ─── ResponseEngine ─────────────────────────────────────────────────

class ResponseEngine:
    """
    Autonomous threat response engine.
    Thread-safe — uses a lock for all in-memory mutations.
    """

    def __init__(self):
        self._lock = threading.Lock()

        # Active response entries keyed by IP
        self._blocked: Dict[str, ResponseEntry] = {}       # CRITICAL → block
        self._rate_limited: Dict[str, ResponseEntry] = {}  # HIGH → rate limit
        self._flagged: Dict[str, ResponseEntry] = {}       # MEDIUM → flag

        # Fast lookup sets for packet-path checks (O(1))
        self._blocked_ips: Set[str] = set()
        self._rate_limited_ips: Set[str] = set()

        # Cumulative stats (never reset — grows over session)
        self.total_responses = 0
        self.total_blocks_ever = 0
        self.total_packets_dropped = 0
        self.total_bytes_dropped = 0

    # ── Core Response ────────────────────────────────────────────────

    def respond(self, threat: Dict) -> Dict:
        """
        Decide and execute a response to a detected threat.

        Args:
            threat: Threat dict from ThreatEngine containing:
                    source_ip, attack_type, severity (level string),
                    confidence, details.packets_per_second

        Returns:
            Response dict with action, reason, expires_at, and impact data
        """
        source_ip = threat.get("source_ip", "unknown")
        attack_type = threat.get("attack_type", "unknown")
        severity_level = threat.get("severity", "LOW").upper()
        confidence = threat.get("confidence", 0.0)

        # Skip response for unknown/internal IPs in loopback
        if source_ip in ("unknown", "127.0.0.1", "::1"):
            return {
                "action": "skip",
                "reason": "Loopback / unknown IP — no response taken",
                "ip": source_ip,
            }

        action = _RESPONSE_ACTIONS.get(severity_level, "log")

        with self._lock:
            # Escalate if already blocked — just update stats
            if source_ip in self._blocked_ips and not self._blocked[source_ip].is_expired():
                entry = self._blocked[source_ip]
                return {
                    "action": "already_blocked",
                    "reason": f"IP already blocked (expires {entry.expires_at.strftime('%H:%M:%S')})",
                    "ip": source_ip,
                    "expires_at": entry.expires_at.isoformat(),
                    "existing_entry_id": entry.id,
                }

            if action == "block_ip":
                return self._do_block(source_ip, attack_type, severity_level, confidence)
            elif action == "rate_limit":
                return self._do_rate_limit(source_ip, attack_type, severity_level)
            elif action == "flag":
                return self._do_flag(source_ip, attack_type, severity_level)
            else:
                self.total_responses += 1
                return {
                    "action": "log",
                    "reason": _ACTION_DESCRIPTIONS["log"],
                    "ip": source_ip,
                }

    def _do_block(self, ip: str, attack_type: str, severity: str, confidence: float) -> Dict:
        expires = datetime.utcnow() + timedelta(minutes=BLOCK_DURATION_MINUTES)
        reason = (
            f"{severity} severity {attack_type.upper()} detected "
            f"(confidence: {confidence:.0%}) — auto-blocked for {BLOCK_DURATION_MINUTES} min"
        )
        entry = ResponseEntry(ip, "block_ip", reason, attack_type, severity, expires)
        self._blocked[ip] = entry
        self._blocked_ips.add(ip)

        # Also remove from rate-limited if was there before
        self._rate_limited.pop(ip, None)
        self._rate_limited_ips.discard(ip)

        self.total_responses += 1
        self.total_blocks_ever += 1

        return {
            "action": "block_ip",
            "reason": reason,
            "ip": ip,
            "entry_id": entry.id,
            "expires_at": expires.isoformat(),
            "duration_minutes": BLOCK_DURATION_MINUTES,
            "message": f"[BLOCKED] {ip} has been blocked. All incoming traffic from this IP will be dropped.",
        }

    def _do_rate_limit(self, ip: str, attack_type: str, severity: str) -> Dict:
        expires = datetime.utcnow() + timedelta(minutes=RATE_LIMIT_DURATION_MINUTES)
        reason = (
            f"{severity} severity {attack_type.upper()} — "
            f"rate limited for {RATE_LIMIT_DURATION_MINUTES} min"
        )
        entry = ResponseEntry(ip, "rate_limit", reason, attack_type, severity, expires)
        self._rate_limited[ip] = entry
        self._rate_limited_ips.add(ip)
        self.total_responses += 1

        return {
            "action": "rate_limit",
            "reason": reason,
            "ip": ip,
            "entry_id": entry.id,
            "expires_at": expires.isoformat(),
            "duration_minutes": RATE_LIMIT_DURATION_MINUTES,
            "message": f"[RATE_LIMITED] {ip} is now rate-limited for {RATE_LIMIT_DURATION_MINUTES} minutes.",
        }

    def _do_flag(self, ip: str, attack_type: str, severity: str) -> Dict:
        expires = datetime.utcnow() + timedelta(minutes=60)
        reason = f"{severity} severity {attack_type.upper()} — flagged for monitoring"
        entry = ResponseEntry(ip, "flag", reason, attack_type, severity, expires)
        self._flagged[ip] = entry
        self.total_responses += 1

        return {
            "action": "flag",
            "reason": reason,
            "ip": ip,
            "entry_id": entry.id,
            "expires_at": expires.isoformat(),
            "message": f"[FLAGGED] {ip} has been flagged for enhanced monitoring.",
        }

    # ── Packet Path Checks (O(1) — called per packet) ───────────────

    def is_blocked(self, ip: str) -> bool:
        """Fast O(1) check — called in packet injection path."""
        return ip in self._blocked_ips

    def is_rate_limited(self, ip: str) -> bool:
        """Fast O(1) check."""
        return ip in self._rate_limited_ips

    def record_dropped_packet(self, ip: str, packet_size: int = 512):
        """Record a packet drop for stats tracking (called from packet path)."""
        with self._lock:
            entry = self._blocked.get(ip)
            if entry:
                entry.record_drop(packet_size)
                self.total_packets_dropped += 1
                self.total_bytes_dropped += packet_size

    # ── Manual Override ──────────────────────────────────────────────

    def unblock_ip(self, ip: str) -> bool:
        """Manual unblock — for operator override or demo purposes."""
        with self._lock:
            removed = False
            if ip in self._blocked:
                del self._blocked[ip]
                self._blocked_ips.discard(ip)
                removed = True
            if ip in self._rate_limited:
                del self._rate_limited[ip]
                self._rate_limited_ips.discard(ip)
                removed = True
            if ip in self._flagged:
                del self._flagged[ip]
                removed = True
            return removed

    # ── Expiry ───────────────────────────────────────────────────────

    def expire_entries(self) -> int:
        """
        Remove expired response entries.
        Called by background task in main.py every 5 minutes.
        Returns count of expired entries removed.
        """
        removed = 0
        with self._lock:
            for store, ip_set in [
                (self._blocked, self._blocked_ips),
                (self._rate_limited, self._rate_limited_ips),
            ]:
                expired_ips = [ip for ip, e in store.items() if e.is_expired()]
                for ip in expired_ips:
                    del store[ip]
                    ip_set.discard(ip)
                    removed += 1

            expired_flags = [ip for ip, e in self._flagged.items() if e.is_expired()]
            for ip in expired_flags:
                del self._flagged[ip]
                removed += 1

        return removed

    # ── Status / Reporting ───────────────────────────────────────────

    def get_blocked_ips(self) -> List[Dict]:
        with self._lock:
            return [e.to_dict() for e in self._blocked.values() if not e.is_expired()]

    def get_rate_limited_ips(self) -> List[Dict]:
        with self._lock:
            return [e.to_dict() for e in self._rate_limited.values() if not e.is_expired()]

    def get_flagged_ips(self) -> List[Dict]:
        with self._lock:
            return [e.to_dict() for e in self._flagged.values() if not e.is_expired()]

    def get_impact_stats(self) -> Dict:
        """Returns real-world impact numbers for /api/stats endpoint."""
        total_mb = round(self.total_bytes_dropped / (1024 * 1024), 2)
        # Estimate: average DDoS attack = 10 min downtime per 50K packets
        downtime_estimate = round(self.total_packets_dropped / 50000 * 10, 1)

        return {
            "total_responses": self.total_responses,
            "total_blocks_ever": self.total_blocks_ever,
            "currently_blocked": len(self._blocked_ips),
            "currently_rate_limited": len(self._rate_limited_ips),
            "total_packets_dropped": self.total_packets_dropped,
            "total_bytes_dropped": self.total_bytes_dropped,
            "total_traffic_stopped_mb": total_mb,
            "estimated_downtime_prevented_minutes": downtime_estimate,
            "without_airs_message": (
                f"Without A.I.R.S, {self.total_packets_dropped:,} malicious packets "
                f"({total_mb:.1f} MB of attack traffic) would have reached your servers."
                if self.total_packets_dropped > 0
                else "System active — monitoring for threats."
            ),
        }

    def get_status(self) -> Dict:
        return {
            "blocked_count": len(self._blocked_ips),
            "rate_limited_count": len(self._rate_limited_ips),
            "flagged_count": len(self._flagged),
            "total_responses": self.total_responses,
            "total_blocks_ever": self.total_blocks_ever,
            "total_packets_dropped": self.total_packets_dropped,
        }
