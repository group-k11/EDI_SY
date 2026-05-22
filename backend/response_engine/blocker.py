"""
Active Response Blocker — A.I.R.S Backend
In-memory IP blocking, rate-limiting, and packet drop simulation.
Answers the examiner question: "You detected it — but what did you DO about it?"
"""

import random
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional

# ─── In-Memory State ────────────────────────────────────────────────
_lock = threading.Lock()

# blocked_ips[ip] = {ip, blocked_at, reason, attack_type, packets_blocked, auto_unblock_after}
blocked_ips: Dict[str, Dict] = {}

# rate_limits[ip] = {ip, rate_limit_bps, applied_at}
rate_limits: Dict[str, Dict] = {}

# ─── Core Blocking Functions ─────────────────────────────────────────

def block_ip(
    ip: str,
    reason: str,
    attack_type: str,
    auto_unblock_after: int = 3600,
) -> Dict:
    """
    Block a source IP.

    Args:
        ip:                 IP address string
        reason:             Human-readable block reason
        attack_type:        Detected attack type
        auto_unblock_after: Seconds until auto-unblock (default: 1 hour)

    Returns:
        Block record dict. If already blocked, increments packets_blocked
        and returns existing record with status "already_blocked".
    """
    with _lock:
        if ip in blocked_ips:
            blocked_ips[ip]["packets_blocked"] += 1
            record = blocked_ips[ip].copy()
            record["status"] = "already_blocked"
            return record

        record = {
            "ip":                 ip,
            "blocked_at":         datetime.utcnow().isoformat(),
            "reason":             reason,
            "attack_type":        attack_type,
            "packets_blocked":    0,
            "auto_unblock_after": auto_unblock_after,
            "expires_at": (
                datetime.utcnow() + timedelta(seconds=auto_unblock_after)
            ).isoformat(),
            "status": "blocked",
        }
        blocked_ips[ip] = record
        return record.copy()


def unblock_ip(ip: str) -> bool:
    """
    Manually unblock an IP. Returns True if it was blocked, False otherwise.
    """
    with _lock:
        if ip in blocked_ips:
            del blocked_ips[ip]
            rate_limits.pop(ip, None)
            return True
        return False


def apply_rate_limit(ip: str, limit_bps: int) -> Dict:
    """Apply a rate limit to an IP (in bits per second)."""
    with _lock:
        record = {
            "ip":            ip,
            "rate_limit_bps": limit_bps,
            "applied_at":    datetime.utcnow().isoformat(),
        }
        rate_limits[ip] = record
        return record.copy()


def is_blocked(ip: str) -> bool:
    """O(1) check — whether an IP is currently blocked."""
    return ip in blocked_ips


def get_blocked_list() -> List[Dict]:
    """Return list of all currently blocked IPs."""
    with _lock:
        return list(blocked_ips.values())


def get_stats() -> Dict:
    """Return aggregate response statistics."""
    with _lock:
        total_pkts = sum(r["packets_blocked"] for r in blocked_ips.values())
        return {
            "total_blocked":        len(blocked_ips),
            "total_packets_blocked": total_pkts,
            "active_rate_limits":   len(rate_limits),
        }


def simulate_packet_drop(ip: str) -> Dict:
    """
    Simulate dropping a packet from a blocked IP.
    Increments packets_blocked counter and returns a drop record.
    (In production this would be a firewall rule — here we simulate it.)
    """
    with _lock:
        if ip in blocked_ips:
            blocked_ips[ip]["packets_blocked"] += 1
            return {
                "action": "DROPPED",
                "ip":     ip,
                "reason": blocked_ips[ip]["reason"],
                "total_dropped": blocked_ips[ip]["packets_blocked"],
            }
    return {
        "action": "NOT_BLOCKED",
        "ip":     ip,
        "reason": "IP is not in blocklist",
    }


# ─── Auto Response ───────────────────────────────────────────────────

def auto_respond(
    prediction: str,
    confidence: float,
    source_ip: Optional[str],
    severity_level: str,
) -> Dict:
    """
    Automatically choose and apply a security response based on severity.

    CRITICAL (DDoS high confidence): block + rate limit
    HIGH (Brute Force / DDoS):       block
    MEDIUM (PortScan / Bot):          rate limit only
    LOW / INFO:                       monitor (log only)

    Args:
        prediction:     Attack type string
        confidence:     ML model confidence (0.0–1.0)
        source_ip:      Source IP (generates random private IP if None)
        severity_level: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"

    Returns:
        Dict with action taken and details.
    """
    # Generate random private IP if none provided
    if not source_ip or source_ip in ("unknown", ""):
        source_ip = (
            f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
        )

    level = severity_level.upper()
    attack = prediction.lower()

    # ── CRITICAL: block + rate limit ───────────────────────────────
    if level == "CRITICAL" or (
        attack in ("dos", "ddos") and confidence > 0.9
    ):
        block_record = block_ip(
            ip=source_ip,
            reason=f"CRITICAL {prediction.upper()} — confidence {confidence:.0%}",
            attack_type=prediction,
            auto_unblock_after=3600,
        )
        limit_record = apply_rate_limit(source_ip, limit_bps=1000)
        return {
            "action": "BLOCKED",
            "severity": level,
            "details": {
                "block":      block_record,
                "rate_limit": limit_record,
                "message":    f"⛔ {source_ip} blocked and rate-limited to 1 kbps.",
            },
        }

    # ── HIGH: block only ────────────────────────────────────────────
    if level == "HIGH" or attack in ("brute_force",):
        block_record = block_ip(
            ip=source_ip,
            reason=f"HIGH severity {prediction.upper()} — confidence {confidence:.0%}",
            attack_type=prediction,
            auto_unblock_after=1800,
        )
        return {
            "action": "BLOCKED",
            "severity": level,
            "details": {
                "block":   block_record,
                "message": f"⛔ {source_ip} blocked for 30 minutes.",
            },
        }

    # ── MEDIUM: rate limit only ─────────────────────────────────────
    if level == "MEDIUM" or attack in ("port_scan", "suspicious"):
        limit_record = apply_rate_limit(source_ip, limit_bps=10000)
        return {
            "action": "RATE_LIMITED",
            "severity": level,
            "details": {
                "rate_limit": limit_record,
                "message":    f"⚠️ {source_ip} rate-limited to 10 kbps.",
            },
        }

    # ── LOW / INFO: log only ────────────────────────────────────────
    return {
        "action": "MONITORED",
        "severity": level,
        "details": {
            "message": f"🔵 {source_ip} logged for review — severity too low for active response.",
        },
    }


# ─── Cleanup ─────────────────────────────────────────────────────────

def expire_old_blocks() -> int:
    """Remove expired blocks. Returns count of entries removed."""
    now = datetime.utcnow()
    removed = 0
    with _lock:
        expired = []
        for ip, record in blocked_ips.items():
            try:
                expires = datetime.fromisoformat(record["expires_at"])
                if now > expires:
                    expired.append(ip)
            except Exception:
                pass
        for ip in expired:
            del blocked_ips[ip]
            rate_limits.pop(ip, None)
            removed += 1
    return removed


if __name__ == "__main__":
    print("=== Response Engine Blocker Test ===")
    result = block_ip("192.168.1.100", "DDoS detected", "dos")
    print("Block result:", result)

    print("Blocked list:", get_blocked_list())

    ar = auto_respond("dos", 0.96, "10.0.0.5", "CRITICAL")
    print("Auto respond CRITICAL:", ar["action"], "-", ar["details"]["message"])

    ar2 = auto_respond("port_scan", 0.72, "10.0.0.8", "MEDIUM")
    print("Auto respond MEDIUM:", ar2["action"], "-", ar2["details"]["message"])

    print("Stats:", get_stats())
    print("Drop sim:", simulate_packet_drop("10.0.0.5"))
