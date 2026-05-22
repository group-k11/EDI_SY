"""
Database module — SQLite storage for threat logs and traffic statistics.
Uses aiosqlite for async operations with FastAPI.
"""

import aiosqlite
import os
import json
from datetime import datetime
from typing import List, Dict, Optional

DB_PATH = os.path.join(os.path.dirname(__file__), "ids_database.db")


async def init_db():
    """Initialize database tables."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS threat_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                target_ip TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence REAL NOT NULL,
                packet_count INTEGER DEFAULT 0,
                flow_duration REAL DEFAULT 0.0,
                details TEXT DEFAULT '{}'
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS traffic_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                packets_captured INTEGER DEFAULT 0,
                active_flows INTEGER DEFAULT 0,
                bytes_total INTEGER DEFAULT 0,
                protocols TEXT DEFAULT '{}'
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS ip_list (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                list_type TEXT NOT NULL,
                source TEXT DEFAULT 'manual',
                reason TEXT DEFAULT '',
                expires_at TEXT,
                created_at TEXT NOT NULL
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS ip_intel (
                ip TEXT PRIMARY KEY,
                asn TEXT,
                org TEXT,
                country TEXT,
                region TEXT,
                city TEXT,
                latitude REAL,
                longitude REAL,
                reputation_score REAL,
                sources TEXT DEFAULT '[]',
                last_updated TEXT
            )
        """)
        await db.execute("""
            CREATE INDEX IF NOT EXISTS idx_threat_timestamp ON threat_logs(timestamp)
        """)
        await db.execute("""
            CREATE INDEX IF NOT EXISTS idx_threat_type ON threat_logs(attack_type)
        """)
        await db.execute("""
            CREATE INDEX IF NOT EXISTS idx_ip_list_type ON ip_list(list_type)
        """)
        await db.execute("""
            CREATE INDEX IF NOT EXISTS idx_ip_list_ip ON ip_list(ip)
        """)
        await db.commit()


async def insert_threat(threat: Dict) -> int:
    """Insert a new threat log entry."""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            """INSERT INTO threat_logs 
               (timestamp, source_ip, target_ip, attack_type, severity, confidence, packet_count, flow_duration, details)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                threat.get("timestamp", datetime.now().isoformat()),
                threat.get("source_ip", "unknown"),
                threat.get("target_ip", "unknown"),
                threat.get("attack_type", "unknown"),
                threat.get("severity", "low"),
                threat.get("confidence", 0.0),
                threat.get("packet_count", 0),
                threat.get("flow_duration", 0.0),
                json.dumps(threat.get("details", {})),
            ),
        )
        await db.commit()
        return cursor.lastrowid or 0


async def get_threats(limit: int = 100, attack_type: Optional[str] = None) -> List[Dict]:
    """Retrieve threat logs, optionally filtered by attack type."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        if attack_type:
            cursor = await db.execute(
                "SELECT * FROM threat_logs WHERE attack_type = ? ORDER BY timestamp DESC LIMIT ?",
                (attack_type, limit),
            )
        else:
            cursor = await db.execute(
                "SELECT * FROM threat_logs ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]


async def get_threat_summary() -> Dict:
    """Get summary statistics of threats."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        # Total threats
        cursor = await db.execute("SELECT COUNT(*) as total FROM threat_logs")
        row_total = await cursor.fetchone()
        total = row_total["total"] if row_total else 0

        # By severity
        cursor = await db.execute(
            "SELECT severity, COUNT(*) as count FROM threat_logs GROUP BY severity"
        )
        severity_counts = {row["severity"]: row["count"] for row in await cursor.fetchall()}

        # By attack type
        cursor = await db.execute(
            "SELECT attack_type, COUNT(*) as count FROM threat_logs GROUP BY attack_type"
        )
        type_counts = {row["attack_type"]: row["count"] for row in await cursor.fetchall()}

        # Recent threats (last 24 hours)
        cursor = await db.execute(
            "SELECT COUNT(*) as recent FROM threat_logs WHERE timestamp > datetime('now', '-1 day')"
        )
        row_recent = await cursor.fetchone()
        recent = row_recent["recent"] if row_recent else 0

        return {
            "total_threats": total,
            "recent_threats_24h": recent,
            "by_severity": severity_counts,
            "by_attack_type": type_counts,
        }


async def get_network_map() -> List[Dict]:
    """Get attacker-target relationships for network graph."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("""
            WITH ranked AS (
                SELECT source_ip, target_ip, attack_type, severity,
                       COUNT(*) as connection_count,
                       AVG(confidence) as avg_confidence,
                       ROW_NUMBER() OVER (
                           PARTITION BY source_ip, target_ip
                           ORDER BY COUNT(*) DESC, AVG(confidence) DESC
                       ) as rn
                FROM threat_logs
                GROUP BY source_ip, target_ip, attack_type, severity
            )
            SELECT source_ip, target_ip, attack_type, severity,
                   connection_count, avg_confidence
            FROM ranked
            WHERE rn = 1
            ORDER BY connection_count DESC
            LIMIT 50
        """)
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]


async def insert_traffic_stats(stats: Dict):
    """Log traffic statistics snapshot."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """INSERT INTO traffic_stats (timestamp, packets_captured, active_flows, bytes_total, protocols)
               VALUES (?, ?, ?, ?, ?)""",
            (
                datetime.now().isoformat(),
                stats.get("packets_captured", 0),
                stats.get("active_flows", 0),
                stats.get("bytes_total", 0),
                json.dumps(stats.get("protocols", {})),
            ),
        )
        await db.commit()


async def get_ip_list_summary() -> Dict:
    """Return summary counts for blocklist and allowlist entries."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT list_type, COUNT(*) as count FROM ip_list GROUP BY list_type"
        )
        rows = await cursor.fetchall()
        summary = {row["list_type"]: row["count"] for row in rows}
        return {
            "blocklist": summary.get("blocklist", 0),
            "allowlist": summary.get("allowlist", 0),
        }


async def add_ip_list_entry(entry: Dict) -> int:
    """Add a block/allow list entry."""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            """INSERT INTO ip_list (ip, list_type, source, reason, expires_at, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                entry.get("ip"),
                entry.get("list_type"),
                entry.get("source", "manual"),
                entry.get("reason", ""),
                entry.get("expires_at"),
                datetime.utcnow().isoformat(),
            ),
        )
        await db.commit()
        return cursor.lastrowid or 0


async def list_ip_list(list_type: str, limit: int = 200, search: Optional[str] = None) -> List[Dict]:
    """List block/allow list entries."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        if search:
            cursor = await db.execute(
                """SELECT * FROM ip_list WHERE list_type = ? AND ip LIKE ?
                   ORDER BY created_at DESC LIMIT ?""",
                (list_type, f"%{search}%", limit),
            )
        else:
            cursor = await db.execute(
                """SELECT * FROM ip_list WHERE list_type = ?
                   ORDER BY created_at DESC LIMIT ?""",
                (list_type, limit),
            )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]


async def delete_ip_list_entry(entry_id: int) -> None:
    """Remove an entry from the block/allow list."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM ip_list WHERE id = ?", (entry_id,))
        await db.commit()


async def clear_ip_list_source(list_type: str, source: str) -> None:
    """Remove all entries for a list type and source (used for feed refresh)."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "DELETE FROM ip_list WHERE list_type = ? AND source = ?",
            (list_type, source),
        )
        await db.commit()


async def upsert_ip_intel(intel: Dict) -> None:
    """Insert or update IP intelligence record."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """INSERT INTO ip_intel (ip, asn, org, country, region, city, latitude, longitude,
                                    reputation_score, sources, last_updated)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(ip) DO UPDATE SET
                 asn = excluded.asn,
                 org = excluded.org,
                 country = excluded.country,
                 region = excluded.region,
                 city = excluded.city,
                 latitude = excluded.latitude,
                 longitude = excluded.longitude,
                 reputation_score = excluded.reputation_score,
                 sources = excluded.sources,
                 last_updated = excluded.last_updated
            """,
            (
                intel.get("ip"),
                intel.get("asn"),
                intel.get("org"),
                intel.get("country"),
                intel.get("region"),
                intel.get("city"),
                intel.get("latitude"),
                intel.get("longitude"),
                intel.get("reputation_score"),
                intel.get("sources", "[]"),
                intel.get("last_updated"),
            ),
        )
        await db.commit()


async def get_ip_intel(ip_value: str) -> Optional[Dict]:
    """Get IP intelligence data."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM ip_intel WHERE ip = ?", (ip_value,))
        row = await cursor.fetchone()
        return dict(row) if row else None
