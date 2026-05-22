"""
Threat Intel -- IP reputation feeds, block/allow list management, and IP enrichment.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import urllib.request
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from database import (
    add_ip_list_entry,
    clear_ip_list_source,
    get_ip_intel,
    list_ip_list,
    upsert_ip_intel,
)


class ThreatIntel:
    """Manage IP reputation feeds and enrichment."""

    def __init__(self) -> None:
        self._allow_networks: List[Tuple[ipaddress._BaseNetwork, Dict]] = []
        self._block_networks: List[Tuple[ipaddress._BaseNetwork, Dict]] = []
        self._last_refresh: Optional[datetime] = None
        self._feed_urls = self._read_feed_urls()
        self._enrich_ttl = timedelta(days=7)

    async def refresh_from_db(self) -> None:
        allow_entries = await list_ip_list("allowlist", limit=5000, search=None)
        block_entries = await list_ip_list("blocklist", limit=10000, search=None)
        self._allow_networks = self._build_networks(allow_entries)
        self._block_networks = self._build_networks(block_entries)
        self._last_refresh = datetime.utcnow()

    async def refresh_feeds(self) -> Dict:
        """Refresh blocklist feeds from configured URLs."""
        if not self._feed_urls:
            return {"status": "skipped", "reason": "no_feed_urls"}

        total_added = 0
        for url in self._feed_urls:
            raw = await asyncio.to_thread(self._fetch_text, url)
            entries = self._parse_feed(raw)
            await clear_ip_list_source("blocklist", url)
            for entry in entries:
                await add_ip_list_entry({
                    "ip": entry,
                    "list_type": "blocklist",
                    "source": url,
                    "reason": "reputation_feed",
                    "expires_at": None,
                })
            total_added += len(entries)

        await self.refresh_from_db()
        return {"status": "ok", "feeds": len(self._feed_urls), "entries_added": total_added}

    def check_ip(self, ip_value: str) -> Dict:
        """Return list match for an IP if present."""
        try:
            ip_obj = ipaddress.ip_address(ip_value)
        except ValueError:
            return {"status": "invalid"}

        for net, meta in self._allow_networks:
            if ip_obj in net:
                return {"status": "allow", "entry": meta}

        for net, meta in self._block_networks:
            if ip_obj in net:
                return {"status": "block", "entry": meta}

        return {"status": "none"}

    async def enrich_ip(self, ip_value: str) -> Optional[Dict]:
        """Return cached enrichment or fetch from external source if stale."""
        if not ip_value or ip_value == "unknown":
            return None

        cached = await get_ip_intel(ip_value)
        if cached and not self._is_stale(cached.get("last_updated")):
            return cached

        data = await asyncio.to_thread(self._fetch_ipapi, ip_value)
        if not data:
            return cached

        await upsert_ip_intel(data)
        return data

    async def enrich_threats(self, threats: List[Dict]) -> None:
        ips = set()
        for threat in threats:
            src = threat.get("source_ip")
            tgt = threat.get("target_ip")
            if src:
                ips.add(src)
            if tgt:
                ips.add(tgt)

        tasks = {ip: asyncio.create_task(self.enrich_ip(ip)) for ip in ips}
        results = {ip: await task for ip, task in tasks.items()}

        for threat in threats:
            src = threat.get("source_ip")
            tgt = threat.get("target_ip")
            src_intel = results.get(src)
            tgt_intel = results.get(tgt)
            if src_intel or tgt_intel:
                details = threat.setdefault("details", {})
                details["source_intel"] = src_intel
                details["target_intel"] = tgt_intel

    def get_stats(self) -> Dict:
        return {
            "allowlist_count": len(self._allow_networks),
            "blocklist_count": len(self._block_networks),
            "last_refresh": self._last_refresh.isoformat() if self._last_refresh else None,
        }

    def _build_networks(self, entries: List[Dict]) -> List[Tuple[ipaddress._BaseNetwork, Dict]]:
        networks: List[Tuple[ipaddress._BaseNetwork, Dict]] = []
        for entry in entries:
            try:
                net = ipaddress.ip_network(entry.get("ip"), strict=False)
            except ValueError:
                continue
            networks.append((net, entry))
        return networks

    def _read_feed_urls(self) -> List[str]:
        raw = os.getenv("THREAT_FEED_URLS", "")
        return [u.strip() for u in raw.split(",") if u.strip()]

    def _fetch_text(self, url: str) -> str:
        with urllib.request.urlopen(url, timeout=10) as resp:
            return resp.read().decode("utf-8", errors="ignore")

    def _parse_feed(self, raw: str) -> List[str]:
        entries: List[str] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            line = re.split(r"\s+#", line)[0].strip()
            if self._looks_like_ip_or_cidr(line):
                entries.append(line)
        return entries

    def _looks_like_ip_or_cidr(self, value: str) -> bool:
        try:
            ipaddress.ip_network(value, strict=False)
            return True
        except ValueError:
            return False

    def _fetch_ipapi(self, ip_value: str) -> Optional[Dict]:
        url = f"https://ipapi.co/{ip_value}/json/"
        try:
            with urllib.request.urlopen(url, timeout=8) as resp:
                raw = resp.read().decode("utf-8", errors="ignore")
            payload = json.loads(raw)
        except Exception:
            return None

        if payload.get("error"):
            return None

        return {
            "ip": ip_value,
            "asn": payload.get("asn"),
            "org": payload.get("org"),
            "country": payload.get("country_name"),
            "region": payload.get("region"),
            "city": payload.get("city"),
            "latitude": payload.get("latitude"),
            "longitude": payload.get("longitude"),
            "reputation_score": None,
            "sources": json.dumps(["ipapi"]),
            "last_updated": datetime.utcnow().isoformat(),
        }

    def _is_stale(self, last_updated: Optional[str]) -> bool:
        if not last_updated:
            return True
        try:
            ts = datetime.fromisoformat(last_updated)
        except ValueError:
            return True
        return datetime.utcnow() - ts > self._enrich_ttl
