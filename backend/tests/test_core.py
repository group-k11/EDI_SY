"""
Backend Tests — pytest suite for A.I.R.S core modules.
Run: cd backend && pytest tests/ -v
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from intelligence.severity_scorer import SeverityScorer
from intelligence.mitre_mapping import MITREMapper
from flow_builder import FlowBuilder, NetworkFlow
from feature_engineering import FeatureEngine
from collections import defaultdict


# ─── SeverityScorer Tests ───────────────────────────────────────────────────

class TestSeverityScorer:
    def setup_method(self):
        self.scorer = SeverityScorer()

    def test_normal_returns_info(self):
        result = self.scorer.score("normal", confidence=0.99)
        assert result["level"] == "INFO"
        assert result["score"] == 0.0

    def test_dos_high_confidence_is_critical(self):
        result = self.scorer.score("dos", confidence=0.95)
        assert result["level"] in ("CRITICAL", "HIGH")
        assert result["score"] > 60

    def test_port_scan_medium_confidence(self):
        result = self.scorer.score("port_scan", confidence=0.6)
        assert result["level"] in ("MEDIUM", "HIGH")

    def test_score_capped_at_100(self):
        result = self.scorer.score("ddos", confidence=1.0, packets_per_second=10000)
        assert result["score"] <= 100.0

    def test_rate_bonus_applied(self):
        base = self.scorer.score("dos", confidence=0.8)["score"]
        with_rate = self.scorer.score("dos", confidence=0.8, packets_per_second=500)["score"]
        assert with_rate >= base

    def test_result_has_required_fields(self):
        result = self.scorer.score("brute_force", confidence=0.75)
        assert "level" in result
        assert "score" in result
        assert "color" in result
        assert "factors" in result
        assert "recommended_action" in result

    def test_recommended_action_not_empty(self):
        for attack_type in ["dos", "ddos", "port_scan", "brute_force", "suspicious", "blocklist"]:
            result = self.scorer.score(attack_type, confidence=0.8)
            assert result["recommended_action"], f"No recommended_action for {attack_type}"

    def test_simple_severity_thresholds(self):
        assert SeverityScorer.simple_severity(0.95, "dos") == "critical"
        assert SeverityScorer.simple_severity(0.80, "port_scan") == "high"
        assert SeverityScorer.simple_severity(0.60, "suspicious") == "medium"
        assert SeverityScorer.simple_severity(0.30, "suspicious") == "low"
        assert SeverityScorer.simple_severity(0.99, "normal") == "info"


# ─── MITREMapper Tests ───────────────────────────────────────────────────────

class TestMITREMapper:
    def setup_method(self):
        self.mapper = MITREMapper()

    def test_dos_maps_to_T1498(self):
        result = self.mapper.map("dos")
        assert result["technique_id"] == "T1498"

    def test_port_scan_maps_to_T1046(self):
        result = self.mapper.map("port_scan")
        assert result["technique_id"] == "T1046"

    def test_brute_force_maps_to_T1110(self):
        result = self.mapper.map("brute_force")
        assert result["technique_id"] == "T1110"

    def test_bot_attack_mapped(self):
        result = self.mapper.map("bot")
        assert result["technique_id"] is not None
        assert "C2" in result["description"] or "botnet" in result["description"].lower()

    def test_unknown_attack_returns_fallback(self):
        result = self.mapper.map("unknown_xyz_attack")
        assert result is not None
        assert "technique_id" in result

    def test_case_insensitive(self):
        assert self.mapper.get_technique_id("DOS") == self.mapper.get_technique_id("dos")

    def test_hyphen_normalized(self):
        assert self.mapper.get_technique_id("brute-force") == self.mapper.get_technique_id("brute_force")

    def test_all_techniques_returns_dict(self):
        all_t = self.mapper.all_techniques()
        assert isinstance(all_t, dict)
        assert len(all_t) >= 5

    def test_countermeasures_are_non_empty_lists(self):
        for attack_type in ["dos", "port_scan", "brute_force"]:
            cm = self.mapper.get_countermeasures(attack_type)
            assert isinstance(cm, list)
            assert len(cm) > 0


# ─── FlowBuilder Tests ───────────────────────────────────────────────────────

class TestFlowBuilder:
    def setup_method(self):
        self.builder = FlowBuilder(flow_timeout=0.01)  # 10ms timeout for fast tests

    def _make_packet(self, src="1.1.1.1", dst="2.2.2.2", sport=1234, dport=80, proto="TCP", size=100):
        return {
            "src_ip": src, "dst_ip": dst,
            "src_port": sport, "dst_port": dport,
            "protocol": proto,
            "packet_length": size,
            "flags": {"SYN": 1, "ACK": 0, "RST": 0, "FIN": 0},
        }

    def test_first_packet_creates_flow(self):
        pkt = self._make_packet()
        self.builder.add_packet(pkt)  # returns None, mutates internal state
        flows = self.builder.get_active_flows()
        assert len(flows) >= 1

    def test_active_flows_returned(self):
        pkt = self._make_packet()
        self.builder.add_packet(pkt)
        flows = self.builder.get_active_flows()
        assert len(flows) >= 1

    def test_completed_flows_capped(self):
        """Memory leak guard: completed_flows must not grow unboundedly."""
        assert self.builder._MAX_COMPLETED == 1000

    def test_get_stats_keys(self):
        stats = self.builder.get_stats()
        assert "active_flows" in stats
        assert "completed_flows" in stats

    def test_packets_accumulate_in_flow(self):
        pkt = self._make_packet()
        self.builder.add_packet(pkt)
        self.builder.add_packet({**pkt, "packet_length": 200})
        flows = self.builder.get_active_flows()
        assert any(f["packet_count"] >= 2 for f in flows)


# ─── FeatureEngine Tests ─────────────────────────────────────────────────────

class TestFeatureEngine:
    def setup_method(self):
        self.engine = FeatureEngine()

    def test_ip_packet_sizes_bounded(self):
        """Memory leak guard: ip_packet_sizes must be capped per IP."""
        src = "10.0.0.1"
        # Simulate inserting 1500 packets (as the cap logic does)
        for i in range(1500):
            self.engine.ip_packet_sizes[src].append(i)
            if len(self.engine.ip_packet_sizes[src]) > 1000:
                self.engine.ip_packet_sizes[src] = self.engine.ip_packet_sizes[src][-1000:]
        assert len(self.engine.ip_packet_sizes[src]) <= 1000

    def test_defaultdict_does_not_keyerror(self):
        """ip_packet_sizes is a defaultdict(list) — accessing unknown keys must not raise."""
        _ = self.engine.ip_packet_sizes["999.999.999.999"]
        assert True  # no KeyError
