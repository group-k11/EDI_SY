"""
Threat Engine — Combines ML predictions with rule-based heuristic detection.
Produces threat events with attack_type, severity, confidence, and metadata.
"""

import time
from datetime import datetime
from typing import Dict, List, Optional


# Rule thresholds (adjusted for demo mode)
RULES = {
    "port_scan": {
        "unique_ports_min": 5,      # Lowered from 10
        "connection_rate_min": 1.0,  # Lowered from 3.0
        "syn_ratio_min": 0.4,        # Lowered from 0.6
    },
    "dos": {
        "packets_per_second_min": 20,   # Lowered from 50
        "burst_rate_min": 15,            # Lowered from 30
        "byte_rate_min": 5000,           # Lowered from 10000
    },
    "brute_force": {
        "failed_connections_min": 3,     # Lowered from 5
        "connection_rate_min": 1.0,      # Lowered from 3.0
        "unique_ports_max": 3,
    },
}


def _severity_from_confidence(confidence: float, attack_type: str) -> str:
    """Determine severity level from confidence score and attack type."""
    if attack_type == "normal":
        return "info"
    if confidence >= 0.9:
        return "critical"
    if confidence >= 0.75:
        return "high"
    if confidence >= 0.5:
        return "medium"
    return "low"


class ThreatEngine:
    """Combined ML + rule-based threat detection engine."""

    def __init__(self):
        self.recent_threats: List[Dict] = []
        self._max_recent = 200
        self.threat_count = 0
        self.base_ml_threshold = 0.6
        self.ml_confidence_threshold = 0.6
        self.drift_score: Optional[float] = None
        self.drift_level = "unknown"
        self._intel = None

    def set_intel(self, intel) -> None:
        self._intel = intel

    def update_drift(self, drift_status: Dict) -> None:
        """Update adaptive ML confidence threshold using drift status."""
        if not drift_status:
            return

        self.drift_score = drift_status.get("psi_avg")
        self.drift_level = drift_status.get("drift_level", "unknown")

        if self.drift_score is None:
            self.ml_confidence_threshold = self.base_ml_threshold
            return

        # Increase threshold as drift increases to reduce false positives.
        adjustment = min(0.2, float(self.drift_score) * 0.5)
        self.ml_confidence_threshold = min(0.9, max(0.4, self.base_ml_threshold + adjustment))

    def _apply_rules(self, features: Dict) -> Optional[Dict]:
        """Apply rule-based detection. Returns a rule match or None."""
        import random

        # Port scan rule
        r = RULES["port_scan"]
        if (
            features.get("unique_ports_contacted", 0) >= r["unique_ports_min"]
            and features.get("connection_rate", 0) >= r["connection_rate_min"]
            and features.get("syn_packet_ratio", 0) >= r["syn_ratio_min"]
        ):
            # Vary confidence based on severity
            base_conf = 0.85
            variation = random.uniform(-0.10, 0.10)
            return {
                "attack_type": "port_scan",
                "rule_confidence": round(min(0.99, max(0.65, base_conf + variation)), 4),
                "rule_name": "rapid_multi_port_contact",
            }

        # DoS rule
        r = RULES["dos"]
        if (
            features.get("packets_per_second", 0) >= r["packets_per_second_min"]
            or features.get("burst_rate", 0) >= r["burst_rate_min"]
        ) and features.get("bytes_per_second", 0) >= r["byte_rate_min"]:
            base_conf = 0.88
            variation = random.uniform(-0.12, 0.08)
            return {
                "attack_type": "dos",
                "rule_confidence": round(min(0.99, max(0.70, base_conf + variation)), 4),
                "rule_name": "high_packet_rate",
            }

        # Brute force rule
        r = RULES["brute_force"]
        if (
            features.get("failed_connection_attempts", 0) >= r["failed_connections_min"]
            and features.get("connection_rate", 0) >= r["connection_rate_min"]
            and features.get("unique_ports_contacted", 0) <= r["unique_ports_max"]
        ):
            base_conf = 0.82
            variation = random.uniform(-0.15, 0.12)
            return {
                "attack_type": "brute_force",
                "rule_confidence": round(min(0.99, max(0.60, base_conf + variation)), 4),
                "rule_name": "repeated_failed_connections",
            }

        return None

    def analyze(self, features: Dict, ml_result: Dict) -> Optional[Dict]:
        """
        Combine ML prediction with rule-based analysis.
        Returns a threat event if an attack is detected, or None.
        """
        ml_attack = ml_result.get("attack_type", "normal")
        ml_confidence = ml_result.get("confidence", 0.0)
        is_anomaly = ml_result.get("is_anomaly", False)
        source_ip = features.get("source_ip", "unknown")
        target_ip = features.get("destination_ip", "unknown")

        ml_threshold = self.ml_confidence_threshold

        intel_status = None
        allowlisted = False
        if self._intel:
            intel_status = self._intel.check_ip(source_ip)
            allowlisted = intel_status.get("status") == "allow"

        rule_match = self._apply_rules(features)

        # Decision logic
        attack_type = "normal"
        confidence = 0.0
        detection_method = "none"

        if ml_attack != "normal" and ml_confidence >= ml_threshold:
            attack_type = ml_attack
            confidence = ml_confidence
            detection_method = "ml"

        if rule_match:
            if rule_match["attack_type"] == ml_attack:
                # ML + rule agree: boost confidence
                confidence = min(confidence + 0.15, 0.99)
                detection_method = "ml+rule"
            elif attack_type == "normal":
                # Only rule triggered
                attack_type = rule_match["attack_type"]
                confidence = rule_match["rule_confidence"]
                detection_method = "rule"

        if attack_type == "normal" and is_anomaly:
            attack_type = "suspicious"
            confidence = max(0.5, 1.0 - abs(ml_result.get("anomaly_score", 0)))
            detection_method = "anomaly"

        if attack_type == "normal" and not allowlisted and intel_status and intel_status.get("status") == "block":
            attack_type = "blocklist"
            confidence = 0.95
            detection_method = "blocklist"

        # Skip normal traffic
        if attack_type == "normal":
            return None

        # Build threat event
        threat = {
            "attack_type": attack_type,
            "source_ip": source_ip,
            "target_ip": target_ip,
            "severity": _severity_from_confidence(confidence, attack_type),
            "confidence": round(confidence, 4),
            "timestamp": datetime.now().isoformat(),
            "detection_method": detection_method,
            "details": {
                "packet_count": features.get("packet_count", 0),
                "flow_duration": round(features.get("flow_duration", 0), 4),
                "packets_per_second": round(features.get("packets_per_second", 0), 2),
                "unique_ports": features.get("unique_ports_contacted", 0),
                "anomaly_score": ml_result.get("anomaly_score", 0),
                "ml_confidence_threshold": round(ml_threshold, 4),
                "drift_score": None if self.drift_score is None else round(self.drift_score, 4),
                "intel_status": intel_status,
            },
        }

        self.recent_threats.append(threat)
        if len(self.recent_threats) > self._max_recent:
            self.recent_threats = self.recent_threats[-self._max_recent:]
        self.threat_count += 1

        return threat

    def analyze_batch(self, features_list: List[Dict], ml_results: List[Dict]) -> List[Dict]:
        """Analyze a batch of flows. Returns list of detected threats."""
        threats = []
        for features, ml_result in zip(features_list, ml_results):
            threat = self.analyze(features, ml_result)
            if threat:
                threats.append(threat)
        return threats

    def get_recent_threats(self, limit: int = 50) -> List[Dict]:
        return self.recent_threats[-limit:]

    def get_stats(self) -> Dict:
        return {
            "total_threats_detected": self.threat_count,
            "recent_threats": len(self.recent_threats),
            "ml_confidence_threshold": round(self.ml_confidence_threshold, 4),
            "drift_score": None if self.drift_score is None else round(self.drift_score, 4),
            "drift_level": self.drift_level,
        }
