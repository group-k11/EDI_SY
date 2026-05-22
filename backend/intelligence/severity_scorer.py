"""
Severity Scorer — Multi-factor threat severity scoring engine.
Replaces the single-line _severity_from_confidence() in threat_engine.py
with a rich, explainable scoring model.

Scoring formula:
    base_score      = confidence × 100                    (0–100)
    type_mult       = attack type weight                  (1.0–1.5)
    mitre_weight    = MITRE tactic severity weight        (0.9–1.4)
    rate_bonus      = min(20, packets_per_second / 50)   (0–20)
    final_score     = (base_score × type_mult × mitre_weight) + rate_bonus

Thresholds:
    CRITICAL  ≥ 80
    HIGH      ≥ 60
    MEDIUM    ≥ 35
    LOW       < 35
"""

from typing import Dict, List, Optional


# ─── Weight Tables ─────────────────────────────────────────────────

# Attack type multipliers — more dangerous = higher weight
_ATTACK_TYPE_WEIGHTS: Dict[str, float] = {
    "dos":         1.5,
    "ddos":        1.5,
    "brute_force": 1.2,
    "blocklist":   1.3,
    "port_scan":   1.0,
    "suspicious":  0.8,
    "normal":      0.0,
}

# MITRE tactic severity weights — tactical impact hierarchy
_TACTIC_WEIGHTS: Dict[str, float] = {
    "Impact":             1.4,   # Direct damage
    "Credential Access":  1.2,   # Account compromise
    "Command and Control":1.3,   # Active C2 link
    "Lateral Movement":   1.3,   # Network spread
    "Exfiltration":       1.4,   # Data theft
    "Execution":          1.2,   # Code running
    "Persistence":        1.1,   # Long-term foothold
    "Privilege Escalation":1.2,  # Elevated access
    "Defense Evasion":    1.1,   # Hiding activity
    "Discovery":          1.0,   # Reconnaissance
    "Reconnaissance":     0.9,   # Early stage
    "Resource Development":0.8,  # Preparation
    "Collection":         1.1,   # Data gathering
}

# Level thresholds
_THRESHOLDS = [
    (80.0, "CRITICAL"),
    (60.0, "HIGH"),
    (35.0, "MEDIUM"),
    (0.0,  "LOW"),
]

# Level colors (for frontend badge rendering)
LEVEL_COLORS = {
    "CRITICAL": "#ef4444",
    "HIGH":     "#f97316",
    "MEDIUM":   "#f59e0b",
    "LOW":      "#3b82f6",
}

# Recommended actions per attack type
_RECOMMENDED_ACTIONS: Dict[str, str] = {
    "dos":         "Block source IP immediately + Apply rate limiting on target endpoint",
    "ddos":        "Block source IP range + Engage upstream ISP for traffic scrubbing",
    "port_scan":   "Block source IP + Audit exposed services + Enable honeypot alerts",
    "brute_force": "Block source IP + Trigger account lockout + Audit recent logins",
    "suspicious":  "Flag for enhanced monitoring + Correlate with threat intelligence",
    "blocklist":   "Block at perimeter + Investigate if internal hosts contacted this IP",
    "bot":         "Block source IP + Investigate botnet C2 infrastructure + Check internal hosts",
    "normal":      "No action required — continue baseline monitoring",
}


# ─── SeverityScorer ────────────────────────────────────────────────

class SeverityScorer:
    """
    Multi-factor severity scoring engine.
    Takes ML confidence, attack type, MITRE tactic, and packet rate
    to compute a 0–100 score with an explainable breakdown.
    """

    def score(
        self,
        attack_type: str,
        confidence: float,
        mitre_tactic: str = "Discovery",
        packets_per_second: float = 0.0,
        features: Optional[Dict] = None,
    ) -> Dict:
        """
        Compute severity score and level.

        Args:
            attack_type: Detected attack class (e.g. "dos", "port_scan")
            confidence: ML confidence score (0.0–1.0)
            mitre_tactic: MITRE tactic name (e.g. "Impact")
            packets_per_second: Flow packet rate for volumetric bonus
            features: Full feature dict (optional, for additional context)

        Returns:
            {level, score, color, factors}
        """
        if attack_type == "normal":
            return {
                "level": "INFO",
                "score": 0.0,
                "color": "#94a3b8",
                "factors": [],
            }

        # ── Factor 1: Base confidence score
        base_score = round(confidence * 100, 2)

        # ── Factor 2: Attack type multiplier
        type_mult = _ATTACK_TYPE_WEIGHTS.get(
            attack_type.lower().replace("-", "_"), 1.0
        )
        type_contribution = round(base_score * (type_mult - 1.0), 2)

        # ── Factor 3: MITRE tactic weight
        mitre_weight = _TACTIC_WEIGHTS.get(mitre_tactic, 1.0)
        after_mitre = round(base_score * type_mult * mitre_weight, 2)
        mitre_contribution = round(after_mitre - base_score * type_mult, 2)

        # ── Factor 4: Volumetric rate bonus (capped at +20)
        rate_bonus = round(min(20.0, packets_per_second / 50.0), 2)

        # ── Final score (capped at 100)
        raw_score = after_mitre + rate_bonus
        final_score = round(min(100.0, raw_score), 2)

        # ── Determine level
        level = "LOW"
        for threshold, label in _THRESHOLDS:
            if final_score >= threshold:
                level = label
                break

        # ── Build explainable factors breakdown
        factors: List[Dict] = [
            {
                "name": "ML Confidence",
                "value": f"{confidence:.0%}",
                "contribution": base_score,
                "description": f"Model confidence: {confidence:.1%}",
            },
            {
                "name": "Attack Type",
                "value": attack_type.upper(),
                "contribution": round(type_contribution, 2),
                "description": f"Type weight: {type_mult}×",
            },
            {
                "name": "MITRE Tactic",
                "value": mitre_tactic,
                "contribution": round(mitre_contribution, 2),
                "description": f"Tactic weight: {mitre_weight}×",
            },
        ]

        if rate_bonus > 0:
            factors.append({
                "name": "Packet Rate",
                "value": f"{packets_per_second:.0f} pkt/s",
                "contribution": rate_bonus,
                "description": f"Volumetric bonus: +{rate_bonus:.1f} pts",
            })

        return {
            "level": level,
            "score": final_score,
            "color": LEVEL_COLORS.get(level, "#94a3b8"),
            "factors": factors,
            "recommended_action": _RECOMMENDED_ACTIONS.get(attack_type.lower(), "Investigate and monitor activity"),
        }

    def level_from_score(self, score: float) -> str:
        """Convert numeric score to level string."""
        for threshold, label in _THRESHOLDS:
            if score >= threshold:
                return label
        return "LOW"

    @staticmethod
    def simple_severity(confidence: float, attack_type: str) -> str:
        """
        Drop-in replacement for threat_engine._severity_from_confidence().
        Returns a simple level string without full scoring breakdown.
        Used in background loop where full scoring is not needed.
        """
        if attack_type == "normal":
            return "info"
        if confidence >= 0.9:
            return "critical"
        if confidence >= 0.75:
            return "high"
        if confidence >= 0.5:
            return "medium"
        return "low"
