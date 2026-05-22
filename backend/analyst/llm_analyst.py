"""
LLM Threat Analyst — A.I.R.S Backend
Uses Anthropic Claude to generate natural-language threat reports.
Falls back to rich template-based reports when API key is unavailable.
"""

import os
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# ─── Mock/Fallback Reports ──────────────────────────────────────────

MOCK_REPORTS: Dict[str, str] = {
    "DDoS": (
        "This traffic exhibits classic volumetric DDoS characteristics with abnormally high "
        "packet rates and byte volume exceeding baseline thresholds by 8-10x. "
        "The pattern maps to T1498 Network Denial of Service targeting the Impact phase "
        "with coordinated multi-source traffic towards a single destination. "
        "Immediate action: implement rate limiting, null-route the source subnet, "
        "and engage upstream ISP for traffic scrubbing."
    ),
    "dos": (
        "High-volume flood traffic detected from a concentrated source, consistent with a "
        "volumetric Denial of Service attack. Packet rate and byte rate far exceed normal "
        "operational baselines, mapping to MITRE T1498 Network Denial of Service. "
        "Recommended action: block source IP immediately and apply rate limiting on "
        "the targeted endpoint to preserve service availability."
    ),
    "PortScan": (
        "Sequential port probing detected consistent with automated reconnaissance tooling "
        "such as Nmap or Masscan. The low bytes-per-packet and high destination port "
        "variance confirm T1046 Network Service Discovery in the Discovery tactic. "
        "Recommended action: block the source IP and increase monitoring on all "
        "exposed services to detect follow-up exploitation attempts."
    ),
    "port_scan": (
        "Systematic multi-port contact pattern detected from a single source — a clear "
        "indicator of automated port scanning. High SYN ratio without corresponding ACK "
        "responses confirms incomplete handshakes typical of Nmap-style SYN scans. "
        "This maps to MITRE T1046 and precedes exploitation. "
        "Block source IP and alert the security team for investigation."
    ),
    "Bot": (
        "Regular beacon intervals with low-volume but highly consistent IAT readings "
        "indicate C2 communication pattern from a compromised host. "
        "This matches T1071 Application Layer Protocol used in the Command and Control tactic. "
        "Isolate the affected endpoint immediately and inspect all outbound connections "
        "from that host for lateral movement indicators."
    ),
    "Brute Force": (
        "High-frequency authentication attempts from a single source targeting a consistent "
        "destination port confirms a credential attack in progress. "
        "T1110 Brute Force maps to the Credential Access tactic — account lockout "
        "policies should trigger immediately. "
        "Block source IP, audit all recent successful logins, and rotate credentials "
        "for affected accounts."
    ),
    "brute_force": (
        "Repeated failed connection attempts targeting an authentication service detected. "
        "High RST count and consistent destination port strongly indicate automated "
        "credential guessing — MITRE T1110 Brute Force, Credential Access tactic. "
        "Immediate response: block source IP, trigger account lockout, "
        "and review authentication logs for any successful logins from this source."
    ),
    "suspicious": (
        "Traffic pattern deviates significantly from the established baseline across "
        "multiple feature dimensions, triggering anomaly detection without matching "
        "a specific known attack signature. This may indicate a novel attack vector "
        "or early-stage reconnaissance. MITRE T1595 Active Scanning, Reconnaissance tactic. "
        "Recommended: flag for enhanced monitoring, correlate with threat intelligence feeds, "
        "and investigate the source host."
    ),
    "Benign": (
        "Traffic pattern is consistent with normal baseline user activity across all "
        "feature dimensions. No anomalous packet rates, IAT irregularities, or suspicious "
        "port targeting detected. No action required — continuing baseline monitoring."
    ),
    "normal": (
        "Traffic pattern is consistent with normal baseline user activity. "
        "All feature values are within expected operational ranges. "
        "No action required."
    ),
}

# Template for generating dynamic fallback reports with real data
_TEMPLATE = """This {attack_type_display} attack was detected with {confidence:.0%} confidence \
against {target_ip} from source {source_ip}. \
The primary indicator is {top_feature} ({top_contribution:.0%} feature contribution), \
mapping to MITRE {technique_id} — {technique_name} ({tactic} tactic). \
{recommended_action}."""


def _build_fallback_report(
    prediction: str,
    confidence: float,
    shap_features: List[Dict],
    mitre_data: Optional[Dict],
    severity_data: Dict,
    source_ip: str = "unknown",
    target_ip: str = "unknown",
) -> str:
    """
    Build a data-filled fallback report when Claude API is unavailable.
    Uses real threat numbers — not hardcoded text.
    """
    # Try to use template with real data
    try:
        top = shap_features[0] if shap_features else {}
        top_feature = top.get("human_label", top.get("feature", "packet rate"))
        top_contribution = top.get("abs_contribution", 0.0)

        attack_display_map = {
            "dos": "DDoS / DoS",
            "ddos": "DDoS",
            "port_scan": "Port Scan",
            "brute_force": "Brute Force",
            "suspicious": "Suspicious Traffic",
            "blocklist": "Blocklisted IP",
        }
        attack_type_display = attack_display_map.get(prediction.lower(), prediction.upper())

        mitre_id = mitre_data.get("technique_id", "T1498") if mitre_data else "T1498"
        mitre_name = mitre_data.get("technique_name", "Network Attack") if mitre_data else "Network Attack"
        tactic = mitre_data.get("tactic", "Impact") if mitre_data else "Impact"
        action = severity_data.get("recommended_action", "Investigate and monitor.")

        return _TEMPLATE.format(
            attack_type_display=attack_type_display,
            confidence=confidence,
            target_ip=target_ip,
            source_ip=source_ip,
            top_feature=top_feature,
            top_contribution=top_contribution,
            technique_id=mitre_id,
            technique_name=mitre_name,
            tactic=tactic,
            recommended_action=action,
        )
    except Exception:
        # Last resort — use static mock
        key = prediction.lower()
        return MOCK_REPORTS.get(key, MOCK_REPORTS.get(prediction, MOCK_REPORTS["suspicious"]))


def generate_threat_report(
    prediction: str,
    confidence: float,
    shap_features: List[Dict],
    mitre_data: Optional[Dict],
    severity_data: Dict,
    source_ip: str = "unknown",
    target_ip: str = "unknown",
) -> str:
    """
    Generate a natural language threat analysis report.

    Primary: Anthropic Claude API (claude-haiku-4-5)
    Fallback: Rich template-based report with real threat data

    Args:
        prediction:    Attack type string (e.g. "dos", "port_scan")
        confidence:    ML confidence (0.0–1.0)
        shap_features: Top SHAP features from shap_explainer
        mitre_data:    MITRE ATT&CK dict from mitre_mapping
        severity_data: Severity dict from severity_scorer
        source_ip:     Source IP of the threat
        target_ip:     Target IP

    Returns:
        Natural language report string. Never raises.
    """
    api_key = os.getenv("ANTHROPIC_API_KEY", "").strip()
    llm_mode = os.getenv("LLM_MODE", "claude").strip().lower()

    if not api_key or llm_mode == "fallback":
        logger.info("[LLM] Using fallback report (no API key or LLM_MODE=fallback).")
        return _build_fallback_report(
            prediction, confidence, shap_features,
            mitre_data, severity_data, source_ip, target_ip,
        )

    # ── Build Claude prompt ──────────────────────────────────────────
    top_features_text = ""
    for i, f in enumerate(shap_features[:3], 1):
        direction = "↑" if f["direction"] == "+" else "↓"
        top_features_text += (
            f"  {i}. {f.get('human_label', f['feature'])}: "
            f"{direction}{f['abs_contribution']:.3f} contribution\n"
        )

    mitre_text = "None"
    if mitre_data:
        mitre_text = (
            f"{mitre_data.get('technique_id')} — "
            f"{mitre_data.get('technique_name')} "
            f"({mitre_data.get('tactic')} tactic)"
        )

    user_prompt = (
        f"Analyze this detected network threat:\n"
        f"  Attack Type: {prediction.upper()}\n"
        f"  Confidence: {confidence:.1%}\n"
        f"  Severity: {severity_data.get('level', 'UNKNOWN')} "
        f"(score: {severity_data.get('score', 0):.0f}/100)\n"
        f"  Source IP: {source_ip} → Target: {target_ip}\n"
        f"  Top Contributing Features:\n{top_features_text}"
        f"  MITRE ATT&CK: {mitre_text}\n\n"
        f"Provide: 1) What this attack is doing, 2) Why these features confirm it, "
        f"3) One specific recommended action."
    )

    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        message = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=300,
            system=(
                "You are a SOC analyst writing threat intelligence reports. "
                "Respond in exactly 3 sentences. Be direct, technical, and actionable. "
                "No preamble, no bullet points."
            ),
            messages=[{"role": "user", "content": user_prompt}],
        )
        report = message.content[0].text.strip()
        logger.info("[LLM] Claude report generated (%d chars).", len(report))
        return report

    except ImportError:
        logger.warning("[LLM] anthropic package not installed — using fallback.")
    except Exception as exc:
        logger.warning("[LLM] Claude API call failed: %s — using fallback.", exc)

    return _build_fallback_report(
        prediction, confidence, shap_features,
        mitre_data, severity_data, source_ip, target_ip,
    )


if __name__ == "__main__":
    # Quick test with fallback (no API key needed)
    result = generate_threat_report(
        prediction="dos",
        confidence=0.94,
        shap_features=[
            {"feature": "packets_per_second", "human_label": "Packet Rate",
             "contribution": 0.42, "abs_contribution": 0.42, "direction": "+"},
            {"feature": "burst_rate", "human_label": "Burst Rate",
             "contribution": 0.28, "abs_contribution": 0.28, "direction": "+"},
        ],
        mitre_data={"technique_id": "T1498", "technique_name": "Network Denial of Service",
                    "tactic": "Impact"},
        severity_data={"level": "CRITICAL", "score": 94, "recommended_action": "Block source IP"},
        source_ip="10.0.0.5",
        target_ip="192.168.1.1",
    )
    print("Report:", result)
