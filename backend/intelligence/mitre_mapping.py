"""
MITRE ATT&CK Mapping — Maps detected attack types to MITRE ATT&CK framework.
Pure Python dictionary lookup — no external calls, no dependencies.
"""

from typing import Dict, Optional


# ─── MITRE ATT&CK Technique Database ──────────────────────────────

_TECHNIQUE_DB: Dict[str, Dict] = {
    "dos": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "sub_technique_id": "T1498.001",
        "sub_technique_name": "Direct Network Flood",
        "description": (
            "Adversaries may attempt to cause a denial of service (DoS) by sending "
            "high volumes of network traffic to a target. This exhausts the target's "
            "bandwidth or processing capacity, making it unavailable to legitimate users."
        ),
        "reference_url": "https://attack.mitre.org/techniques/T1498",
        "severity_weight": 1.5,
        "indicators": [
            "High packet rate from single or multiple sources",
            "Abnormally short flow durations",
            "High SYN flag ratio without corresponding ACK",
            "Large byte volume concentrated on specific ports",
        ],
        "typical_targets": ["Web servers", "DNS infrastructure", "Load balancers"],
        "countermeasures": [
            "Rate limiting on ingress interfaces",
            "Upstream traffic scrubbing / CDN-level filtering",
            "BCP38 network ingress filtering",
            "Anycast-based DDoS mitigation",
        ],
    },

    "ddos": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "sub_technique_id": "T1498.001",
        "sub_technique_name": "Direct Network Flood",
        "description": (
            "Distributed Denial of Service attack using multiple coordinated sources "
            "to overwhelm a target's network capacity. Traffic originates from a botnet "
            "or amplification infrastructure."
        ),
        "reference_url": "https://attack.mitre.org/techniques/T1498",
        "severity_weight": 1.5,
        "indicators": [
            "Multiple source IPs targeting single destination",
            "Coordinated high-volume traffic bursts",
            "Traffic from geographically distributed sources",
            "Uniform packet sizes (amplification indicator)",
        ],
        "typical_targets": ["Web services", "Game servers", "Financial platforms"],
        "countermeasures": [
            "Block source IP ranges at perimeter",
            "Apply rate limits per source IP",
            "Engage upstream ISP for traffic null-routing",
            "Enable DDoS protection service",
        ],
    },

    "port_scan": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "sub_technique_id": None,
        "sub_technique_name": None,
        "description": (
            "Adversaries probe a target network to enumerate running services and open ports. "
            "This reconnaissance phase identifies attack vectors before exploitation. "
            "Common tools include Nmap, Masscan, and Zmap."
        ),
        "reference_url": "https://attack.mitre.org/techniques/T1046",
        "severity_weight": 1.0,
        "indicators": [
            "Single source contacting many destination ports",
            "High SYN packet ratio without completing handshakes",
            "Short flow durations per connection",
            "Sequential or random port progression patterns",
        ],
        "typical_targets": ["Entire network ranges", "Specific hosts prior to exploitation"],
        "countermeasures": [
            "Block source IP in firewall",
            "Enable port scan detection in IDS/IPS",
            "Use honeypot ports to detect scanners early",
            "Alert SOC for follow-up investigation",
        ],
    },

    "brute_force": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "sub_technique_id": "T1110.001",
        "sub_technique_name": "Password Guessing",
        "description": (
            "Adversaries attempt to gain access by systematically guessing credentials. "
            "Common targets are SSH (port 22), RDP (port 3389), and database services. "
            "Repeated failed authentication attempts from a single source are the key indicator."
        ),
        "reference_url": "https://attack.mitre.org/techniques/T1110",
        "severity_weight": 1.2,
        "indicators": [
            "High rate of failed connection attempts (RST responses)",
            "Repeated connections to same port from single IP",
            "Connection attempts at regular time intervals",
            "Targeting authentication ports: SSH/22, RDP/3389, MySQL/3306",
        ],
        "typical_targets": ["SSH servers", "RDP endpoints", "Web admin panels", "Databases"],
        "countermeasures": [
            "Block source IP after N failed attempts",
            "Implement account lockout policies",
            "Enable multi-factor authentication",
            "Move services to non-standard ports",
            "Use fail2ban or equivalent",
        ],
    },

    "suspicious": {
        "technique_id": "T1595",
        "technique_name": "Active Scanning",
        "tactic": "Reconnaissance",
        "tactic_id": "TA0043",
        "sub_technique_id": "T1595.001",
        "sub_technique_name": "Scanning IP Blocks",
        "description": (
            "Adversaries are actively probing infrastructure to gather information prior "
            "to an attack. Traffic patterns deviate from normal baselines without matching "
            "a specific known attack signature — indicating an early-stage reconnaissance "
            "or novel attack vector."
        ),
        "reference_url": "https://attack.mitre.org/techniques/T1595",
        "severity_weight": 0.8,
        "indicators": [
            "Statistical anomaly in traffic features vs baseline",
            "Unusual flow patterns not matching known attack types",
            "Elevated connection attempts without clear targeting pattern",
        ],
        "typical_targets": ["Network perimeter", "Public-facing services"],
        "countermeasures": [
            "Flag IP for enhanced monitoring",
            "Log all traffic from this source",
            "Correlate with other threat intelligence",
            "Consider proactive rate limiting",
        ],
    },

    "blocklist": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "sub_technique_id": "T1071.001",
        "sub_technique_name": "Web Protocols",
        "description": (
            "Traffic originating from an IP address on a known malicious reputation list. "
            "This IP has been previously associated with botnets, C2 infrastructure, "
            "malware distribution, or prior attack campaigns."
        ),
        "reference_url": "https://attack.mitre.org/techniques/T1071",
        "severity_weight": 1.3,
        "indicators": [
            "Source IP matches known threat intelligence feed",
            "IP previously associated with malicious activity",
            "May be part of a botnet or compromised host",
        ],
        "typical_targets": ["Any network asset"],
        "countermeasures": [
            "Block at network perimeter immediately",
            "Report to threat intelligence sharing community",
            "Investigate if any internal hosts contacted this IP",
        ],
    },

    "bot": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "sub_technique_id": "T1071.001",
        "sub_technique_name": "Web Protocols",
        "description": (
            "Traffic consistent with botnet C2 communication using standard application "
            "layer protocols (HTTP/HTTPS/DNS) to blend with legitimate traffic. "
            "The endpoint may be part of a compromised botnet receiving commands."
        ),
        "reference_url": "https://attack.mitre.org/techniques/T1071",
        "severity_weight": 1.3,
        "indicators": [
            "Periodic beaconing pattern at regular intervals",
            "Unusual outbound connections to external IPs",
            "Application protocol on non-standard ports",
            "Low-entropy communication (possibly encoded C2 commands)",
        ],
        "typical_targets": ["Compromised hosts", "Internal workstations", "IoT devices"],
        "countermeasures": [
            "Block source/destination IP immediately",
            "Investigate botnet C2 infrastructure",
            "Check all internal hosts that may have communicated with this IP",
            "Scan compromised hosts for malware",
        ],
    },
}

# Fallback for unknown attack types
_UNKNOWN_TECHNIQUE: Dict = {
    "technique_id": "T1499",
    "technique_name": "Endpoint Denial of Service",
    "tactic": "Impact",
    "tactic_id": "TA0040",
    "sub_technique_id": None,
    "sub_technique_name": None,
    "description": "Unknown attack pattern detected. Manual investigation recommended.",
    "reference_url": "https://attack.mitre.org/techniques/T1499",
    "severity_weight": 1.0,
    "indicators": ["Anomalous traffic pattern"],
    "typical_targets": ["Unknown"],
    "countermeasures": ["Investigate and monitor"],
}


# ─── MITREMapper ────────────────────────────────────────────────────

class MITREMapper:
    """Maps detected attack types to MITRE ATT&CK framework entries."""

    def map(self, attack_type: str) -> Dict:
        """
        Return MITRE ATT&CK entry for the given attack type.
        Always returns a valid dict — falls back to unknown entry if not found.
        """
        key = attack_type.lower().replace("-", "_").replace(" ", "_")
        entry = _TECHNIQUE_DB.get(key, _UNKNOWN_TECHNIQUE).copy()
        return entry

    def get_technique_id(self, attack_type: str) -> str:
        return self.map(attack_type)["technique_id"]

    def get_tactic(self, attack_type: str) -> str:
        return self.map(attack_type)["tactic"]

    def get_severity_weight(self, attack_type: str) -> float:
        return float(self.map(attack_type).get("severity_weight", 1.0))

    def get_countermeasures(self, attack_type: str) -> list:
        return self.map(attack_type).get("countermeasures", [])

    def all_techniques(self) -> Dict[str, str]:
        """Return mapping of attack_type → technique_id for reference."""
        return {k: v["technique_id"] for k, v in _TECHNIQUE_DB.items()}
