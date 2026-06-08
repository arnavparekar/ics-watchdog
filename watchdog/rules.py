"""
ICS-Watchdog — Detection Rules Engine

Evaluates parsed Modbus packets against stateful security rules.
Matches trigger alerts mapped to MITRE ATT&CK for ICS.
"""

import time
from collections import defaultdict
from typing import Optional
from alert import Alert

# ---------------------------------------------------------------------------
# Rule Engine
# ---------------------------------------------------------------------------

class RuleEngine:
    """Stateful engine that evaluates packets against active rules."""

    def __init__(self):
        # Allowlist from SRS
        self.master_ip = "192.168.100.10"
        
        # State for R-001 (Function Code Scan)
        # Maps src_ip -> dict of {function_code: latest_timestamp}
        self.fc_history: dict[str, dict[int, float]] = defaultdict(dict)

    def evaluate(self, pkt: dict) -> list[Alert]:
        """Run a packet through all rules and return triggered alerts."""
        alerts = []
        
        # Add timestamp as epoch for sliding window calculations
        import dateutil.parser
        pkt["epoch"] = dateutil.parser.isoparse(pkt["timestamp"]).timestamp()

        # Update global state for this packet
        src = pkt["src_ip"]
        fc = pkt["function_code"]
        self.fc_history[src][fc] = pkt["epoch"]

        # Run rules
        if alert := self._rule_001_function_code_scan(pkt):
            alerts.append(alert)
            
        if alert := self._rule_002_unauthorised_write(pkt):
            alerts.append(alert)

        return alerts

    # -----------------------------------------------------------------------
    # Rules
    # -----------------------------------------------------------------------

    def _rule_001_function_code_scan(self, pkt: dict) -> Optional[Alert]:
        """
        R-001: Modbus Function Code Scan
        MITRE: T0846 — Remote System Discovery
        Logic: >10 distinct function codes from same src_ip within 30s.
        """
        src = pkt["src_ip"]
        now = pkt["epoch"]
        
        # Count distinct FCs in the last 30 seconds
        recent_fcs = [
            fc for fc, ts in self.fc_history[src].items() 
            if (now - ts) <= 30
        ]
        
        if len(recent_fcs) > 10:
            # We don't want to alert on every subsequent packet, so we clear the history
            # to reset the threshold counter.
            self.fc_history[src].clear()
            
            return Alert(
                timestamp=pkt["timestamp"],
                rule_id="R-001",
                rule_name="Modbus Function Code Scan",
                severity="HIGH",
                src_ip=src,
                dst_ip=pkt["dst_ip"],
                function_code=pkt["function_code"],
                mitre_technique="T0846",
                mitre_name="Remote System Discovery",
                explanation=f"Source sent {len(recent_fcs)} distinct function codes within 30 seconds (threshold is 10).",
                raw_packet_count=len(recent_fcs)
            )
        return None

    def _rule_002_unauthorised_write(self, pkt: dict) -> Optional[Alert]:
        """
        R-002: Unauthorised Write to Coils
        MITRE: T0855 — Unauthorized Command Message
        Logic: FC05 or FC15 from any IP not in the whitelist (master).
        """
        fc = pkt["function_code"]
        src = pkt["src_ip"]
        
        if fc in (5, 15) and src != self.master_ip:
            return Alert(
                timestamp=pkt["timestamp"],
                rule_id="R-002",
                rule_name="Unauthorised Write to Coils",
                severity="CRITICAL",
                src_ip=src,
                dst_ip=pkt["dst_ip"],
                function_code=fc,
                mitre_technique="T0855",
                mitre_name="Unauthorized Command Message",
                explanation=f"Non-master IP {src} attempted a coil write operation (FC{fc:02d}).",
                raw_packet_count=1
            )
        return None
