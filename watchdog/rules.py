"""
ICS-Watchdog — Detection Rules Engine
Evaluates parsed Modbus packets against stateful security rules.
Matches trigger alerts mapped to MITRE ATT&CK for ICS.
"""

import time
from collections import defaultdict
from typing import Optional
from alert import Alert


# Rule Engine
class RuleEngine:
    """Stateful engine that evaluates packets against active rules."""

    def __init__(self):
        # Allowlist from SRS
        self.master_ip = "192.168.100.10"
        
        # State for R-001 (Function Code Scan)
        # Maps src_ip -> dict of {function_code: latest_timestamp}
        self.fc_history: dict[str, dict[int, float]] = defaultdict(dict)

        # State for R-003 (Register Read Flood)
        # Maps src_ip -> list of timestamps for FC03 requests
        self.read_history: dict[str, list[float]] = defaultdict(list)

        # State for R-004 (Broadcast Probe / Sequential Scan)
        # Maps src_ip -> set of (dst_ip, timestamp)
        self.dst_history: dict[str, list[tuple[str, float]]] = defaultdict(list)

        # Allowlist for R-006 (New Source IP)
        self.known_ips = {"192.168.100.10", "192.168.100.21", "192.168.100.22", "192.168.100.23"}

        # State for R-007 (Replay Attack)
        # Maps src_ip -> dict of {payload_hex: list of timestamps}
        self.payload_history: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))

        # State for R-008 (Excessive Write Rate)
        # Maps src_ip -> list of timestamps for write requests
        self.write_history: dict[str, list[float]] = defaultdict(list)

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
            
        if alert := self._rule_003_register_read_flood(pkt):
            alerts.append(alert)
            
        if alert := self._rule_004_broadcast_probe(pkt):
            alerts.append(alert)
            
        if alert := self._rule_005_out_of_range_access(pkt):
            alerts.append(alert)
            
        if alert := self._rule_006_new_source_ip(pkt):
            alerts.append(alert)
            
        if alert := self._rule_007_replay_attack(pkt):
            alerts.append(alert)
            
        if alert := self._rule_008_excessive_write_rate(pkt):
            alerts.append(alert)

        return alerts

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

    def _rule_003_register_read_flood(self, pkt: dict) -> Optional[Alert]:
        """
        R-003: Register Read Flood
        MITRE: T0884 — Connection Probe
        Logic: More than 50 FC03 requests from same source within 10 seconds.
        """
        if pkt["function_code"] != 3:
            return None
            
        src = pkt["src_ip"]
        now = pkt["epoch"]
        
        # Append current and prune old timestamps
        self.read_history[src].append(now)
        self.read_history[src] = [ts for ts in self.read_history[src] if (now - ts) <= 10]
        
        if len(self.read_history[src]) > 50:
            count = len(self.read_history[src])
            self.read_history[src].clear()
            return Alert(
                timestamp=pkt["timestamp"],
                rule_id="R-003",
                rule_name="Register Read Flood",
                severity="HIGH",
                src_ip=src,
                dst_ip=pkt["dst_ip"],
                function_code=3,
                mitre_technique="T0884",
                mitre_name="Connection Probe",
                explanation=f"Source sent {count} FC03 requests in under 10 seconds. Threshold is 50/10s.",
                raw_packet_count=count
            )
        return None

    def _rule_004_broadcast_probe(self, pkt: dict) -> Optional[Alert]:
        """
        R-004: Broadcast Probe / Sequential Scan
        MITRE: T0846 — Remote System Discovery
        Logic: Modbus packet to broadcast OR sequential scan of all 3 slaves
               (detected via distinct unit_ids 1,2,3 or dst IPs .21/.22/.23) within 5s.
        """
        src = pkt["src_ip"]
        dst = pkt["dst_ip"]
        now = pkt["epoch"]
        unit_id = pkt.get("unit_id", 0)
        
        # Check for broadcast
        if dst.endswith(".255"):
            return Alert(
                timestamp=pkt["timestamp"],
                rule_id="R-004",
                rule_name="Broadcast Probe",
                severity="HIGH",
                src_ip=src,
                dst_ip=dst,
                function_code=pkt["function_code"],
                mitre_technique="T0846",
                mitre_name="Remote System Discovery",
                explanation=f"Modbus packet sent to broadcast address {dst}.",
                raw_packet_count=1
            )
            
        # Track both dst_ip and unit_id for sequential scan detection
        self.dst_history[src].append((dst, unit_id, now))
        self.dst_history[src] = [(d, u, ts) for d, u, ts in self.dst_history[src] if (now - ts) <= 5]
        
        # Check sequential scan via dst_ip (.21/.22/.23)
        recent_dsts = {d for d, u, ts in self.dst_history[src]}
        slave_ips = {"192.168.100.21", "192.168.100.22", "192.168.100.23"}
        
        # Check sequential scan via unit_id (1, 2, 3) — for traffic routed through master
        recent_units = {u for d, u, ts in self.dst_history[src]}
        slave_units = {1, 2, 3}
        
        if slave_ips.issubset(recent_dsts) or slave_units.issubset(recent_units):
            self.dst_history[src].clear()
            return Alert(
                timestamp=pkt["timestamp"],
                rule_id="R-004",
                rule_name="Sequential Scan Probe",
                severity="HIGH",
                src_ip=src,
                dst_ip=dst,
                function_code=pkt["function_code"],
                mitre_technique="T0846",
                mitre_name="Remote System Discovery",
                explanation="Source sequentially probed all 3 slave devices within 5 seconds.",
                raw_packet_count=len(self.dst_history.get(src, []))
            )
        return None

    def _rule_005_out_of_range_access(self, pkt: dict) -> Optional[Alert]:
        """
        R-005: Out-of-Range Register Access
        MITRE: T0855 — Unauthorized Command Message
        Logic: FC03/FC04 requesting registers above address 9.
        """
        fc = pkt["function_code"]
        if fc in (3, 4) and "register_address" in pkt:
            addr = pkt["register_address"]
            if addr > 9:
                return Alert(
                    timestamp=pkt["timestamp"],
                    rule_id="R-005",
                    rule_name="Out-of-Range Register Access",
                    severity="MEDIUM",
                    src_ip=pkt["src_ip"],
                    dst_ip=pkt["dst_ip"],
                    function_code=fc,
                    mitre_technique="T0855",
                    mitre_name="Unauthorized Command Message",
                    explanation=f"Requested register address {addr} is outside normal operating range (0-9).",
                    raw_packet_count=1
                )
        return None

    def _rule_006_new_source_ip(self, pkt: dict) -> Optional[Alert]:
        """
        R-006: New Source IP
        MITRE: T0843 — Program Download
        Logic: Any Modbus packet from a source IP not in the known-devices whitelist.
        """
        src = pkt["src_ip"]
        if src not in self.known_ips:
            # Add to known IPs to prevent alerting on every subsequent packet
            self.known_ips.add(src)
            return Alert(
                timestamp=pkt["timestamp"],
                rule_id="R-006",
                rule_name="New Source IP",
                severity="HIGH",
                src_ip=src,
                dst_ip=pkt["dst_ip"],
                function_code=pkt["function_code"],
                mitre_technique="T0843",
                mitre_name="Program Download",
                explanation=f"Modbus traffic observed from an unknown source IP ({src}).",
                raw_packet_count=1
            )
        return None

    def _rule_007_replay_attack(self, pkt: dict) -> Optional[Alert]:
        """
        R-007: Replay Attack
        MITRE: T0856 — Spoof Reporting Message
        Logic: Identical packet (same FC + payload) sent > 3 times within 5 seconds from same source.
        """
        src = pkt["src_ip"]
        now = pkt["epoch"]
        fc = pkt["function_code"]
        
        # We only care about writes or non-standard reads for replays usually,
        # but the rule applies to any identical packet. Let's exclude FC03/04 polls 
        # from the master to avoid false positives on legitimate polling.
        if src == self.master_ip and fc in (3, 4):
            return None
            
        payload = pkt.get("data_hex", "")
        if not payload:
            return None
            
        history = self.payload_history[src][payload]
        history.append(now)
        
        # Prune old
        self.payload_history[src][payload] = [ts for ts in history if (now - ts) <= 5]
        count = len(self.payload_history[src][payload])
        
        if count > 3:
            self.payload_history[src][payload].clear()
            return Alert(
                timestamp=pkt["timestamp"],
                rule_id="R-007",
                rule_name="Replay Attack",
                severity="CRITICAL",
                src_ip=src,
                dst_ip=pkt["dst_ip"],
                function_code=fc,
                mitre_technique="T0856",
                mitre_name="Spoof Reporting Message",
                explanation=f"Identical Modbus packet payload retransmitted {count} times within 5 seconds.",
                raw_packet_count=count
            )
        return None

    def _rule_008_excessive_write_rate(self, pkt: dict) -> Optional[Alert]:
        """
        R-008: Excessive Write Rate
        MITRE: T0855 — Unauthorized Command Message
        Logic: > 20 write commands (FC05/06/15/16) in 10 seconds from any source.
        """
        fc = pkt["function_code"]
        if fc not in (5, 6, 15, 16):
            return None
            
        src = pkt["src_ip"]
        now = pkt["epoch"]
        
        self.write_history[src].append(now)
        self.write_history[src] = [ts for ts in self.write_history[src] if (now - ts) <= 10]
        
        count = len(self.write_history[src])
        if count > 20:
            self.write_history[src].clear()
            return Alert(
                timestamp=pkt["timestamp"],
                rule_id="R-008",
                rule_name="Excessive Write Rate",
                severity="CRITICAL",
                src_ip=src,
                dst_ip=pkt["dst_ip"],
                function_code=fc,
                mitre_technique="T0855",
                mitre_name="Unauthorized Command Message",
                explanation=f"Source sent {count} Modbus write commands in under 10 seconds. Threshold is 20/10s.",
                raw_packet_count=count
            )
        return None
