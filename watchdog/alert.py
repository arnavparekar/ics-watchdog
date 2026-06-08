"""
ICS-Watchdog — Alert Schema and Writer
Defines the structure of a detection alert according to the
SRS JSON schema and provides a writer to append alerts to a
shared JSON Lines file.
"""

import json
import uuid
import os
from dataclasses import dataclass, asdict

ALERTS_FILE = "/app/output/alerts.jsonl"


@dataclass
class Alert:
    """Alert structure corresponding to the SRS schema."""
    timestamp: str
    rule_id: str
    rule_name: str
    severity: str
    src_ip: str
    dst_ip: str
    function_code: int
    mitre_technique: str
    mitre_name: str
    explanation: str
    raw_packet_count: int
    alert_id: str = ""

    def __post_init__(self):
        if not self.alert_id:
            self.alert_id = str(uuid.uuid4())


class AlertWriter:
    """Appends alerts to a JSON Lines file."""

    def __init__(self, filepath: str = ALERTS_FILE):
        self.filepath = filepath
        os.makedirs(os.path.dirname(self.filepath), exist_ok=True)
        open(self.filepath, "a").close()

    def write(self, alert: Alert):
        """Append a single alert to the file."""
        try:
            with open(self.filepath, "a") as f:
                f.write(json.dumps(asdict(alert)) + "\n")
        except Exception as exc:
            import logging
            logging.getLogger("ics-watchdog").error("Failed to write alert: %s", exc)
