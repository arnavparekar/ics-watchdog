#!/usr/bin/env python3
"""
ICS-Watchdog — Passive Modbus/TCP Network Sniffer

Captures all Modbus/TCP traffic on the Docker bridge network using
promiscuous mode.  Parses MBAP (Modbus Application Protocol) headers,
logs packet metadata to stdout, and writes running statistics to a
shared volume for the reporter container.

No detection rules in this module — pure capture and parse.
Rules are added by the rule engine (rules.py) in later commits.
"""

import struct
import time
import signal
import logging
import json
import os
import subprocess
import threading
from datetime import datetime, timezone
from collections import defaultdict

from scapy.all import sniff, TCP, IP, Raw, conf

from alert import AlertWriter
from rules import RuleEngine

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
MODBUS_PORT = 502
CAPTURE_IFACE = os.environ.get("CAPTURE_IFACE", "eth0")
OUTPUT_DIR = "/app/output"
STATS_FILE = os.path.join(OUTPUT_DIR, "packet_stats.json")
ALERTS_FILE = os.path.join(OUTPUT_DIR, "alerts.jsonl")
STATS_FLUSH_INTERVAL = 5  # seconds between stats file writes

# ---------------------------------------------------------------------------
# Modbus function code reference
# ---------------------------------------------------------------------------
FC_NAMES = {
    1:  "Read Coils",
    2:  "Read Discrete Inputs",
    3:  "Read Holding Registers",
    4:  "Read Input Registers",
    5:  "Write Single Coil",
    6:  "Write Single Register",
    7:  "Read Exception Status",
    8:  "Diagnostics",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
    17: "Report Server ID",
    23: "Read/Write Multiple Registers",
    43: "Encapsulated Interface Transport",
}

WRITE_FUNCTION_CODES = {5, 6, 15, 16}

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [WATCHDOG] %(levelname)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ics-watchdog")

# ---------------------------------------------------------------------------
# Graceful shutdown
# ---------------------------------------------------------------------------
running = True


def _shutdown(sig, _frame):
    global running
    logger.info("Shutdown signal received (sig=%s)", sig)
    running = False


signal.signal(signal.SIGTERM, _shutdown)
signal.signal(signal.SIGINT, _shutdown)


# ---------------------------------------------------------------------------
# Modbus/TCP parser
# ---------------------------------------------------------------------------

def parse_mbap(payload: bytes) -> dict | None:
    """Parse a Modbus/TCP MBAP header + PDU from a raw TCP payload.

    MBAP Header (7 bytes):
        Transaction ID  :  2 bytes  (big-endian)
        Protocol ID     :  2 bytes  (0x0000 = Modbus)
        Length           :  2 bytes  (remaining byte count incl. Unit ID)
        Unit ID          :  1 byte

    PDU (starts at byte 7):
        Function Code   :  1 byte
        Data             :  variable

    Returns a dict with parsed fields, or None if the payload is not
    a valid Modbus/TCP frame.
    """
    if payload is None or len(payload) < 8:
        return None

    transaction_id, protocol_id, length, unit_id, function_code = struct.unpack(
        ">HHHBB", payload[:8]
    )

    # Protocol ID must be 0 for Modbus
    if protocol_id != 0:
        return None

    data = payload[8:]

    parsed = {
        "transaction_id": transaction_id,
        "protocol_id": protocol_id,
        "length": length,
        "unit_id": unit_id,
        "function_code": function_code,
        "function_name": FC_NAMES.get(function_code, f"Unknown({function_code})"),
        "data": data,
        "data_hex": data.hex() if data else "",
    }

    # Extract register address / count where possible
    _extract_register_info(parsed, function_code, data)

    return parsed


def _extract_register_info(parsed: dict, fc: int, data: bytes):
    """Enrich the parsed dict with register address and count fields
    extracted from the PDU data, where applicable."""

    if fc in (1, 2, 3, 4):
        # Read request:  StartAddr(2) + Quantity(2)
        # Read response: ByteCount(1) + Values(N)
        if len(data) >= 4:
            addr, count = struct.unpack(">HH", data[:4])
            # Heuristic: if addr is small and count is reasonable, it's a request
            if count <= 125:
                parsed["register_address"] = addr
                parsed["register_count"] = count
                parsed["is_response"] = False
            else:
                parsed["is_response"] = True
        elif len(data) >= 1:
            parsed["byte_count"] = data[0]
            parsed["is_response"] = True

    elif fc in (5, 6):
        # Write Single Coil / Register: Address(2) + Value(2)
        if len(data) >= 4:
            parsed["register_address"] = struct.unpack(">H", data[:2])[0]
            parsed["register_value"] = struct.unpack(">H", data[2:4])[0]

    elif fc in (15, 16):
        # Write Multiple: StartAddr(2) + Quantity(2) + ...
        if len(data) >= 4:
            parsed["register_address"], parsed["register_count"] = struct.unpack(
                ">HH", data[:4]
            )


# ---------------------------------------------------------------------------
# Packet capture engine
# ---------------------------------------------------------------------------

class PacketCapture:
    """Stateful packet capture engine that sniffs Modbus/TCP traffic,
    parses headers, logs to stdout, and maintains running statistics."""

    def __init__(self):
        self.start_time = datetime.now(timezone.utc)
        self.total_packets = 0
        self.modbus_packets = 0
        self.fc_distribution: dict[int, int] = defaultdict(int)
        self.src_ip_counts: dict[str, int] = defaultdict(int)
        self.dst_ip_counts: dict[str, int] = defaultdict(int)
        self.unique_pairs: set[tuple[str, str]] = set()
        self.packets: list[dict] = []  # recent parsed packets for rule engine

        self.engine = RuleEngine()
        self.alert_writer = AlertWriter()

        # Ensure output directory exists
        os.makedirs(OUTPUT_DIR, exist_ok=True)

    def process_packet(self, pkt):
        """Scapy callback — called for each captured packet."""
        self.total_packets += 1

        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return

        ip_layer = pkt[IP]
        tcp_layer = pkt[TCP]

        # Determine direction
        if tcp_layer.dport == MODBUS_PORT:
            direction = "REQ"
        elif tcp_layer.sport == MODBUS_PORT:
            direction = "RSP"
        else:
            return

        # Extract TCP payload
        if not pkt.haslayer(Raw):
            return  # TCP control packet (SYN, ACK, FIN) — no Modbus data

        payload = bytes(pkt[Raw].load)
        parsed = parse_mbap(payload)
        if parsed is None:
            return

        self.modbus_packets += 1

        # Enrich with network-level metadata
        parsed["timestamp"] = datetime.now(timezone.utc).isoformat()
        parsed["src_ip"] = ip_layer.src
        parsed["dst_ip"] = ip_layer.dst
        parsed["src_port"] = tcp_layer.sport
        parsed["dst_port"] = tcp_layer.dport
        parsed["direction"] = direction

        # Update statistics
        fc = parsed["function_code"]
        self.fc_distribution[fc] += 1
        self.src_ip_counts[ip_layer.src] += 1
        self.dst_ip_counts[ip_layer.dst] += 1
        self.unique_pairs.add((ip_layer.src, ip_layer.dst))

        # Store for rule engine (keep last 1000 packets in memory)
        self.packets.append(parsed)
        if len(self.packets) > 1000:
            self.packets.pop(0)

        # Run detection engine
        if parsed["direction"] == "REQ":  # Only evaluate requests
            alerts = self.engine.evaluate(parsed)
            for alert in alerts:
                logger.warning("🚨 ALERT FIRED: [%s] %s (src: %s)", alert.rule_id, alert.rule_name, alert.src_ip)
                self.alert_writer.write(alert)

        # Log to stdout
        reg_info = ""
        if "register_address" in parsed:
            reg_info = f"  reg={parsed['register_address']}"
            if "register_count" in parsed:
                reg_info += f" cnt={parsed['register_count']}"
            elif "register_value" in parsed:
                reg_info += f" val={parsed['register_value']}"

        logger.info(
            "%s  %s → %s  FC=%02d (%s)%s",
            direction,
            ip_layer.src,
            ip_layer.dst,
            fc,
            parsed["function_name"],
            reg_info,
        )

    def get_stats(self) -> dict:
        """Return current capture statistics as a JSON-serialisable dict."""
        now = datetime.now(timezone.utc)
        elapsed = (now - self.start_time).total_seconds()

        return {
            "start_time": self.start_time.isoformat(),
            "current_time": now.isoformat(),
            "elapsed_seconds": round(elapsed, 1),
            "total_packets": self.total_packets,
            "modbus_packets": self.modbus_packets,
            "function_code_distribution": {
                FC_NAMES.get(fc, f"FC{fc}"): count
                for fc, count in sorted(self.fc_distribution.items())
            },
            "function_code_raw": dict(sorted(self.fc_distribution.items())),
            "source_ips": dict(self.src_ip_counts),
            "destination_ips": dict(self.dst_ip_counts),
            "unique_communication_pairs": len(self.unique_pairs),
        }

    def flush_stats(self):
        """Write current statistics to the shared output volume."""
        try:
            stats = self.get_stats()
            with open(STATS_FILE, "w") as f:
                json.dump(stats, f, indent=2)
        except Exception as exc:
            logger.error("Failed to write stats: %s", exc)


# ---------------------------------------------------------------------------
# Stats flusher thread
# ---------------------------------------------------------------------------

def _stats_flusher(capture: PacketCapture):
    """Background thread that periodically writes capture stats to disk."""
    while running:
        time.sleep(STATS_FLUSH_INTERVAL)
        capture.flush_stats()
        if capture.modbus_packets > 0 and capture.modbus_packets % 50 == 0:
            logger.info(
                "Stats: %d Modbus packets captured, %d total",
                capture.modbus_packets,
                capture.total_packets,
            )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    logger.info("=" * 60)
    logger.info("ICS-Watchdog — Passive Modbus/TCP Sniffer")
    logger.info("Interface : %s", CAPTURE_IFACE)
    logger.info("Filter    : tcp port %d", MODBUS_PORT)
    logger.info("Output    : %s", OUTPUT_DIR)
    logger.info("=" * 60)

    # Attempt to set promiscuous mode for bridge-wide capture
    try:
        subprocess.run(
            ["ip", "link", "set", CAPTURE_IFACE, "promisc", "on"],
            check=True,
            capture_output=True,
        )
        logger.info("Promiscuous mode enabled on %s", CAPTURE_IFACE)
    except Exception as exc:
        logger.warning(
            "Could not enable promiscuous mode on %s: %s  "
            "(will only see packets addressed to this container)",
            CAPTURE_IFACE,
            exc,
        )

    # Disable scapy verbosity
    conf.verb = 0

    capture = PacketCapture()

    # Create empty alerts file (rule engine will append to this later)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    open(ALERTS_FILE, "a").close()

    # Start background stats writer
    stats_thread = threading.Thread(
        target=_stats_flusher, args=(capture,), daemon=True
    )
    stats_thread.start()

    logger.info("Starting packet capture… (Ctrl+C to stop)")

    # Scapy sniff — blocks until interrupted
    try:
        sniff(
            iface=CAPTURE_IFACE,
            filter=f"tcp port {MODBUS_PORT}",
            prn=capture.process_packet,
            store=0,
            stop_filter=lambda _: not running,
        )
    except PermissionError:
        logger.error(
            "Permission denied — container needs cap_add: [NET_RAW, NET_ADMIN]"
        )
    except Exception as exc:
        logger.error("Sniff error: %s", exc)

    # Final stats flush
    capture.flush_stats()
    stats = capture.get_stats()
    logger.info("=" * 60)
    logger.info("Capture complete")
    logger.info("Total packets  : %d", stats["total_packets"])
    logger.info("Modbus packets : %d", stats["modbus_packets"])
    logger.info("Duration       : %.1fs", stats["elapsed_seconds"])
    logger.info("=" * 60)

    # Write done signal for the reporter
    done_file = os.path.join(OUTPUT_DIR, "done.signal")
    with open(done_file, "w") as f:
        f.write(datetime.now(timezone.utc).isoformat())
    logger.info("Done signal written to %s", done_file)


if __name__ == "__main__":
    main()
