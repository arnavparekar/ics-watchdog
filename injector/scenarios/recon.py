"""
Reconnaissance Scan Attack Scenario
Sends multiple function codes and out-of-bounds register reads 
to probe the Modbus/TCP network. Traffic is sent to each slave 
via its real IP and simultaneously mirrored to the watchdog 
for passive detection.
Triggers rules:
R-001: Modbus Function Code Scan (>10 distinct FCs from same source in 30s)
R-004: Sequential Scan Probe (scanning all 3 slaves rapidly)
R-005: Out-of-Range Register Access (reading registers > 9)
R-006: New Source IP (injector IP not in whitelist)
"""

import time
import logging
import struct
from pymodbus.client import ModbusTcpClient
from scapy.all import IP, TCP, send

logger = logging.getLogger("injector")

SLAVE_IPS = ["192.168.100.21", "192.168.100.22", "192.168.100.23"]
WATCHDOG_IP = "192.168.100.100"

def _mirror_to_watchdog(fc: int, unit_id: int, data: bytes):
    """Send a raw Modbus/TCP packet to the watchdog for passive capture."""
    # MBAP: TransID=0, Proto=0, Len=len(data)+2, UnitID, FC
    mbap = struct.pack('>HHHBB', 0, 0, len(data) + 2, unit_id, fc)
    payload = mbap + data
    pkt = IP(dst=WATCHDOG_IP) / TCP(dport=502, sport=55555, flags='PA') / payload
    send(pkt, verbose=0)


def run():
    logger.info("Starting Reconnaissance Scan (T0846, T0843, T0855)")

    for idx, ip in enumerate(SLAVE_IPS):
        slave_id = idx + 1
        logger.info("  -> Probing slave-%d (%s)...", slave_id, ip)

        client = ModbusTcpClient(ip, port=502)
        if not client.connect():
            logger.warning("Failed to connect to %s", ip)
            continue

        # --- R-005: Out-of-range register reads (slaves only have 0-9) ---
        logger.info("     Reading out-of-range registers (FC03, addr=50)")
        try:
            client.read_holding_registers(address=50, count=10, device_id=slave_id)
        except Exception:
            pass
        # Mirror: FC03, addr=50, count=10
        _mirror_to_watchdog(3, slave_id, struct.pack('>HH', 50, 10))

        # --- R-001: Fuzz many function codes ---
        logger.info("     Fuzzing function codes 01-08")
        fcs_used = []
        
        try:
            client.read_coils(0, 10, device_id=slave_id)         # FC01
            fcs_used.append(1)
        except: pass
        _mirror_to_watchdog(1, slave_id, struct.pack('>HH', 0, 10))
        
        try:
            client.read_discrete_inputs(0, 10, device_id=slave_id)  # FC02
            fcs_used.append(2)
        except: pass
        _mirror_to_watchdog(2, slave_id, struct.pack('>HH', 0, 10))
        
        try:
            client.read_holding_registers(0, 10, device_id=slave_id)  # FC03
            fcs_used.append(3)
        except: pass
        _mirror_to_watchdog(3, slave_id, struct.pack('>HH', 0, 10))
        
        try:
            client.read_input_registers(0, 10, device_id=slave_id)   # FC04
            fcs_used.append(4)
        except: pass
        _mirror_to_watchdog(4, slave_id, struct.pack('>HH', 0, 10))
        
        try:
            client.write_coil(0, True, device_id=slave_id)           # FC05
            fcs_used.append(5)
        except: pass
        _mirror_to_watchdog(5, slave_id, struct.pack('>HH', 0, 0xFF00))
        
        try:
            client.write_register(0, 100, device_id=slave_id)        # FC06
            fcs_used.append(6)
        except: pass
        _mirror_to_watchdog(6, slave_id, struct.pack('>HH', 0, 100))
        
        try:
            client.write_coils(0, [True, False, True], device_id=slave_id)  # FC15
            fcs_used.append(15)
        except: pass
        _mirror_to_watchdog(15, slave_id, struct.pack('>HH', 0, 3))
        
        try:
            client.write_registers(0, [100, 200, 300], device_id=slave_id)  # FC16
            fcs_used.append(16)
        except: pass
        _mirror_to_watchdog(16, slave_id, struct.pack('>HH', 0, 3))

        # Additional FCs via raw mirrors to push distinct count > 10 for R-001
        # FC07 (Read Exception Status), FC08 (Diagnostics), FC17 (Report Server ID), FC23 (R/W Multiple)
        logger.info("     Sending additional probing FCs (07, 08, 17, 23)")
        _mirror_to_watchdog(7, slave_id, b'')
        _mirror_to_watchdog(8, slave_id, struct.pack('>HH', 0, 0))
        _mirror_to_watchdog(17, slave_id, b'')
        _mirror_to_watchdog(23, slave_id, struct.pack('>HHHH', 0, 1, 0, 1))

        client.close()
        time.sleep(0.3)

    logger.info("Reconnaissance Scan complete.")
