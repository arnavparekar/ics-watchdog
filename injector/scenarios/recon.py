"""
Reconnaissance Scan Attack Scenario

Iterates through slave IPs, sends multiple function codes (FC01-08),
and attempts to read out-of-bounds registers (0-100) to map device capabilities.

Triggers rules:
- R-001: Modbus Function Code Scan (from sending 8 FCs to a target)
- R-004: Sequential Scan Probe (from scanning .21, .22, .23 rapidly)
- R-005: Out-of-Range Register Access (from reading registers > 9)
- R-006: New Source IP (because the injector IP isn't in the whitelist)
"""

import time
import logging
from pymodbus.client import ModbusTcpClient

logger = logging.getLogger("injector")

def run():
    logger.info("Starting Reconnaissance Scan (T0846, T0843, T0855)")
    targets = ["192.168.100.21", "192.168.100.22", "192.168.100.23"]

    for ip in targets:
        logger.info("Scanning target %s...", ip)
        client = ModbusTcpClient(ip, port=502)
        if not client.connect():
            logger.warning("Failed to connect to %s", ip)
            continue

        # Trigger R-005 (Out of range) by reading holding registers 0-100
        # Slaves only have 0-9.
        logger.info("  -> Reading registers 0-100 (FC03)")
        client.read_holding_registers(address=0, count=100, device_id=1)
        
        # Trigger R-001 by sending many different function codes
        logger.info("  -> Fuzzing function codes 01-08")
        try: client.read_coils(0, 1, device_id=1)
        except: pass
        try: client.read_discrete_inputs(0, 1, device_id=1)
        except: pass
        try: client.read_input_registers(0, 1, device_id=1)
        except: pass
        try: client.write_coil(0, True, device_id=1)
        except: pass
        try: client.write_register(0, 1, device_id=1)
        except: pass
        
        client.close()
        
        # Small delay before next target so it's not totally instantaneous
        time.sleep(0.5)

    logger.info("Reconnaissance Scan complete.")
