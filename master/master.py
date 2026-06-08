#!/usr/bin/env python3
"""
ICS-Watchdog — Modbus Master (PLC Simulator)

Simulates a PLC master controller that polls 3 slave field devices
every 2 seconds, reading holding registers 0-9 (simulated sensor data).
Occasionally writes to registers via FC06 to simulate normal control
operations (setpoint adjustments, calibration, etc.).
"""

import time
import sys
import signal
import logging
import random

from pymodbus.client import ModbusTcpClient

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SLAVE_IPS = ["192.168.100.21", "192.168.100.22", "192.168.100.23"]
MODBUS_PORT = 502
POLL_INTERVAL = 2       # seconds between polling cycles
REGISTER_START = 0
REGISTER_COUNT = 10     # read holding registers 0-9
WRITE_EVERY_N = 10      # write a register every Nth poll cycle
STARTUP_DELAY = 5       # seconds to wait for slaves to initialise

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [MASTER] %(levelname)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("modbus-master")

# ---------------------------------------------------------------------------
# Graceful shutdown
# ---------------------------------------------------------------------------
running = True


def _shutdown(sig, frame):
    global running
    logger.info("Shutdown signal received (sig=%s), stopping…", sig)
    running = False


signal.signal(signal.SIGTERM, _shutdown)
signal.signal(signal.SIGINT, _shutdown)

# ---------------------------------------------------------------------------
# Modbus helpers
# ---------------------------------------------------------------------------

def poll_slave(client: ModbusTcpClient, slave_ip: str) -> bool:
    """Read holding registers 0-9 from a slave (FC03)."""
    try:
        result = client.read_holding_registers(
            REGISTER_START, count=REGISTER_COUNT, device_id=1
        )
        if not result.isError():
            logger.info(
                "READ  %s  HR[0-9] → %s", slave_ip, result.registers
            )
            return True
        else:
            logger.warning("READ  %s  failed: %s", slave_ip, result)
            return False
    except Exception as exc:
        logger.error("READ  %s  error: %s", slave_ip, exc)
        return False


def write_register(
    client: ModbusTcpClient, slave_ip: str, address: int, value: int
) -> bool:
    """Write a single holding register (FC06) to simulate control."""
    try:
        result = client.write_register(address, value, device_id=1)
        if not result.isError():
            logger.info("WRITE %s  HR[%d] = %d", slave_ip, address, value)
            return True
        else:
            logger.warning("WRITE %s  failed: %s", slave_ip, result)
            return False
    except Exception as exc:
        logger.error("WRITE %s  error: %s", slave_ip, exc)
        return False

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main():
    logger.info("=" * 60)
    logger.info("Modbus Master starting")
    logger.info("Slaves : %s", ", ".join(SLAVE_IPS))
    logger.info("Poll   : every %ds, registers %d–%d",
                POLL_INTERVAL, REGISTER_START, REGISTER_START + REGISTER_COUNT - 1)
    logger.info("=" * 60)

    # Give slaves time to boot
    logger.info("Waiting %ds for slaves to initialise…", STARTUP_DELAY)
    time.sleep(STARTUP_DELAY)

    # Persistent TCP connections to each slave
    clients: dict[str, ModbusTcpClient] = {}
    for ip in SLAVE_IPS:
        client = ModbusTcpClient(ip, port=MODBUS_PORT, timeout=3)
        clients[ip] = client
        logger.info("Client created for %s", ip)

    poll_count = 0

    while running:
        for ip, client in clients.items():
            if not running:
                break

            # Ensure connection is alive
            if not client.connected:
                try:
                    client.connect()
                    logger.info("Connected to %s", ip)
                except Exception as exc:
                    logger.error("Connection to %s failed: %s", ip, exc)
                    continue

            # --- Normal read cycle (FC03) ---
            poll_slave(client, ip)

            # --- Periodic write cycle (FC06) ---
            if poll_count > 0 and poll_count % WRITE_EVERY_N == 0:
                reg_addr = random.randint(0, 9)
                reg_value = random.randint(100, 999)
                write_register(client, ip, reg_addr, reg_value)

        poll_count += 1
        time.sleep(POLL_INTERVAL)

    # Clean shutdown
    for ip, client in clients.items():
        try:
            client.close()
        except Exception:
            pass
        logger.info("Connection to %s closed", ip)

    logger.info("Master shutdown complete")


if __name__ == "__main__":
    main()
