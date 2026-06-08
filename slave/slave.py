#!/usr/bin/env python3
"""
ICS-Watchdog — Modbus Slave (Field Device Simulator)

Simulates a PLC field device that responds to Modbus/TCP requests.
Each instance is parameterised by the SLAVE_ID environment variable
(1, 2, or 3) and exposes:

  - Holding registers 0-9  (FC03 read / FC06 write) — sensor values
  - Input registers 0-9    (FC04 read-only)          — diagnostic data
  - Coils 0-9              (FC01 read / FC05 write)   — actuator states
  - Discrete inputs 0-9    (FC02 read-only)           — binary sensors

A background thread drifts sensor values every few seconds to simulate
realistic, changing process data.
"""

import os
import time
import logging
import random
import threading

from pymodbus.server import StartTcpServer
from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusDeviceContext,
    ModbusServerContext,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SLAVE_ID = int(os.environ.get("SLAVE_ID", 1))
MODBUS_PORT = 502
SENSOR_UPDATE_INTERVAL = 3  # seconds between simulated sensor drift

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format=f"%(asctime)s [SLAVE-{SLAVE_ID}] %(levelname)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(f"modbus-slave-{SLAVE_ID}")

# ---------------------------------------------------------------------------
# Sensor profiles — each slave simulates a different plant area
# ---------------------------------------------------------------------------
SENSOR_PROFILES = {
    1: {
        "name": "Reactor Unit",
        "base_temp": 350,     # °F
        "base_pressure": 45,  # PSI
        "base_flow": 120,     # GPM
    },
    2: {
        "name": "Cooling Tower",
        "base_temp": 85,
        "base_pressure": 12,
        "base_flow": 500,
    },
    3: {
        "name": "Storage Tank",
        "base_temp": 72,
        "base_pressure": 1,
        "base_flow": 0,
    },
}

# ---------------------------------------------------------------------------
# Datastore initialisation
# ---------------------------------------------------------------------------

def _build_initial_registers() -> list[int]:
    """Build 100 holding register values.  Addresses 0-9 contain
    meaningful sensor readings; 10-99 are zeroed (reserved)."""
    profile = SENSOR_PROFILES.get(SLAVE_ID, SENSOR_PROFILES[1])
    regs = [0] * 100

    # HR0 = temperature,  HR1 = pressure,  HR2 = flow rate
    # HR3–HR9 = auxiliary sensors with small random offsets
    regs[0] = profile["base_temp"] + random.randint(-5, 5)
    regs[1] = profile["base_pressure"] + random.randint(-2, 2)
    regs[2] = profile["base_flow"] + random.randint(-10, 10)
    for i in range(3, 10):
        regs[i] = random.randint(50, 500)

    return regs


def create_datastore() -> ModbusServerContext:
    """Create the Modbus datastore with initial register values."""
    hr_values = _build_initial_registers()
    ir_values = _build_initial_registers()

    store = ModbusDeviceContext(
        di=ModbusSequentialDataBlock(0, [random.choice([0, 1]) for _ in range(100)]),
        co=ModbusSequentialDataBlock(0, [0] * 100),
        hr=ModbusSequentialDataBlock(0, hr_values),
        ir=ModbusSequentialDataBlock(0, ir_values),
    )
    return ModbusServerContext(devices=store, single=True)


# ---------------------------------------------------------------------------
# Background sensor drift
# ---------------------------------------------------------------------------

def sensor_update_loop(context: ModbusServerContext):
    """Periodically mutate holding register values to simulate real
    process dynamics — temperature drift, pressure fluctuations, etc."""
    logger.info("Sensor drift thread started (interval=%ds)", SENSOR_UPDATE_INTERVAL)

    while True:
        try:
            time.sleep(SENSOR_UPDATE_INTERVAL)
            store = context[0x00]

            for addr in range(10):
                current = store.getValues(3, addr, count=1)[0]
                drift = random.randint(-3, 3)
                new_val = max(0, min(65535, current + drift))
                store.setValues(3, addr, [new_val])

            logger.debug("Sensor values updated")
        except Exception as exc:
            logger.error("Sensor update error: %s", exc)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    profile = SENSOR_PROFILES.get(SLAVE_ID, SENSOR_PROFILES[1])

    logger.info("=" * 60)
    logger.info("Modbus Slave %d  (%s)", SLAVE_ID, profile["name"])
    logger.info("Port: %d | Registers: 0-99 | Coils: 0-99", MODBUS_PORT)
    logger.info("=" * 60)

    context = create_datastore()

    # Log initial sensor state
    store = context[0x00]
    hr_vals = store.getValues(3, 0, count=10)
    logger.info("Initial HR[0-9]: %s", hr_vals)

    # Background thread for sensor drift
    updater = threading.Thread(
        target=sensor_update_loop, args=(context,), daemon=True
    )
    updater.start()

    # Start Modbus TCP server — blocks until process is killed
    logger.info("Listening on 0.0.0.0:%d …", MODBUS_PORT)
    StartTcpServer(context=context, address=("0.0.0.0", MODBUS_PORT))


if __name__ == "__main__":
    main()
