#!/usr/bin/env python3
"""
ICS-Watchdog — Attack Injection CLI

Executes simulated OT attacks against the Modbus/TCP network.
Used to trigger detection rules in the watchdog container.
"""

import argparse
import logging
import sys

from scenarios import recon, coil_inject, replay

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [INJECTOR] %(levelname)s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("injector")

def main():
    parser = argparse.ArgumentParser(description="Inject simulated attacks into the ICS network.")
    parser.add_argument(
        "--attack",
        type=str,
        required=True,
        choices=["recon", "coil-inject", "replay"],
        help="The attack scenario to execute."
    )
    
    args = parser.parse_args()

    if args.attack == "recon":
        recon.run()
    elif args.attack == "coil-inject":
        coil_inject.run()
    elif args.attack == "replay":
        replay.run()
    else:
        logger.error("Unknown attack type.")
        sys.exit(1)

if __name__ == "__main__":
    main()
