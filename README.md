# ICS-Watchdog

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

ICS-Watchdog is a lightweight, containerised passive security monitoring tool designed for Operational Technology (OT) networks. It analyses Modbus/TCP traffic in real-time, detecting reconnaissance, malicious commands, and network anomalies mapped to the **MITRE ATT&CK® for ICS** framework.

## Features

- **Passive Sniffing**: Uses `scapy` and `tcpdump` to capture packets promiscuously without disrupting sensitive industrial equipment.
- **Stateful Rule Engine**: Evaluates traffic across time windows to detect complex behaviors (e.g., sequential scans, replay attacks, excessive write rates).
- **MITRE ICS Mapping**: Every alert is natively mapped to MITRE ATT&CK for ICS techniques (e.g., T0846, T0855, T0856).
- **JSON & HTML Reporting**: Generates structured machine-readable logs (`alerts.jsonl`) and beautiful HTML dashboards with Chart.js visualization.
- **Dockerised Architecture**: Easy deployment across modern edge devices or servers. Includes a built-in honeypot environment (Master/Slave simulation) and an attack injector for testing.

## Built-in Attack Scenarios

The project includes an `ics-injector` container capable of launching three distinct attacks against the simulated ICS network to validate detection capabilities:

1. **Reconnaissance Scan (T0846, T0843)**: Iterates over the network, sending multiple Modbus function codes and probing out-of-range registers to map device capabilities.
2. **Coil Write Injection (T0855)**: Rapidly issues unauthorised Write Single Coil (FC05) commands, simulating an attacker attempting to actuate physical relays or valves.
3. **Replay Attack (T0856)**: Crafts and transmits identical, byte-for-byte raw Modbus packets using Scapy to bypass protocol sequence numbers.

## Quick Start

### 1. Build and Start the Environment
```bash
# Clone the repository
git clone https://github.com/arnavparekar/ics-watchdog.git
cd ics-watchdog

# Build and start all 7 containers (Watchdog, Master, 3x Slaves, Injector, Reporter)
docker-compose up -d --build
```

### 2. Run Attack Scenarios
Once the stack is running, execute the built-in attack injector to simulate malicious traffic:
```bash
# Run the Reconnaissance Scan
docker exec ics-injector python3 inject.py --attack recon

# Run the Coil Write Injection
docker exec ics-injector python3 inject.py --attack coil-inject

# Run the Replay Attack
docker exec ics-injector python3 inject.py --attack replay
```

### 3. Generate and View Reports
The Watchdog passively logs all network telemetry and alerts to a shared Docker volume. To compile this into a final report:
```bash
# Generate the JSON and HTML reports
docker-compose build report-gen
docker run --rm -v ics-watchdog_watchdog-data:/app/output ics-watchdog-report-gen python3 report.py
```
The reports will be available in the `samples/` directory (if copied) or within the `ics-watchdog_watchdog-data` volume. You can view the stunning HTML dashboard by opening the generated `watchdog_report.html` file in your browser.

## Detection Rules

ICS-Watchdog currently ships with 8 core detection rules:

| Rule ID | Name | MITRE ICS Technique | Condition |
|---------|------|---------------------|-----------|
| **R-001** | Modbus Function Code Scan | T0846 (Remote System Discovery) | >10 distinct function codes from same src within 30s |
| **R-002** | Unauthorised Coil Write | T0855 (Unauthorized Command Message) | FC05 or FC15 from non-master IP |
| **R-003** | Register Read Flood | T0884 (Connection Probe) | >50 FC03 requests from same source within 10s |
| **R-004** | Sequential Scan Probe | T0846 (Remote System Discovery) | Broadcast packet or sequential scan of all slaves in 5s |
| **R-005** | Out-of-Range Access | T0855 (Unauthorized Command Message) | Reading registers > 9 (device limit) |
| **R-006** | New Source IP | T0843 (Program Download) | Modbus traffic from an unknown IP address |
| **R-007** | Replay Attack | T0856 (Spoof Reporting Message) | Identical Modbus packet payload retransmitted >3 times in 5s |
| **R-008** | Excessive Write Rate | T0855 (Unauthorized Command Message) | >20 write commands (FC05/06/15/16) in 10s |

## Sample Output

See the [`samples/`](samples/) directory for examples of the generated `watchdog_report.json` and `watchdog_report.html` outputs.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
