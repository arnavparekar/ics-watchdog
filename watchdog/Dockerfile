FROM python:3.11-slim

WORKDIR /app

# System dependencies for packet capture
RUN apt-get update && apt-get install -y --no-install-recommends \
    tcpdump \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir scapy python-dateutil

COPY . .

CMD ["python3", "-u", "watchdog.py"]
