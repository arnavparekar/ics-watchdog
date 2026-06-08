FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir pymodbus==3.12.1 scapy

COPY . .

CMD ["tail", "-f", "/dev/null"]
