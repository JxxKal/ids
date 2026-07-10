FROM python:3.12-slim

# arpwatch selbst + libpcap (als Dependency gezogen). Kein sendmail nötig —
# wir fahren arpwatch mit -d (kein Mail, Reports auf stderr).
RUN apt-get update \
    && apt-get install -y --no-install-recommends arpwatch \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src/ ./src/

# Default-Verzeichnis für die arp.dat-Zustandsdatei (per Volume überschrieben).
RUN mkdir -p /var/lib/arpwatch

CMD ["python", "-u", "src/main.py"]
