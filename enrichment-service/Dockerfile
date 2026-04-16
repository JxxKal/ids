FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ .

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# GeoIP-Datenbank-Pfade (optional – MaxMind GeoLite2)
# Dateien müssen ins Image oder per Volume gemountet werden:
#   /geoip/GeoLite2-City.mmdb
#   /geoip/GeoLite2-ASN.mmdb
ENV GEOIP_CITY_DB=/geoip/GeoLite2-City.mmdb
ENV GEOIP_ASN_DB=/geoip/GeoLite2-ASN.mmdb

CMD ["python", "main.py"]
