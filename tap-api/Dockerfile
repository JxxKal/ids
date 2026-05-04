FROM python:3.12-slim

# docker-ce-cli wird für /api/load gebraucht — `_sniffer_stats` ruft
# `docker logs cyjan-tap-sniffer` über den gemounteten /var/run/docker.sock,
# um pps/drop_pct/kafka_errors aus den letzten Stats-Zeilen rauszufischen.
# curl + ca-certificates sind die einzigen Build-Vorbedingungen für den
# Docker-Apt-Repo-Pfad.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates gnupg \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
    && chmod a+r /etc/apt/keyrings/docker.asc \
    && . /etc/os-release \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
       https://download.docker.com/linux/debian ${VERSION_CODENAME} stable" \
       > /etc/apt/sources.list.d/docker.list \
    && apt-get update && apt-get install -y --no-install-recommends docker-ce-cli \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src/ ./src/
COPY templates/ ./templates/
COPY static/ ./static/

EXPOSE 8000
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
