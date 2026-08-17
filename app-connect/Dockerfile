FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

# Operator-CLI: `docker compose exec app-connect cyjan-app status`.
# Bewusst ein Wrapper statt eines Console-Scripts — kein setup.py/Paket,
# gleiche Struktur wie die übrigen Services im Repo.
RUN printf '#!/bin/sh\nexec python -u /app/src/cli.py "$@"\n' > /usr/local/bin/cyjan-app \
    && chmod +x /usr/local/bin/cyjan-app

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Unprivilegiert laufen. Der Dienst braucht keine Wurzelrechte: er öffnet
# ausgehende Verbindungen, hört intern auf 8090 (>1024) und schreibt nur
# /tmp/heartbeat sowie die Zustandsdatei unter /run/cyjan — beides tmpfs.
# Feste UID, damit `user:` im Compose-File dazu passt.
RUN groupadd -g 10002 cyjan \
 && useradd -u 10002 -g 10002 -M -s /usr/sbin/nologin cyjan \
 && chown -R 10002:10002 /app

CMD ["python", "-u", "src/main.py"]
