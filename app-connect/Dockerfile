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

CMD ["python", "-u", "src/main.py"]
