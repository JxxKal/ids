FROM python:3.12-slim

# Base-Tools: curl für CLI-Download, nsenter (util-linux) + iproute2 für
# veth-Handover. Docker-CLI nicht via apt (docker.io-Paket auf Slim-Debian
# liefert kein /usr/bin/docker), sondern als Static-Binary direkt von
# docker.com — minimaler Footprint, keine Daemon-Abhängigkeit.
ARG DOCKER_CLI_VERSION=27.5.1
RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      iproute2 \
      util-linux \
 && curl -fsSL "https://download.docker.com/linux/static/stable/x86_64/docker-${DOCKER_CLI_VERSION}.tgz" \
      | tar -xz -C /tmp \
 && cp /tmp/docker/docker /usr/local/bin/docker \
 && chmod +x /usr/local/bin/docker \
 && rm -rf /tmp/docker \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* /var/cache/apt /tmp/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ /app/

USER root
EXPOSE 8002

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8002"]
