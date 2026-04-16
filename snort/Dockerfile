FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# snort3 ist in Debian Bookworm (main) direkt verfügbar – kein PPA nötig
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        snort3 \
        curl \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/log/snort /etc/snort/rules

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
