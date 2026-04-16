FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# Suricata ist in Debian Bookworm main direkt verfügbar.
# snort3 hat kein offizielles Debian/Ubuntu-Paket.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        suricata \
        curl \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/log/suricata /etc/suricata/rules

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
