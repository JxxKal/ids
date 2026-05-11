FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive

# Suricata 7.x ist in Debian Trixie (Debian 13 stable) in main verfügbar —
# Bookworm hatte nur 6.0, deshalb der Base-Image-Switch. 7.x bringt:
#  - native HTTP/2 + QUIC + MQTT + DOIP app-layer-Parser
#  - bessere SMB2/SMB3-Detection inkl. NTLM-Auth-Tracking
#  - Erweiterte Kerberos-Telemetrie (KRB5 cipher etype, ticket lifetime)
#  - Modbus-Parser ist deutlich robuster gegen mal-formed Pakete
# S7Comm bleibt auch in 7.x NICHT als nativer Parser — Detection nur über
# byte-content-Rules; das hat aber keinen Block-Charakter für unsere Templates.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        suricata \
        curl \
        iproute2 \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/log/suricata /etc/suricata/rules

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
