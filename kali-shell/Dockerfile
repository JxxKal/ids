# kali-shell — Minimal Kali-Container für CYJAN Auto-RedTeam.
# Netzwerk-isoliert (network_mode: none), read-only Rootfs, non-root,
# seccomp-locked. Kommuniziert ausschließlich über docker exec vom
# redteam-orchestrator. Keine offenen Ports, kein Listener.

FROM kalilinux/kali-rolling:latest

ARG DEBIAN_FRONTEND=noninteractive
ARG PROXY_URL=""
ENV http_proxy=${PROXY_URL} https_proxy=${PROXY_URL}

# Minimal Pen-Test-Tooling. BEWUSST AUSGESCHLOSSEN:
#   - openssh-server / -client    (kein Remote-Access)
#   - sudo                         (keine Priv-Esc-Pfade)
#   - cron / systemd               (kein Scheduler)
#   - python3-requests             (vermeidet HTTP-Egress-Libs)
RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends \
      ca-certificates \
      iproute2 \
      iputils-ping \
      tcpdump \
      nmap \
      hydra \
      hping3 \
      libcap2-bin \
      python3 \
      python3-yaml \
      python3-pymodbus \
      netcat-openbsd \
 && apt-get autoremove -y \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* /var/cache/apt /tmp/* /var/tmp/*

# File-Capabilities setzen — wir laufen non-root mit cap_drop ALL +
# cap_add NET_RAW. Damit non-setuid-Binaries die NET_RAW-Capability auch
# tatsächlich nutzen, brauchen sie das file-cap. apt-get strippt das
# manchmal in --no-install-recommends; setcap idempotent.
# setcap einzeln statt &&-verkettet — sonst bricht die erste fehlende
# Binary die ganze Kette und || true swallowed nur den Combined-Exit.
RUN setcap cap_net_raw+ep /usr/bin/ping || true
RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+ep /usr/bin/nmap || true
RUN setcap cap_net_raw+ep /usr/sbin/hping3 || true

# Non-root user — UID 1000 matched Default-Host-User
RUN groupadd -g 1000 redteam \
 && useradd  -u 1000 -g 1000 -m -s /bin/bash redteam \
 && mkdir -p /opt/cyjan \
 && chown -R redteam:redteam /opt/cyjan

# Tool-Whitelist + Runner werden als Read-only kopiert
COPY --chown=redteam:redteam kali_runner.py   /opt/cyjan/kali_runner.py
COPY --chown=redteam:redteam allowed_tools.yml /opt/cyjan/allowed_tools.yml

USER redteam
WORKDIR /opt/cyjan

# Default-CMD = sleep infinity — sichersten Container-Default:
# keine Listener, keine Auto-Actions. Tools werden via docker exec aufgerufen.
CMD ["sleep", "infinity"]
