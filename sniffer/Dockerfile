# ══════════════════════════════════════════════════════════════════════════════
# IDS Sniffer – Multi-Stage Dockerfile
# Stage 1: Build (Rust + libpcap-dev + cmake für rdkafka)
# Stage 2: Runtime (nur libpcap.so + Binary)
# ══════════════════════════════════════════════════════════════════════════════

# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM rust:1.85-slim AS builder

RUN apt-get update && apt-get install -y \
    # pcap crate
    libpcap-dev \
    pkg-config \
    # rdkafka cmake-build: librdkafka 2.x aus Quellen kompilieren
    # cmake-build statisch linken → kein System-librdkafka nötig
    # libcurl4-openssl-dev: rdkafka_conf.c in librdkafka 2.12 inkludiert
    # curl/curl.h auch wenn WITH_CURL=0 gesetzt ist (Bug in 2.12.1)
    cmake \
    build-essential \
    libssl-dev \
    zlib1g-dev \
    libcurl4-openssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# ── Dependency-Caching ────────────────────────────────────────────────────────
# Erst Cargo.toml + Cargo.lock kopieren und mit Dummy-main builden.
# Docker-Layer-Cache: dieser teure Schritt wird nur bei Dependency-Änderungen
# wiederholt, nicht bei Source-Code-Änderungen.
COPY Cargo.toml ./
# Cargo.lock optional: vorhanden → reproduzierbarer Build; fehlt → cargo löst auf
COPY Cargo.loc[k] ./
RUN mkdir -p src \
    && echo 'fn main() { println!("placeholder"); }' > src/main.rs \
    && cargo build --release \
    && rm -rf src

# ── Source Build ──────────────────────────────────────────────────────────────
COPY src ./src
# touch erzwingt Neukompilierung des eigenen Codes
RUN touch src/main.rs && cargo build --release

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    libpcap0.8 \
    libcurl4 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Binary aus Build-Stage kopieren
COPY --from=builder /build/target/release/sniffer /usr/local/bin/sniffer

# Kein Root-User nötig außer für AF_PACKET (CAP_NET_RAW/CAP_NET_ADMIN werden
# über docker-compose gesetzt, nicht über USER-Direktive)

ENTRYPOINT ["sniffer"]
