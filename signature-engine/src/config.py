import ipaddress
import logging
import os
from dataclasses import dataclass, field

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Config:
    kafka_brokers: str
    rules_dir: str
    # Wie oft auf geänderte Regel-Dateien geprüft wird (Hot-Reload)
    reload_interval_s: float
    test_mode: bool
    # Phase-2 Shadow-Metrik-Pipeline:
    # Pro evaluiertem Flow wird mit Wahrscheinlichkeit metrics_sampling_rate
    # (Bernoulli) ein Bündel `rule-metrics`-Records auf metrics_topic
    # geschrieben — einer pro `(rule, param)` mit `metric:`-Deklaration.
    # Sampling spart Volumen: bei 1 % und ~10k Flows/s landen ~100 Sample-
    # Bündel/s im Topic. Komplett deaktivierbar über metrics_enabled=false.
    metrics_enabled: bool
    metrics_topic: str
    metrics_sampling_rate: float
    # Self-Traffic-Filter: IPs/CIDRs der eigenen IDS-Hosts (Master + Tap-
    # Mgmt-IPs). Flows wo src ODER dst eine dieser IPs ist, werden
    # komplett übersprungen — kein Alert, keine Metrik. Verhindert FPs
    # durch enrichment-service-ICMP-Pings (DOS_ICMP_001-Flood) und
    # ähnlichen IDS-eigenen Traffic der vom Mirror-Port mit-erfasst wird.
    own_ips: frozenset = field(default_factory=frozenset)
    own_nets: tuple = field(default_factory=tuple)

    @classmethod
    def from_env(cls) -> "Config":
        try:
            rate = float(os.environ.get("METRICS_SAMPLING_RATE", "0.01"))
        except ValueError:
            rate = 0.01
        # Clamp auf [0, 1] — Werte außerhalb ergeben keinen Sinn und
        # wurden in der Vergangenheit schon mal als Tippfehler gesetzt.
        rate = max(0.0, min(1.0, rate))

        own_ips, own_nets = _parse_own_ips(os.environ.get("IDS_OWN_IPS", ""))
        if own_ips or own_nets:
            log.info("Self-Traffic-Filter aktiv: %d IPs, %d CIDRs",
                     len(own_ips), len(own_nets))

        return cls(
            kafka_brokers=os.environ.get("KAFKA_BROKERS", "localhost:9092"),
            rules_dir=os.environ.get("RULES_DIR", "/rules"),
            reload_interval_s=30.0,
            test_mode=os.environ.get("TEST_MODE", "false").lower() == "true",
            metrics_enabled=os.environ.get("METRICS_ENABLED", "true").lower() == "true",
            metrics_topic=os.environ.get("METRICS_TOPIC", "rule-metrics"),
            metrics_sampling_rate=rate,
            own_ips=frozenset(own_ips),
            own_nets=tuple(own_nets),
        )


def _parse_own_ips(env_str: str):
    """Parst IDS_OWN_IPS env-Var: comma-separated, akzeptiert Single-IPs
    UND CIDRs gemischt. Single-IPs landen in einem Set für O(1)-Lookup,
    CIDRs als ip_network-Tupel für CIDR-Match.

    Beispiel:  "10.0.0.5,10.10.20.0/24,fd00::1"
    """
    ips: set[str] = set()
    nets: list = []
    for raw in (env_str or "").split(","):
        raw = raw.strip()
        if not raw:
            continue
        try:
            if "/" in raw:
                nets.append(ipaddress.ip_network(raw, strict=False))
            else:
                # Normalisierte String-Form (zero-stripped, comma-folded)
                ips.add(str(ipaddress.ip_address(raw)))
        except ValueError as exc:
            log.warning("IDS_OWN_IPS: ignoriere ungültigen Eintrag '%s': %s", raw, exc)
    return ips, nets
