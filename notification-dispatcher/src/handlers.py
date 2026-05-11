"""Plugin-Pattern für Notification-Handler.

Phase 1 implementiert WebhookHandler, NtfyHandler, EmailHandler. Phase 2
(Cyjan-Cloud-Companion-App) registriert nur einen weiteren Handler unter
dem Type-Key 'cyjan-cloud' — die bestehende Dispatcher-Logik bleibt
unverändert.

Jeder Handler implementiert:
  - send(alert_payload: dict, config: dict) -> DeliveryResult

Der Dispatcher schaut über `HANDLERS[channel.type]` den passenden Handler
und ruft .send(). Unbekannter Type → DeliveryResult mit status='failed'.
"""
from __future__ import annotations

import logging
import smtplib
from dataclasses import dataclass
from email.mime.text import MIMEText
from typing import Any, Awaitable, Callable

import httpx

log = logging.getLogger(__name__)


@dataclass
class DeliveryResult:
    status:      str              # 'sent' | 'failed' | 'rate_limited' | 'filtered' | 'disabled'
    status_code: int | None = None
    latency_ms:  int | None = None
    error:       str | None = None


# Handler-Type: alle handler haben dieselbe Signatur. Async damit wir
# httpx.AsyncClient effizient teilen können.
HandlerFn = Callable[[dict, dict, "DispatcherContext"], Awaitable[DeliveryResult]]


@dataclass
class DispatcherContext:
    """Geteilter Context — Connection-Pools etc. werden vom main.py erzeugt
    und an alle Handler durchgereicht."""
    http_client: httpx.AsyncClient
    smtp_host:     str
    smtp_port:     int
    smtp_user:     str
    smtp_password: str
    smtp_from:     str
    smtp_use_tls:  bool


# ────────────────────────────────────────────────────────────────────────
# Webhook — generischer POST mit konfigurierbaren Headers + Body-Template
# ────────────────────────────────────────────────────────────────────────

async def webhook_handler(
    alert: dict, config: dict, ctx: DispatcherContext,
) -> DeliveryResult:
    """Sendet alert-JSON als POST an config.url.

    config:
      url:           Pflicht
      headers:       Optional dict (Authorization, X-API-Key etc.)
      body_template: Optional 'alert' (default — sendet alert direkt) oder
                     'wrapped' (sendet {alert: ..., source: 'cyjan-ids'})
    """
    url = config.get("url")
    if not url:
        return DeliveryResult(status="failed", error="missing config.url")

    headers = dict(config.get("headers") or {})
    headers.setdefault("Content-Type", "application/json")
    headers.setdefault("User-Agent", "cyjan-ids/notification-dispatcher")

    template = config.get("body_template", "alert")
    if template == "wrapped":
        body = {"alert": alert, "source": "cyjan-ids", "schema_version": 1}
    else:
        body = alert

    import time
    t0 = time.monotonic()
    try:
        r = await ctx.http_client.post(url, json=body, headers=headers, timeout=10.0)
        latency = int((time.monotonic() - t0) * 1000)
        if 200 <= r.status_code < 300:
            return DeliveryResult(status="sent", status_code=r.status_code, latency_ms=latency)
        return DeliveryResult(
            status="failed", status_code=r.status_code, latency_ms=latency,
            error=r.text[:200],
        )
    except httpx.HTTPError as exc:
        return DeliveryResult(status="failed", error=str(exc)[:200])


# ────────────────────────────────────────────────────────────────────────
# ntfy.sh — spezialisierter Webhook mit ntfy-spezifischen Headers
# ────────────────────────────────────────────────────────────────────────

_NTFY_PRIORITY = {
    "low":      "3",
    "medium":   "3",
    "high":     "4",
    "critical": "5",
}


async def ntfy_handler(
    alert: dict, config: dict, ctx: DispatcherContext,
) -> DeliveryResult:
    """ntfy.sh-Push. config:
        server:   Default 'https://ntfy.sh'
        topic:    Pflicht — User-definiertes Topic, fungiert als 'Adresse'
        auth_token: Optional (für selbst-gehostete ntfy mit Auth)
    """
    server = (config.get("server") or "https://ntfy.sh").rstrip("/")
    topic  = config.get("topic")
    if not topic:
        return DeliveryResult(status="failed", error="missing config.topic")

    url = f"{server}/{topic}"
    severity = alert.get("severity") or "medium"
    rule_id  = alert.get("rule_id") or "?"
    src_ip   = alert.get("src_ip") or "?"
    dst_ip   = alert.get("dst_ip") or "?"
    desc     = alert.get("description") or alert.get("signature") or ""

    headers = {
        "Title":    f"[{severity.upper()}] {rule_id}",
        "Priority": _NTFY_PRIORITY.get(severity, "3"),
        "Tags":     "rotating_light," + severity,
        "User-Agent": "cyjan-ids/notification-dispatcher",
    }
    if config.get("auth_token"):
        headers["Authorization"] = f"Bearer {config['auth_token']}"

    body = f"{src_ip} → {dst_ip}\n{desc[:300]}"

    import time
    t0 = time.monotonic()
    try:
        r = await ctx.http_client.post(url, content=body.encode(), headers=headers, timeout=10.0)
        latency = int((time.monotonic() - t0) * 1000)
        if 200 <= r.status_code < 300:
            return DeliveryResult(status="sent", status_code=r.status_code, latency_ms=latency)
        return DeliveryResult(
            status="failed", status_code=r.status_code, latency_ms=latency,
            error=r.text[:200],
        )
    except httpx.HTTPError as exc:
        return DeliveryResult(status="failed", error=str(exc)[:200])


# ────────────────────────────────────────────────────────────────────────
# Email — SMTP (System-Default oder per-channel override)
# ────────────────────────────────────────────────────────────────────────

async def email_handler(
    alert: dict, config: dict, ctx: DispatcherContext,
) -> DeliveryResult:
    """Sendet Email via System-SMTP. config:
        to:        Pflicht — Empfänger
        subject:   Optional — Default '[severity] rule_id'
    """
    to = config.get("to")
    if not to:
        return DeliveryResult(status="failed", error="missing config.to")
    if not ctx.smtp_host:
        return DeliveryResult(status="failed", error="SMTP not configured (set SMTP_HOST)")

    severity = alert.get("severity") or "medium"
    rule_id  = alert.get("rule_id") or "?"
    subject  = config.get("subject") or f"[{severity.upper()}] Cyjan-IDS: {rule_id}"

    body_lines = [
        f"Cyjan-IDS Alert",
        f"",
        f"Time:        {alert.get('ts')}",
        f"Rule:        {rule_id}",
        f"Severity:    {severity}",
        f"Source:      {alert.get('source','?')}",
        f"Source-IP:   {alert.get('src_ip','?')}",
        f"Dest-IP:     {alert.get('dst_ip','?')}:{alert.get('dst_port','?')}",
        f"Protocol:    {alert.get('proto','?')}",
        f"",
        f"Description: {alert.get('description') or alert.get('signature') or ''}",
        f"",
        f"-- ",
        f"Cyjan IDS · Auto-Notification",
    ]
    msg = MIMEText("\n".join(body_lines), "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"]    = ctx.smtp_from
    msg["To"]      = to

    import time
    t0 = time.monotonic()
    try:
        # Sync SMTP in einem Thread-Executor — smtplib hat keine async-Variante
        # in der Standard-Lib. Für V1 ok; bei Volumen-Skalierung später aiosmtplib.
        import asyncio
        await asyncio.get_event_loop().run_in_executor(None, _smtp_send_sync, ctx, msg, to)
        latency = int((time.monotonic() - t0) * 1000)
        return DeliveryResult(status="sent", latency_ms=latency)
    except Exception as exc:
        return DeliveryResult(status="failed", error=str(exc)[:200])


def _smtp_send_sync(ctx: DispatcherContext, msg: MIMEText, to: str) -> None:
    with smtplib.SMTP(ctx.smtp_host, ctx.smtp_port, timeout=15) as smtp:
        if ctx.smtp_use_tls:
            smtp.starttls()
        if ctx.smtp_user and ctx.smtp_password:
            smtp.login(ctx.smtp_user, ctx.smtp_password)
        smtp.send_message(msg, from_addr=ctx.smtp_from, to_addrs=[to])


# ────────────────────────────────────────────────────────────────────────
# Registry — Phase 2 fügt hier ihren Handler hinzu
# ────────────────────────────────────────────────────────────────────────

HANDLERS: dict[str, HandlerFn] = {
    "webhook": webhook_handler,
    "ntfy":    ntfy_handler,
    "email":   email_handler,
    # Phase 2 wird hier hinzufügen:
    # "cyjan-cloud": cyjan_cloud_handler,
    # "fcm":         fcm_handler,
    # "apns":        apns_handler,
}


def known_types() -> list[str]:
    return sorted(HANDLERS.keys())


async def dispatch_to(
    type_: str, alert: dict, config: dict, ctx: DispatcherContext,
) -> DeliveryResult:
    handler = HANDLERS.get(type_)
    if not handler:
        return DeliveryResult(status="failed", error=f"unknown channel type: {type_!r}")
    try:
        return await handler(alert, config, ctx)
    except Exception as exc:
        log.exception("handler %s crashed", type_)
        return DeliveryResult(status="failed", error=f"handler crash: {exc!s}"[:200])
