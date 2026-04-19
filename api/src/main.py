"""
IDS API – FastAPI Einstiegspunkt.

Endpunkte:
  GET  /api/alerts                      – Alert-Liste (Filter, Pagination)
  GET  /api/alerts/{id}                 – Einzelner Alert
  PATCH /api/alerts/{id}/feedback       – Feedback setzen (fp/tp)
  GET  /api/alerts/{id}/pcap            – PCAP-Datei herunterladen (MinIO-Proxy)
  GET  /api/flows                       – Flow-Liste (Filter, Pagination)
  GET  /api/stats/threat-level          – Aktueller Threat-Level (0–100)
  GET  /api/networks                    – Bekannte Netzwerke
  POST /api/networks                    – Netzwerk anlegen
  DELETE /api/networks/{id}             – Netzwerk löschen
  GET  /api/config                      – System-Konfiguration
  GET  /api/config/{key}                – Einzelner Config-Key
  PATCH /api/config/{key}               – Config-Key aktualisieren
  POST /api/tests/run                   – Test-Szenario auslösen
  GET  /api/tests/runs                  – Test-Run-Protokoll
  GET  /api/tests/runs/{id}             – Einzelner Test-Run

WebSocket:
  WS   /ws/alerts                       – Echtzeit-Alert-Stream
"""
from __future__ import annotations

import asyncio
import logging

import orjson
from confluent_kafka import Producer
from fastapi import Depends, FastAPI, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from jose import JWTError
from minio import Minio

from config import Config
from database import close_pool, init_pool
from deps import get_current_user
from routers import alerts as alerts_router
from routers import auth as auth_router
from routers import flows as flows_router
from routers import hosts as hosts_router
from routers import networks as networks_router
from routers import ml as ml_router
from routers import rules as rules_router
from routers import system as system_router
from routers import tests as tests_router
from routers import users as users_router
from routers.alerts import make_pcap_endpoint, set_feedback_producer
from routers.tests import make_run_endpoint
from ws.manager import AlertStreamer, ConnectionManager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s – %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("api")

cfg = Config.from_env()

app = FastAPI(
    title="Cyjan IDS API",
    version="1.0.0",
    description=(
        "REST API + WebSocket für das Cyjan Passive Network IDS.\n\n"
        "**Authentifizierung:** Zuerst `POST /api/auth/login` aufrufen, "
        "den `access_token` kopieren und oben rechts auf **Authorize** klicken "
        "(`Bearer <token>` wird automatisch gesetzt)."
    ),
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)


def _custom_openapi() -> dict:
    if app.openapi_schema:
        return app.openapi_schema
    schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    schema.setdefault("components", {})
    schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "JWT-Token aus POST /api/auth/login → access_token",
        }
    }
    # Alle Endpunkte standardmäßig mit BearerAuth absichern
    schema["security"] = [{"BearerAuth": []}]
    app.openapi_schema = schema
    return schema


app.openapi = _custom_openapi  # type: ignore[method-assign]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Globale Objekte ────────────────────────────────────────────────────────────

ws_manager  = ConnectionManager()
alert_queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
streamer:    AlertStreamer | None = None

minio_client = Minio(
    cfg.minio_endpoint,
    access_key=cfg.minio_access_key,
    secret_key=cfg.minio_secret_key,
    secure=False,
)

kafka_producer = Producer({
    "bootstrap.servers": cfg.kafka_brokers,
    "acks": "1",
})

# ── Routers einbinden ─────────────────────────────────────────────────────────
# WICHTIG: make_*_endpoint vor include_router aufrufen – FastAPI kopiert die
# Routes beim include_router-Aufruf; später hinzugefügte Routen werden ignoriert.

set_feedback_producer(kafka_producer)
make_pcap_endpoint(minio_client, cfg.pcap_bucket)
make_run_endpoint(kafka_producer)

_auth = [Depends(get_current_user)]

# Auth-Router ohne Schutz (Login ist öffentlich)
app.include_router(auth_router.router)

# Alle anderen Routen erfordern gültiges JWT
app.include_router(alerts_router.router,   dependencies=_auth)
app.include_router(flows_router.router,    dependencies=_auth)
app.include_router(hosts_router.router,    dependencies=_auth)
app.include_router(networks_router.router, dependencies=_auth)
app.include_router(ml_router.router,       dependencies=_auth)
app.include_router(rules_router.router,    dependencies=_auth)
app.include_router(system_router.router,   dependencies=_auth)
app.include_router(tests_router.router,    dependencies=_auth)
app.include_router(users_router.router,    dependencies=_auth)


# ── Lifecycle ─────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup() -> None:
    global streamer
    await init_pool(cfg.postgres_dsn)
    log.info("DB pool initialised")

    # WebSocket-Broadcast-Task
    asyncio.create_task(_broadcast_loop())

    # Kafka-Consumer-Thread für WebSocket-Alerts
    loop = asyncio.get_event_loop()
    streamer = AlertStreamer(cfg.kafka_brokers, alert_queue)
    streamer.start(loop)
    log.info("API startup complete")


@app.on_event("shutdown")
async def shutdown() -> None:
    if streamer:
        streamer.stop()
    kafka_producer.flush(timeout=5)
    await close_pool()
    log.info("API shutdown complete")


async def _broadcast_loop() -> None:
    """Liest aus der Alert-Queue und sendet an alle WebSocket-Clients."""
    while True:
        try:
            msg = await asyncio.wait_for(alert_queue.get(), timeout=5.0)
            await ws_manager.broadcast(msg)
        except asyncio.TimeoutError:
            continue
        except Exception as exc:
            log.debug("Broadcast loop error: %s", exc)


# ── WebSocket ─────────────────────────────────────────────────────────────────

@app.websocket("/ws/alerts")
async def ws_alerts(
    ws:    WebSocket,
    token: str | None = Query(default=None),
) -> None:
    # JWT-Prüfung – Token kommt als ?token=... da Browser-WS keine Header unterstützen
    from jwt_utils import decode_token
    if not token:
        await ws.close(code=4001, reason="Nicht authentifiziert")
        return
    try:
        decode_token(cfg.secret_key, token)
    except JWTError:
        await ws.close(code=4001, reason="Token ungültig")
        return

    await ws_manager.connect(ws)
    try:
        # Letzte 50 Alerts als initiales Paket senden
        from database import get_pool
        pool = get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT * FROM alerts
                ORDER BY ts DESC
                LIMIT 50
                """
            )
        from routers.alerts import _row_to_alert
        initial = [_row_to_alert(r).model_dump(mode="json") for r in reversed(rows)]
        await ws.send_text(
            orjson.dumps({"type": "initial", "data": initial}).decode()
        )

        # Verbindung offen halten
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        await ws_manager.disconnect(ws)


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}
