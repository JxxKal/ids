"""POST /api/mqtt/test — Connection-Test für die MQTT-Bridge-Konfiguration.

Der Endpoint baut eine kurzlebige paho-mqtt-Connection mit den vom User
in der Settings-UI eingegebenen Werten auf, publiziert ein Test-Topic
(`<prefix>/<host>/test`) als retain=false QoS-1 und wartet auf PUBACK.
Erfolg → 200 mit duration_ms; Fehler → 4xx mit klarer Message.

Kein Touch des laufenden mqtt-bridge-Containers — der hat seine eigene,
laufende Connection. Hier ist nur Validierung, ob die Credentials in
Kombination mit Broker-URL stimmen.
"""
from __future__ import annotations

import asyncio
import logging
import ssl
import time
import uuid
from typing import Optional

import paho.mqtt.client as mqtt
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from deps import require_admin

router = APIRouter(prefix="/api/mqtt", tags=["mqtt"])
log = logging.getLogger(__name__)


class MqttTestRequest(BaseModel):
    broker_host: str
    broker_port: int = Field(default=8883, ge=1, le=65535)
    use_tls: bool = True
    tls_verify: bool = True
    username: str = ""
    password: str = ""
    client_id: str = ""
    topic_prefix: str = "cyjan"
    master_host_id: str = "master"


class MqttTestResponse(BaseModel):
    ok: bool
    duration_ms: int
    test_topic: str
    detail: Optional[str] = None


@router.post("/test", response_model=MqttTestResponse, dependencies=[Depends(require_admin)])
async def test_mqtt_connection(req: MqttTestRequest) -> MqttTestResponse:
    test_topic = f"{req.topic_prefix.strip('/') or 'cyjan'}/{req.master_host_id or 'master'}/test"
    client_id  = req.client_id or f"cyjan-test-{uuid.uuid4().hex[:8]}"

    # paho ist sync — wir packen den Test in eine Thread, damit die
    # API-Eventloop nicht blockt.
    def _do_test() -> tuple[bool, int, Optional[str]]:
        client = mqtt.Client(
            client_id=client_id,
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            clean_session=True,
        )
        if req.username:
            client.username_pw_set(req.username, req.password)
        if req.use_tls:
            ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            if not req.tls_verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            client.tls_set_context(ctx)

        connect_done = {"rc": None}
        publish_done = {"mid": None}

        def on_connect(c, u, f, rc, p=None):
            connect_done["rc"] = rc

        def on_publish(c, u, mid, *args):
            publish_done["mid"] = mid

        client.on_connect = on_connect
        client.on_publish = on_publish

        t0 = time.time()
        try:
            client.connect(req.broker_host, req.broker_port, keepalive=10)
        except Exception as exc:
            return False, int((time.time() - t0) * 1000), f"connect: {exc}"

        client.loop_start()
        try:
            # Wait for CONNACK (max 10s)
            for _ in range(100):
                if connect_done["rc"] is not None:
                    break
                time.sleep(0.1)
            rc = connect_done["rc"]
            if rc is None:
                return False, int((time.time() - t0) * 1000), "connect timeout (10s)"
            # paho v5 CallbackAPI: rc kann int oder ReasonCode sein
            rc_failure = (
                rc.is_failure if hasattr(rc, "is_failure")
                else rc != mqtt.MQTT_ERR_SUCCESS
            )
            if rc_failure:
                return False, int((time.time() - t0) * 1000), f"connack failure: rc={rc}"

            # Publish + wait for PUBACK
            info = client.publish(test_topic, payload=b"cyjan-mqtt-bridge-test", qos=1, retain=False)
            if info.rc != mqtt.MQTT_ERR_SUCCESS:
                return False, int((time.time() - t0) * 1000), f"publish-rc {info.rc}"
            target_mid = info.mid
            for _ in range(50):
                if publish_done["mid"] == target_mid:
                    break
                time.sleep(0.1)
            if publish_done["mid"] != target_mid:
                return False, int((time.time() - t0) * 1000), "puback timeout (5s)"

            return True, int((time.time() - t0) * 1000), None
        finally:
            try:
                client.loop_stop()
                client.disconnect()
            except Exception:
                pass

    try:
        ok, duration_ms, detail = await asyncio.to_thread(_do_test)
    except Exception as exc:
        log.warning("mqtt-test crashed: %s", exc)
        raise HTTPException(status_code=500, detail=f"test crashed: {exc}")

    if not ok:
        return MqttTestResponse(ok=False, duration_ms=duration_ms, test_topic=test_topic, detail=detail)
    return MqttTestResponse(ok=True, duration_ms=duration_ms, test_topic=test_topic)
