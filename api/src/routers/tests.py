"""Test-Szenarien und Test-Run-Protokoll."""
from __future__ import annotations

import time
import uuid
from typing import Annotated

import asyncpg
import orjson
from confluent_kafka import Producer
from fastapi import APIRouter, Depends, HTTPException, Query

from database import get_pool
from models import TestRunRequest, TestRunResponse

router = APIRouter(prefix="/api/tests", tags=["tests"])

# Bekannte Test-Szenarien (scenario_id → erwartete Regel-ID)
_SCENARIOS: dict[str, dict] = {
    "TEST_001":    {"expected_rule": "TEST_001",    "description": "IDS Test Signature"},
    "SCAN_001":    {"expected_rule": "SCAN_001",    "description": "TCP SYN Port Scan"},
    "DOS_SYN_001": {"expected_rule": "DOS_SYN_001", "description": "SYN Flood"},
    "RECON_003":   {"expected_rule": "RECON_003",   "description": "ICMP Host Sweep"},
    "DNS_DGA_001": {"expected_rule": "DNS_DGA_001", "description": "DNS High-Entropy (DGA)"},
}


def _row_to_run(row: asyncpg.Record) -> TestRunResponse:
    return TestRunResponse(
        id=row["id"],
        scenario_id=row["scenario_id"],
        started_at=row["started_at"],
        completed_at=row["completed_at"],
        status=row["status"],
        expected_rule=row["expected_rule"],
        triggered=row["triggered"],
        alert_id=row["alert_id"],
        latency_ms=row["latency_ms"],
        error=row["error"],
    )


def make_run_endpoint(producer: Producer):
    @router.post("/run", response_model=TestRunResponse, status_code=202)
    async def run_test(
        body: TestRunRequest,
        pool: asyncpg.Pool = Depends(get_pool),
    ) -> TestRunResponse:
        scenario = _SCENARIOS.get(body.scenario_id)
        if not scenario:
            raise HTTPException(
                status_code=422,
                detail=f"Unknown scenario '{body.scenario_id}'. "
                       f"Available: {list(_SCENARIOS)}",
            )

        run_id = str(uuid.uuid4())

        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO test_runs (id, scenario_id, expected_rule, status)
                VALUES ($1::uuid, $2, $3, 'running')
                RETURNING *
                """,
                run_id,
                body.scenario_id,
                scenario["expected_rule"],
            )

        # Test-Kommando an traffic-generator schicken
        command = {
            "run_id":      run_id,
            "scenario_id": body.scenario_id,
            "ts":          time.time(),
        }
        producer.produce("test-commands", value=orjson.dumps(command))
        producer.poll(0)

        return _row_to_run(row)

    return run_test


@router.get("/runs", response_model=list[TestRunResponse])
async def list_runs(
    limit:  Annotated[int, Query(ge=1, le=200)] = 50,
    pool:   asyncpg.Pool = Depends(get_pool),
) -> list[TestRunResponse]:
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM test_runs ORDER BY started_at DESC LIMIT $1", limit
        )
    return [_row_to_run(r) for r in rows]


@router.get("/runs/{run_id}", response_model=TestRunResponse)
async def get_run(run_id: str, pool: asyncpg.Pool = Depends(get_pool)) -> TestRunResponse:
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM test_runs WHERE id = $1::uuid", run_id
        )
    if not row:
        raise HTTPException(status_code=404, detail="Test run not found")
    return _row_to_run(row)


@router.delete("/runs/{run_id}", status_code=204, response_model=None)
async def delete_run(run_id: str, pool: asyncpg.Pool = Depends(get_pool)) -> None:
    async with pool.acquire() as conn:
        result = await conn.execute(
            "DELETE FROM test_runs WHERE id = $1::uuid", run_id
        )
    if result == "DELETE 0":
        raise HTTPException(status_code=404, detail="Test run not found")


@router.delete("/runs", status_code=204, response_model=None)
async def delete_all_runs(pool: asyncpg.Pool = Depends(get_pool)) -> None:
    """Löscht alle Test-Run-Einträge (z.B. um hängengebliebene 'running'-Einträge zu bereinigen)."""
    async with pool.acquire() as conn:
        await conn.execute("DELETE FROM test_runs")
