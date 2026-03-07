from __future__ import annotations

import json
from datetime import datetime

from integrations.solarwinds.models import SolarWindsTrapParsed
from storage.mssql_connection import get_connection


def _parse_received_at(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")


def save_solarwinds_trap(parsed: SolarWindsTrapParsed) -> None:
    raw_payload_json = json.dumps(parsed.raw_payload_json, ensure_ascii=False)

    sql = """
    INSERT INTO dbo.sw_traps (
        received_at,
        src_ip,
        src_port,
        community,
        enterprise_oid,
        trap_oid,
        vendor_name,
        raw_payload_json
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """

    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    sql,
                    _parse_received_at(parsed.received_at),
                    parsed.src_ip,
                    parsed.src_port,
                    parsed.community,
                    parsed.enterprise_oid,
                    parsed.trap_oid,
                    parsed.vendor_name,
                    raw_payload_json,
                )
                conn.commit()

        print("[SOLARWINDS] Trap guardado en MSSQL")

    except Exception as exc:
        print("[SOLARWINDS][DB ERROR]")
        print(exc)

def list_solarwinds_traps(limit: int = 100) -> list[dict]:
    sql = """
    SELECT TOP (?)
        trap_id,
        received_at,
        src_ip,
        src_port,
        community,
        enterprise_oid,
        trap_oid,
        vendor_name,
        raw_payload_json,
        created_at
    FROM dbo.sw_traps
    ORDER BY trap_id DESC
    """

    items: list[dict] = []

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, limit)
            rows = cur.fetchall()

            for row in rows:
                items.append(
                    {
                        "trap_id": row.trap_id,
                        "received_at": str(row.received_at),
                        "src_ip": row.src_ip,
                        "src_port": row.src_port,
                        "community": row.community,
                        "enterprise_oid": row.enterprise_oid,
                        "trap_oid": row.trap_oid,
                        "vendor_name": row.vendor_name,
                        "raw_payload_json": row.raw_payload_json,
                        "created_at": str(row.created_at),
                    }
                )

    return items


def list_solarwinds_traps_since(last_trap_id: int, limit: int = 100) -> list[dict]:
    sql = """
    SELECT TOP (?)
        trap_id,
        received_at,
        src_ip,
        src_port,
        community,
        enterprise_oid,
        trap_oid,
        vendor_name,
        raw_payload_json,
        created_at
    FROM dbo.sw_traps
    WHERE trap_id > ?
    ORDER BY trap_id ASC
    """

    items: list[dict] = []

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, limit, last_trap_id)
            rows = cur.fetchall()

            for row in rows:
                items.append(
                    {
                        "trap_id": row.trap_id,
                        "received_at": str(row.received_at),
                        "src_ip": row.src_ip,
                        "src_port": row.src_port,
                        "community": row.community,
                        "enterprise_oid": row.enterprise_oid,
                        "trap_oid": row.trap_oid,
                        "vendor_name": row.vendor_name,
                        "raw_payload_json": row.raw_payload_json,
                        "created_at": str(row.created_at),
                    }
                )

    return items