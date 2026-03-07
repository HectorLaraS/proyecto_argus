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