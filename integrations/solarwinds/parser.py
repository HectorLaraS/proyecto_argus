from __future__ import annotations

from typing import Any, Dict
from integrations.solarwinds.models import SolarWindsTrapParsed


def _build_varbinds_map(trap: Dict[str, Any]) -> Dict[str, str]:
    """
    Convierte trap['oids'] a un diccionario:
    {
        "<oid>": "<value>"
    }
    """
    varbinds: Dict[str, str] = {}

    for vb in trap.get("oids", []):
        oid = str(vb.get("oid", "")).strip()
        value = str(vb.get("value", "")).strip()

        if oid:
            varbinds[oid] = value

    return varbinds


def _detect_trap_oid(varbinds: Dict[str, str]) -> str:
    """
    Detecta el trap OID principal.
    Normalmente viene en snmpTrapOID.0
    """
    return varbinds.get("1.3.6.1.6.3.1.1.4.1.0", "").strip()


def _detect_enterprise_oid(trap_oid: str) -> str:
    """
    Extrae el enterprise OID desde el trap OID.
    Ejemplo:
      1.3.6.1.4.1.11307.10 -> 1.3.6.1.4.1.11307
      1.3.6.1.4.1.28914.5.3.1.101 -> 1.3.6.1.4.1.28914
    """
    raw = (trap_oid or "").strip()
    if not raw:
        return ""

    parts = raw.split(".")
    if len(parts) >= 7 and parts[:6] == ["1", "3", "6", "1", "4", "1"]:
        return ".".join(parts[:7])

    return ""


def build_raw_payload_json(trap: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convierte el trap recibido por ARGUS en una estructura base
    lista para guardarse como raw_payload_json.
    """
    varbinds = _build_varbinds_map(trap)
    trap_oid = _detect_trap_oid(varbinds)
    enterprise_oid = _detect_enterprise_oid(trap_oid)

    return {
        "received_at": str(trap.get("timestamp", "")).strip(),
        "src_ip": str(trap.get("src_ip", "")).strip(),
        "src_port": trap.get("src_port"),
        "community": str(trap.get("community", "")).strip(),
        "enterprise_oid": enterprise_oid,
        "trap_oid": trap_oid,
        "varbinds": varbinds,
    }


def _detect_vendor_name(varbinds: Dict[str, str], enterprise_oid: str) -> str:
    """
    Intenta detectar nombre del vendor.
    Primero busca valores conocidos en varbinds.
    Si no encuentra, usa enterprise_oid conocido.
    """
    for value in varbinds.values():
        normalized = value.strip()

        if "GE Transportation Systems Global Signaling" in normalized:
            return "GE Transportation Systems Global Signaling, LLC"

        if "Omnitronix" in normalized:
            return "Omnitronix, Inc."

    if enterprise_oid == "1.3.6.1.4.1.11307":
        return "GE / Omnitronix family"

    if enterprise_oid == "1.3.6.1.4.1.28914":
        return "GE Transportation Systems Global Signaling, LLC"

    return "Unknown"


def parse_solarwinds_trap(trap: Dict[str, Any]) -> SolarWindsTrapParsed:
    """
    Convierte el trap raw de ARGUS en un SolarWindsTrapParsed.
    """
    raw_payload = build_raw_payload_json(trap)
    varbinds = dict(raw_payload.get("varbinds", {}))
    enterprise_oid = str(raw_payload.get("enterprise_oid", "")).strip()

    return SolarWindsTrapParsed(
        received_at=str(raw_payload.get("received_at", "")).strip(),
        src_ip=str(raw_payload.get("src_ip", "")).strip(),
        src_port=raw_payload.get("src_port"),
        community=str(raw_payload.get("community", "")).strip(),
        enterprise_oid=enterprise_oid,
        trap_oid=str(raw_payload.get("trap_oid", "")).strip(),
        vendor_name=_detect_vendor_name(varbinds, enterprise_oid),
        raw_payload_json=raw_payload,
        varbinds=varbinds,
    )