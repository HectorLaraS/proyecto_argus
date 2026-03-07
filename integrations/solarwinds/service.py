from __future__ import annotations

from typing import Any, Dict

from integrations.solarwinds.parser import parse_solarwinds_trap
from integrations.solarwinds.repository import save_solarwinds_trap


def handle_solarwinds_trap(trap: Dict[str, Any]) -> None:
    """
    Procesa un trap de SolarWinds:
    - parsea el trap
    - imprime resumen útil
    - deja listo el punto para persistencia futura
    """
    parsed = parse_solarwinds_trap(trap)

    print("[SOLARWINDS] Trap detectado")
    print(f"[SOLARWINDS] community={parsed.community}")
    print(f"[SOLARWINDS] src_ip={parsed.src_ip}:{parsed.src_port}")
    print(f"[SOLARWINDS] enterprise_oid={parsed.enterprise_oid}")
    print(f"[SOLARWINDS] trap_oid={parsed.trap_oid}")
    print(f"[SOLARWINDS] vendor_name={parsed.vendor_name}")
    print(f"[SOLARWINDS] varbinds_count={len(parsed.varbinds)}")

    save_solarwinds_trap(parsed)
    print("[SOLARWINDS] save_solarwinds_trap() ejecutado")