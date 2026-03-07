from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict


@dataclass(frozen=True)
class SolarWindsTrapParsed:
    received_at: str
    src_ip: str
    src_port: int | None
    community: str

    enterprise_oid: str
    trap_oid: str
    vendor_name: str

    raw_payload_json: Dict[str, object]
    varbinds: Dict[str, str] = field(default_factory=dict)