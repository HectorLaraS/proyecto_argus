"""
SNMP Trap Sender simple (SNMP v2c) - PySNMP moderno
--------------------------------------------------
Envía un trap estilo SolarWinds DPA (enterprise 22980) como en la imagen.

Uso:
  python trap_sender.py
"""

import asyncio
import socket

from pysnmp.hlapi.asyncio import (
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    NotificationType,
    ObjectIdentity,
    OctetString,
    Integer,
)

# Compatibilidad de nombre de función
try:
    from pysnmp.hlapi.asyncio import sendNotification as send_notification_func
except ImportError:
    from pysnmp.hlapi.asyncio import send_notification as send_notification_func


# ================== CONFIG ==================
DEST_IP = "192.168.0.6"
DEST_PORT = 162
COMMUNITY = "dpa_test"

# === SolarWinds/DPA trap OID (como en la imagen) ===
DPA_TRAP_OID = "1.3.6.1.4.1.22980.2.1"  # este debe aparecer en snmpTrapOID.0

# VarBinds (enterprise) vistos en tu captura
OID_DPA_1_1  = "1.3.6.1.4.1.22980.1.1"
OID_DPA_1_2  = "1.3.6.1.4.1.22980.1.2"
OID_DPA_1_3  = "1.3.6.1.4.1.22980.1.3"
OID_DPA_1_4  = "1.3.6.1.4.1.22980.1.4"
OID_DPA_1_5  = "1.3.6.1.4.1.22980.1.5"
OID_DPA_1_6  = "1.3.6.1.4.1.22980.1.6"
OID_DPA_1_7  = "1.3.6.1.4.1.22980.1.7"
OID_DPA_1_8  = "1.3.6.1.4.1.22980.1.8"
OID_DPA_1_9  = "1.3.6.1.4.1.22980.1.9"
OID_DPA_1_10 = "1.3.6.1.4.1.22980.1.10"
OID_DPA_1_11 = "1.3.6.1.4.1.22980.1.11"
OID_DPA_1_12 = "1.3.6.1.4.1.22980.1.12"
OID_DPA_1_13 = "1.3.6.1.4.1.22980.1.13"


def get_source_ip(dest_ip: str) -> str:
    """Obtiene la IP local usada para salir hacia dest_ip."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((dest_ip, 1))
        return s.getsockname()[0]
    finally:
        s.close()


async def send_trap(
    severity: str = "NORMAL",
    state_code: int = 0,
    when_text: str = "Thursday - March 05, 2026 18:10:33",
):
    """
    severity: 'NORMAL' o 'HIGH' (como en tu imagen)
    state_code: 0 o 6 (como en tu imagen)
    when_text: timestamp textual como lo manda DPA
    """
    _ = get_source_ip(DEST_IP)  # no lo manda DPA explícito en esa captura; lo dejo por si lo ocupas

    target = await UdpTransportTarget.create((DEST_IP, DEST_PORT))

    # OJO: NotificationType(ObjectIdentity(DPA_TRAP_OID)) setea snmpTrapOID.0 automáticamente
    res = await send_notification_func(
        SnmpEngine(),
        CommunityData(COMMUNITY, mpModel=1),  # SNMP v2c
        target,
        ContextData(),
        "trap",
        NotificationType(ObjectIdentity(DPA_TRAP_OID)).add_varbinds(
            # == Como en la captura ==
            (ObjectIdentity(OID_DPA_1_1),  OctetString(r"KCTACTOOLSD03\SQLEXPRESS")),
            (ObjectIdentity(OID_DPA_1_2),  OctetString("TAC TEST dpa_test Service Null")),
            (ObjectIdentity(OID_DPA_1_6),  OctetString("")),  # vacío en la imagen
            (ObjectIdentity(OID_DPA_1_7),  OctetString("Notification Text of information")),
            (ObjectIdentity(OID_DPA_1_3),  OctetString(severity)),  # NORMAL / HIGH
            (ObjectIdentity(OID_DPA_1_4),  OctetString("test")),
            (ObjectIdentity(OID_DPA_1_5),  OctetString(when_text)),
            (ObjectIdentity(OID_DPA_1_12), Integer(1)),
            (ObjectIdentity(OID_DPA_1_13), Integer(1)),
            (ObjectIdentity(OID_DPA_1_9),  OctetString("")),  # vacío en la imagen
            (ObjectIdentity(OID_DPA_1_8),  Integer(state_code)),  # 0 o 6
            (ObjectIdentity(OID_DPA_1_11), OctetString("")),  # vacío en la imagen
            (ObjectIdentity(OID_DPA_1_10), OctetString("")),  # vacío en la imagen
        ),
    )

    if isinstance(res, tuple) and len(res) == 4:
        error_indication, error_status, error_index, _ = res
    else:
        error_indication, error_status, error_index = res, 0, 0

    if error_indication:
        print(f"Error enviando trap: {error_indication}")
        return

    if error_status:
        print(f"Error SNMP (status={error_status}, index={error_index})")
        return

    print("Trap DPA enviado correctamente")
    print(f"  Destino  : {DEST_IP}:{DEST_PORT}")
    print(f"  Community: {COMMUNITY}")
    print(f"  snmpTrapOID.0 = {DPA_TRAP_OID}")
    print(f"  Severity = {severity}")
    print(f"  State    = {state_code}")
    print(f"  When     = {when_text}")


if __name__ == "__main__":
    # Replica los 2 traps de tu imagen:
    # 1) NORMAL con state 0
    # 2) HIGH con state 6
    async def main():
        
        await send_trap(severity="HIGH", state_code=6, when_text="Thursday - March 05, 2026 18:00:33")
        await asyncio.sleep(60)
        await send_trap(severity="HIGH", state_code=6, when_text="Thursday - March 05, 2026 18:00:33")
        await asyncio.sleep(60)
        await send_trap(severity="NORMAL", state_code=0, when_text="Thursday - March 05, 2026 18:10:33")
    asyncio.run(main())