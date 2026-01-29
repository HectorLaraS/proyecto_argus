"""
SNMP Trap Sender simple (SNMP v2c) - PySNMP moderno
--------------------------------------------------
Incluye IP de origen y destino como VarBinds.

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
)

# Compatibilidad de nombre de función
try:
    from pysnmp.hlapi.asyncio import sendNotification as send_notification_func
except ImportError:
    from pysnmp.hlapi.asyncio import send_notification as send_notification_func


# ================== CONFIG ==================
DEST_IP = "192.168.0.19"
DEST_PORT = 1162
COMMUNITY = "public"

# Trap estándar
TRAP_OID = "1.3.6.1.6.3.1.1.5.3"  # linkDown

# OIDs informativos (enterprise / custom)
OID_MESSAGE     = "1.3.6.1.4.1.99999.1.1"
OID_SRC_IP      = "1.3.6.1.4.1.99999.1.2"
OID_DEST_IP     = "1.3.6.1.4.1.99999.1.3"


def get_source_ip(dest_ip: str) -> str:
    """Obtiene la IP local usada para salir hacia dest_ip."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((dest_ip, 1))
        return s.getsockname()[0]
    finally:
        s.close()


async def send_trap():
    src_ip = get_source_ip(DEST_IP)
    dest_ip = DEST_IP

    target = await UdpTransportTarget.create((DEST_IP, DEST_PORT))

    res = await send_notification_func(
        SnmpEngine(),
        CommunityData(COMMUNITY, mpModel=1),
        target,
        ContextData(),
        "trap",
        NotificationType(ObjectIdentity(TRAP_OID)).add_varbinds(
            (ObjectIdentity(OID_MESSAGE), OctetString("Trap de prueba ARGUS")),
            (ObjectIdentity(OID_SRC_IP),  OctetString(src_ip)),
            (ObjectIdentity(OID_DEST_IP), OctetString(dest_ip)),
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

    print("Trap enviado correctamente")
    print(f"  IP origen : {src_ip}")
    print(f"  IP destino: {dest_ip}")


if __name__ == "__main__":
    asyncio.run(send_trap())
