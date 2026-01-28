"""
SNMP Trap Sender simple (SNMP v2c) - PySNMP moderno
--------------------------------------------------
- Compatible con:
  - UdpTransportTarget.create()
  - sendNotification / send_notification
  - add_varbinds (nuevo) en vez de addVarBinds

Uso:
  python trap_sender.py
"""

import asyncio

from pysnmp.hlapi.asyncio import (
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    NotificationType,
    ObjectIdentity,
    OctetString,
)

# Compatibilidad de nombre de función (camelCase vs snake_case)
try:
    from pysnmp.hlapi.asyncio import sendNotification as send_notification_func
except ImportError:
    from pysnmp.hlapi.asyncio import send_notification as send_notification_func


# ================== CONFIG ==================
DEST_IP = "192.168.1.69"   # IP del receptor
DEST_PORT = 162            # 162 o 1162
COMMUNITY = "public"

# OID estándar: linkDown
TRAP_OID = "1.3.6.1.6.3.1.1.5.3"

# VarBind de prueba
VAR_OID = "1.3.6.1.2.1.1.1.0"
VAR_VALUE = "Trap enviado desde Python (PySNMP asyncio)"


async def send_trap():
    target = await UdpTransportTarget.create((DEST_IP, DEST_PORT))

    # En PySNMP moderno, este llamado suele devolver:
    # (errorIndication, errorStatus, errorIndex, varBinds)
    res = await send_notification_func(
        SnmpEngine(),
        CommunityData(COMMUNITY, mpModel=1),  # SNMP v2c
        target,
        ContextData(),
        "trap",
        NotificationType(ObjectIdentity(TRAP_OID)).add_varbinds(
            (ObjectIdentity(VAR_OID), OctetString(VAR_VALUE))
        ),
    )

    # Manejo robusto de retorno (por si alguna variante devuelve otra cosa)
    if isinstance(res, tuple) and len(res) == 4:
        error_indication, error_status, error_index, var_binds = res
    else:
        error_indication, error_status, error_index, var_binds = res, 0, 0, []

    if error_indication is not None:
        print(f"Error enviando trap: {error_indication}")
        return

    if error_status:
        print(f"Error SNMP (status={error_status}, index={error_index})")
        return

    print("Trap enviado correctamente")


if __name__ == "__main__":
    asyncio.run(send_trap())
