"""
SNMP Trap Sender simple (SNMP v2c) - SolarWinds trap prober
-----------------------------------------------------------
Envía traps de prueba con formato similar al que recibe ARGUS
para la integración de SolarWinds.

Uso:
  python trap_sender_solarwinds.py
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

try:
    from pysnmp.hlapi.asyncio import sendNotification as send_notification_func
except ImportError:
    from pysnmp.hlapi.asyncio import send_notification as send_notification_func


# ================== CONFIG ==================
DEST_IP = "192.168.1.66"
DEST_PORT = 162

# Debe coincidir con una community que tu dispatcher enrute a SolarWinds
COMMUNITY = "TACTest"

# Enterprise / trap OID estilo Omnitronix / GE family
SOLARWINDS_TRAP_OID = "1.3.6.1.4.1.11307.10"

# VarBinds vistos en tus capturas
OID_SW_10_1 = "1.3.6.1.4.1.11307.10.1"  # status
OID_SW_10_2 = "1.3.6.1.4.1.11307.10.2"  # device/site/node
OID_SW_10_3 = "1.3.6.1.4.1.11307.10.3"  # ip
OID_SW_10_4 = "1.3.6.1.4.1.11307.10.4"  # port
OID_SW_10_5 = "1.3.6.1.4.1.11307.10.5"  # vendor

VENDOR_NAME = "GE Transportation Systems Global Signaling, LLC"


def get_source_ip(dest_ip: str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((dest_ip, 1))
        return s.getsockname()[0]
    finally:
        s.close()


async def send_trap(
    status_text: str = "Up",
    node_name: str = "wu-cprs-00153-206-72-1",
    device_ip: str = "10.199.33.84",
    device_port: str = "38210",
):
    _ = get_source_ip(DEST_IP)

    target = await UdpTransportTarget.create((DEST_IP, DEST_PORT))

    res = await send_notification_func(
        SnmpEngine(),
        CommunityData(COMMUNITY, mpModel=1),
        target,
        ContextData(),
        "trap",
        NotificationType(ObjectIdentity(SOLARWINDS_TRAP_OID)).add_varbinds(
            (ObjectIdentity(OID_SW_10_1), OctetString(status_text)),
            (ObjectIdentity(OID_SW_10_2), OctetString(node_name)),
            (ObjectIdentity(OID_SW_10_3), OctetString(device_ip)),
            (ObjectIdentity(OID_SW_10_4), OctetString(device_port)),
            (ObjectIdentity(OID_SW_10_5), OctetString(VENDOR_NAME)),
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

    print("Trap SolarWinds enviado correctamente")
    print(f"  Destino   : {DEST_IP}:{DEST_PORT}")
    print(f"  Community : {COMMUNITY}")
    print(f"  snmpTrapOID.0 = {SOLARWINDS_TRAP_OID}")
    print(f"  Status    : {status_text}")
    print(f"  Node      : {node_name}")
    print(f"  Device IP : {device_ip}")
    print(f"  Port      : {device_port}")
    print(f"  Vendor    : {VENDOR_NAME}")


if __name__ == "__main__":
    async def main():
        await send_trap(
            status_text="Up",
            node_name="wu-cprs-00153-206-72-1",
            device_ip="10.199.33.84",
            device_port="38210",
        )
        await asyncio.sleep(5)
        await send_trap(
            status_text="Up",
            node_name="Asentria_monterrey",
            device_ip="10.190.196.37",
            device_port="161",
        )

    asyncio.run(main())