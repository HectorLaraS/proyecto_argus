# pip install pysnmp

from datetime import datetime
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.carrier.asyncio.dgram import udp

LOG_FILE = "traps_received.log"

def cbFun(snmpEngine, stateReference, contextEngineId, contextName, varBinds, cbCtx):
    dt = datetime.now()

    print("\nTrap Received:")
    print(f"  Datetime: {dt}")

    with open(LOG_FILE, "a", encoding="utf-8") as log_trap:
        log_trap.write("\nTrap Received:")
        log_trap.write(f"\n  Datetime: {dt}")

        for name, val in varBinds:
            line = f"  {name.prettyPrint()} = {val.prettyPrint()}"
            print(line)
            log_trap.write("\n" + line)

        log_trap.write("\n")
        log_trap.flush()

def trap_receiver(listen_ip="0.0.0.0", listen_port=162):
    snmpEngine = engine.SnmpEngine()

    # Comunidades SNMPv1/v2c (securityName debe ser único por entrada)
    config.add_v1_system(snmpEngine, "mi-area", "public")
    config.add_v1_system(snmpEngine, "TAC-TEST", "TACTest")
    # config.add_v1_system(snmpEngine, "Asentria", "KCSMASENTRIA")
    config.add_v1_system(snmpEngine, "WIU1", "ALSTOM SNMP")
    config.add_v1_system(snmpEngine, "WIU2", "ALSTOM SNMP Trap")

    config.add_transport(
        snmpEngine,
        udp.DOMAIN_NAME,
        udp.UdpTransport().open_server_mode((listen_ip, listen_port))
    )

    ntfrcv.NotificationReceiver(snmpEngine, cbFun)

    print(f"Esperando SNMP traps en {listen_ip}:{listen_port} ...")
    try:
        snmpEngine.transport_dispatcher.run_dispatcher()
    except KeyboardInterrupt:
        print("\nServidor terminado por el usuario.")
    finally:
        snmpEngine.transport_dispatcher.close_dispatcher()

if __name__ == "__main__":
    trap_receiver(listen_ip="0.0.0.0", listen_port=162)
    # Si no corre por permisos/servicio ocupado:
    # trap_receiver(listen_ip="0.0.0.0", listen_port=1162)
