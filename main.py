##pip install pysnmp

import asyncio
from datetime import datetime

# Forzar la creación de un event loop antes de la inicialización de PySNMP
asyncio.set_event_loop(asyncio.new_event_loop())

from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.carrier.asyncio.dgram import udp

def cbFun(snmpEngine, stateReference, contextEngineId, contextName, varBinds, cbCtx):
    dt = datetime.now()
    ##execContext = snmpEngine.observer.getExecutionContext('rfc3412.receiveMessage')
    ##comunidad = execContext['securityName'].prettyPrint()
    with open("traps_received.log","a") as log_trap:
        print('\nTrap Received:')
        print(f'\n  Datetime: {dt}')
        ##print(f'\n  SNMP ENGINE: {comunidad}')
        log_trap.write("\nTrap Received:")
        log_trap.write(f"\n  Datetime: {dt}")
        ##log_trap.write(f"\n  SNMP ENGINE: {comunidad}")
        for name, val in varBinds:
            print(f'  {name.prettyPrint()} = {val.prettyPrint()}')
            log_trap.write(f'\n  {name.prettyPrint()} = {val.prettyPrint()}')

def trap_receiver():
    snmpEngine = engine.SnmpEngine()
    config.add_v1_system(snmpEngine, 'mi-area', 'public')
    config.add_v1_system(snmpEngine,'TAC-TEST','TACTest')
    ##config.add_v1_system(snmpEngine, 'Asentria', 'KCSMASENTRIA')
    config.add_v1_system(snmpEngine, 'WIU', 'ALSTOM SNMP')
    config.add_v1_system(snmpEngine, 'WIU', 'ALSTOM SNMP Trap')
    config.add_transport(
        snmpEngine,
        udp.DOMAIN_NAME,
        udp.UdpTransport().open_server_mode(('10.190.49.118', 162))  # Escuchar en todas las interfaces, puerto 1162
        # Cambia '1162' por '162' solo si tienes permisos de administrador
    )
    ntfrcv.NotificationReceiver(snmpEngine, cbFun)

    print('Esperando SNMP traps en el puerto 162...')
    try:
        snmpEngine.transport_dispatcher.run_dispatcher()
    except KeyboardInterrupt:
        print("\nServidor terminado por el usuario.")
        snmpEngine.transport_dispatcher.close_dispatcher()

if __name__ == "_main_":
    trap_receiver()