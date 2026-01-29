"""
ARGUS - SNMP Trap Receiver + Web UI (PySNMP 7.1.22)
==================================================

✅ FIX real para tu build (según tu debug):
- El observer SÍ trae transportAddress y securityName
- PERO NO trae stateReference (no podemos correlacionar por cache)
=> Solución práctica: guardar "último peer visto" (_LAST_PEER) en el observer
   y el callback lo consume al instante.

Esto te dará:
- SRC (ip:puerto) correcto
- COMMUNITY correcto (alias==community configurado con add_v1_system)

Incluye:
- Web UI con menú: Live / Exportar / Sistema
- Exportar TXT + JSON
- Buffer en memoria (Manager.list) compartido con proceso SNMP
- Log a archivo traps_received.log

Requisitos:
  pip install pysnmp flask

Ejecutar:
  python main_snmp_receiver.py
"""

from __future__ import annotations

import asyncio
import multiprocessing as mp
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from flask import Flask, jsonify, render_template_string

from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.carrier.asyncio.dgram import udp

# ================== CONFIG ==================
SNMP_LISTEN_IP = "0.0.0.0"
SNMP_PORT = 1162
MAX_TRAPS = 200

WEB_HOST = "0.0.0.0"
WEB_PORT = 5000

LOG_FILE = "traps_received.log"

# Imprime UNA vez lo que llega al observer (después se apaga)
DEBUG_OBSERVER_ONCE = True

traps_buffer: Optional[Any] = None

# Último peer visto (capturado por observer)
# (src_ip, src_port, community)
_LAST_PEER: Tuple[str, Optional[int], str] = ("", None, "")


# ================== BUFFER UTILS ==================
def _buffer_insert_front(buffer: Any, item: Dict[str, Any], max_items: int) -> None:
    buffer.insert(0, item)
    del buffer[max_items:]


def format_traps_as_txt(traps: List[Dict[str, Any]]) -> str:
    lines: List[str] = []
    for t in traps:
        ts = t.get("timestamp", "")
        src_ip = t.get("src_ip", "") or "-"
        src_port = t.get("src_port", None)
        src_port_s = "-" if src_port is None else str(src_port)
        community = t.get("community", "") or "-"

        lines.append(f"[{ts}]")
        lines.append(f"SRC: {src_ip}:{src_port_s}")
        lines.append(f"COMMUNITY: {community}")

        for vb in t.get("oids", []):
            lines.append(f"  {vb.get('oid', '')} = {vb.get('value', '')}")
        lines.append("")
    return "\n".join(lines)


# ================== OBSERVER COMPAT ==================
def _register_observer_compat(snmpEngine, cb, point: str) -> None:
    """
    PySNMP 7.x usa snake_case: register_observer
    Algunas variantes antiguas usan registerObserver
    """
    obs = snmpEngine.observer
    if hasattr(obs, "register_observer"):
        obs.register_observer(cb, point)
        return
    if hasattr(obs, "registerObserver"):
        obs.registerObserver(cb, point)
        return
    raise AttributeError("Observer no soporta register_observer/registerObserver")


def _peer_observer(snmpEngine, execPoint, variables, cbCtx):
    """
    Captura SRC/COMMUNITY del mensaje entrante.
    En tu build (según debug), las keys son:
      transportAddress -> (ip, port)
      securityName -> 'public'
    y NO hay stateReference, por eso usamos _LAST_PEER.
    """
    global DEBUG_OBSERVER_ONCE, _LAST_PEER

    try:
        if DEBUG_OBSERVER_ONCE:
            DEBUG_OBSERVER_ONCE = False
            print("[OBSERVER DEBUG] execPoint:", execPoint)
            print("[OBSERVER DEBUG] keys:", sorted(list(variables.keys())))
            print("[OBSERVER DEBUG] transport:", variables.get("transportAddress"))
            print("[OBSERVER DEBUG] security:", variables.get("securityName"))

        ta = variables.get("transportAddress")
        sec = variables.get("securityName")

        src_ip, src_port = "", None
        if isinstance(ta, tuple) and len(ta) >= 2:
            src_ip, src_port = ta[0], ta[1]

        community = ""
        if sec is not None:
            community = sec.prettyPrint() if hasattr(sec, "prettyPrint") else str(sec)

        _LAST_PEER = (src_ip, src_port, community)

    except Exception:
        # No romper recepción por fallos del observer
        pass


# ================== SNMP CALLBACK ==================
def trap_callback(snmpEngine, stateReference, contextEngineId, contextName, varBinds, cbCtx):
    buffer = cbCtx["buffer"]
    max_items = cbCtx["max"]

    # ✅ Tomar el último peer visto por el observer
    global _LAST_PEER
    src_ip, src_port, community = _LAST_PEER

    trap = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": src_ip,
        "src_port": src_port,
        "community": community,
        "oids": [],
    }

    for name, val in varBinds:
        trap["oids"].append({"oid": name.prettyPrint(), "value": val.prettyPrint()})

    _buffer_insert_front(buffer, trap, max_items)

    print(f"Trap recibido (buffer={len(buffer)}) SRC={src_ip}:{src_port} COMMUNITY={community}")

    # Log a archivo
    dt = datetime.now()
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as log_trap:
            log_trap.write("\nTrap Received:")
            log_trap.write(f"\n  Datetime: {dt}")
            log_trap.write(f"\n  SRC: {src_ip}:{src_port}")
            log_trap.write(f"\n  COMMUNITY: {community}")
            for name, val in varBinds:
                log_trap.write(f"\n  {name.prettyPrint()} = {val.prettyPrint()}")
            log_trap.write("\n")
            log_trap.flush()
    except Exception as e:
        print(f"[LOG ERROR] {e} (cwd={os.getcwd()}, abs={os.path.abspath(LOG_FILE)})")


# ================== SNMP SERVER (PROCESS) ==================
def start_snmp_server(shared_buffer, listen_ip: str, listen_port: int, max_items: int) -> None:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    snmpEngine = engine.SnmpEngine()

    # Registrar observer (solo una vez)
    _register_observer_compat(snmpEngine, _peer_observer, "rfc3412.receiveMessage:request")

    # Comunidades aceptadas (v1/v2c)
    # alias == community => securityName sale como community literal
    config.add_v1_system(snmpEngine, "public-2", "public")
    config.add_v1_system(snmpEngine, "TACTest", "TACTest")

    config.add_transport(
        snmpEngine,
        udp.DOMAIN_NAME,
        udp.UdpTransport().open_server_mode((listen_ip, listen_port)),
    )

    ntfrcv.NotificationReceiver(
        snmpEngine,
        trap_callback,
        cbCtx={"buffer": shared_buffer, "max": max_items},
    )

    print(f"SNMP Trap Receiver escuchando en {listen_ip}:{listen_port}")
    print(f"LOG: {os.path.abspath(LOG_FILE)}")

    try:
        snmpEngine.transport_dispatcher.run_dispatcher()
    finally:
        try:
            snmpEngine.transport_dispatcher.close_dispatcher()
        except Exception:
            pass


# ================== WEB UI TEMPLATES ==================
HTML_BASE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>{{ title }}</title>
  <style>
    :root { --bg:#0f172a; --panel:#111c33; --border:#334155; --text:#e5e7eb; --muted:#94a3b8; }
    body { margin:0; font-family: Arial, sans-serif; background:var(--bg); color:var(--text) }
    .nav { position:sticky; top:0; background:rgba(15,23,42,.92); border-bottom:1px solid var(--border); padding:12px; display:flex; gap:14px; align-items:center }
    .nav a { color:var(--text); text-decoration:none; padding:6px 10px; border-radius:8px; border:1px solid transparent }
    .nav a:hover { border-color:var(--border); background:rgba(51,65,85,.25) }
    .nav a.active { border-color:rgba(56,189,248,.6); background:rgba(56,189,248,.12) }
    .spacer { flex: 1; }
    .pill { color:var(--muted); border:1px solid var(--border); padding:6px 10px; border-radius:999px; font-size:.85rem }
    .wrap { max-width: 1100px; margin: 0 auto; padding: 16px }
    .trap { border:1px solid var(--border); margin:8px 0; padding:10px; border-radius:10px; background:rgba(15,23,42,.35) }
    .time { color:var(--muted); font-size:.9em; margin-bottom:6px }
    .oid { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace }
    .meta { color:var(--muted); margin-bottom: 6px; }
    .card { border:1px solid var(--border); background:rgba(17,28,51,.7); padding:12px; border-radius:12px; margin-bottom:12px }
    .btn { display:inline-block; padding:10px 12px; border-radius:10px; border:1px solid var(--border); text-decoration:none; color:var(--text); background:rgba(51,65,85,.25) }
    .btn:hover { border-color:rgba(56,189,248,.6); background:rgba(56,189,248,.10) }
  </style>
</head>
<body>
  <div class="nav">
    <a href="/" class="{{ 'active' if active=='live' else '' }}">Live</a>
    <a href="/export" class="{{ 'active' if active=='export' else '' }}">Exportar</a>
    <a href="/system" class="{{ 'active' if active=='system' else '' }}">Sistema</a>
    <div class="spacer"></div>
    <div class="pill">Buffer: {{ buffer_len }}/{{ buffer_max }}</div>
  </div>
  <div class="wrap">
    <h2>{{ headline }}</h2>
    {{ body|safe }}
  </div>
</body>
</html>
"""

LIVE_BODY = """
<div class="card">
  <div style="color:#94a3b8">Auto-refresh cada 2s. API: <span class="oid">/api/traps</span></div>
</div>
<div id="traps"></div>
<script>
async function loadTraps() {
  const r = await fetch('/api/traps');
  const d = await r.json();
  const c = document.getElementById('traps');
  c.innerHTML = '';
  d.forEach(t => {
    const div = document.createElement('div');
    div.className = 'trap';

    const srcIp = t.src_ip || '-';
    const srcPort = (t.src_port === null || t.src_port === undefined) ? '-' : t.src_port;
    const comm = t.community || '-';

    div.innerHTML =
      `<div class="time">${t.timestamp}</div>` +
      `<div class="meta oid">SRC: ${srcIp}:${srcPort}</div>` +
      `<div class="meta oid">COMMUNITY: ${comm}</div>` +
      t.oids.map(o => `<div class="oid">${o.oid} = ${o.value}</div>`).join('');
    c.appendChild(div);
  });
}
setInterval(loadTraps, 2000);
loadTraps();
</script>
"""

EXPORT_BODY = """
<div class="card">
  <div style="color:#94a3b8; margin-bottom:10px">Descargas del buffer actual.</div>
  <a class="btn" href="/export/json">Descargar JSON</a>
  <a class="btn" href="/export/txt" style="margin-left:10px">Descargar TXT</a>
</div>
"""

SYSTEM_BODY = """
<div class="card">
  <div class="oid">SNMP: {{ snmp_ip }}:{{ snmp_port }}</div>
  <div class="oid">Web: {{ web_host }}:{{ web_port }}</div>
  <div class="oid">Log: {{ log_path }}</div>
  <div style="margin-top:10px">
    <a class="btn" href="/system/clear">Limpiar buffer</a>
  </div>
</div>
"""


# ================== FLASK APP ==================
def create_app() -> Flask:
    app = Flask(__name__)

    def render_page(title: str, headline: str, active: str, body: str, **ctx):
        global traps_buffer
        buffer_len = len(traps_buffer) if traps_buffer is not None else 0
        body_rendered = render_template_string(body, **ctx)
        return render_template_string(
            HTML_BASE,
            title=title,
            headline=headline,
            active=active,
            body=body_rendered,
            buffer_len=buffer_len,
            buffer_max=MAX_TRAPS,
        )

    @app.route("/")
    def index():
        return render_page("Live", "Traps (Live)", "live", LIVE_BODY)

    @app.route("/export")
    def export_page():
        return render_page("Exportar", "Exportar", "export", EXPORT_BODY)

    @app.route("/system")
    def system_page():
        return render_page(
            "Sistema",
            "Sistema",
            "system",
            SYSTEM_BODY,
            snmp_ip=SNMP_LISTEN_IP,
            snmp_port=SNMP_PORT,
            web_host=WEB_HOST,
            web_port=WEB_PORT,
            log_path=os.path.abspath(LOG_FILE),
        )

    @app.route("/system/clear")
    def system_clear():
        global traps_buffer
        if traps_buffer is not None:
            try:
                traps_buffer[:] = []
            except Exception:
                while len(traps_buffer) > 0:
                    traps_buffer.pop(0)

        return render_page(
            "Sistema",
            "Sistema",
            "system",
            "<div class='card'>Buffer limpiado. "
            "<a class='btn' href='/system' style='margin-left:10px'>Volver</a></div>",
        )

    @app.route("/api/traps")
    def api_traps():
        return jsonify(list(traps_buffer) if traps_buffer is not None else [])

    @app.route("/export/json")
    def export_json():
        return jsonify(list(traps_buffer) if traps_buffer is not None else [])

    @app.route("/export/txt")
    def export_txt():
        traps = list(traps_buffer) if traps_buffer is not None else []
        txt = format_traps_as_txt(traps).encode("utf-8")
        return app.response_class(
            response=txt,
            status=200,
            mimetype="text/plain; charset=utf-8",
            headers={"Content-Disposition": "attachment; filename=traps.txt"},
        )

    return app


# ================== MAIN ==================
def main() -> None:
    global traps_buffer
    try:
        mp.set_start_method("spawn")
    except RuntimeError:
        pass

    manager = mp.Manager()
    traps_buffer = manager.list()

    snmp_proc = mp.Process(
        target=start_snmp_server,
        args=(traps_buffer, SNMP_LISTEN_IP, SNMP_PORT, MAX_TRAPS),
        daemon=True,
    )
    snmp_proc.start()

    app = create_app()
    print(f"Web UI disponible en http://{WEB_HOST}:{WEB_PORT}")
    app.run(host=WEB_HOST, port=WEB_PORT, threaded=False)


if __name__ == "__main__":
    mp.freeze_support()
    main()
