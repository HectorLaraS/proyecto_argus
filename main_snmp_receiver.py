"""
SNMP Trap Receiver + Web UI (Windows / Python 3.12+ compatible)
==============================================================

- Recibe traps SNMP v1/v2c usando pysnmp (asyncio transport)
- Corre el receiver en un PROCESO separado (evita problemas de threads)
- Crea y asigna explícitamente un event loop en el proceso SNMP
- Guarda traps en memoria (buffer compartido con tamaño máximo)
- Expone una Web UI con Flask para ver y exportar traps (JSON y TXT)

Requisitos:
  pip install pysnmp flask

Ejecución:
  python snmp_trap_web_server.py

Web:
  http://localhost:5000
"""

from __future__ import annotations

import asyncio
import multiprocessing as mp
from datetime import datetime
from typing import Any, Dict, List, Optional
import os

from flask import Flask, jsonify, render_template_string

from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.carrier.asyncio.dgram import udp

# ================== CONFIG ==================
SNMP_LISTEN_IP = "0.0.0.0"
SNMP_PORT = 1162          # 162 solo con permisos admin
MAX_TRAPS = 200

WEB_HOST = "0.0.0.0"
WEB_PORT = 5000

# Buffer compartido (se inicializa en main)
traps_buffer: Optional[Any] = None


# ================== BUFFER UTILS ==================
def _buffer_insert_front(buffer: Any, item: Dict[str, Any], max_items: int) -> None:
    """Insertar al frente y recortar a max_items (sirve para list() y Manager().list())."""
    buffer.insert(0, item)
    del buffer[max_items:]


def format_traps_as_txt(traps: List[Dict[str, Any]]) -> str:
    """Convierte una lista de traps a texto plano descargable."""
    lines: List[str] = []
    for t in traps:
        ts = t.get("timestamp", "")
        lines.append(f"[{ts}]")
        for vb in t.get("oids", []):
            lines.append(f"  {vb.get('oid', '')} = {vb.get('value', '')}")
        lines.append("")
    return "\n".join(lines)


# ================== SNMP CALLBACK ==================
def trap_callback(snmpEngine, stateReference, contextEngineId, contextName, varBinds, cbCtx):
    buffer = cbCtx["buffer"]
    max_items = cbCtx["max"]

    trap = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "oids": [],
    }

    for name, val in varBinds:
        trap["oids"].append(
            {"oid": name.prettyPrint(), "value": val.prettyPrint()}
        )

    _buffer_insert_front(buffer, trap, max_items)

    # Log mínimo a consola
    try:
        print(f"Trap recibido (buffer={len(buffer)})")
    except Exception:
        print("Trap recibido")
    dt = datetime.now()
    ##execContext = snmpEngine.observer.getExecutionContext('rfc3412.receiveMessage')
    ##comunidad = execContext['securityName'].prettyPrint()
    with open("traps_received.log","a") as log_trap:
        print('\nTrap Received:')
        print(f'\n  Datetime: {dt}')
        ##print(f'\n  SNMP ENGINE: {comunidad}')
        log_trap.write("\nTrap Received:")
        print("CWD:",os.getcwd())
        print("LOG abs: ",os.path.abspath("traps_received.log"))
        log_trap.write(f"\n  Datetime: {dt}")
        ##log_trap.write(f"\n  SNMP ENGINE: {comunidad}")
        for name, val in varBinds:
            print(f'  {name.prettyPrint()} = {val.prettyPrint()}')
            log_trap.write(f'\n  {name.prettyPrint()} = {val.prettyPrint()}')


# ================== SNMP SERVER (PROCESS) ==================
def start_snmp_server(shared_buffer, listen_ip: str, listen_port: int, max_items: int) -> None:
    """
    Proceso del receiver.

    En Python 3.12+/3.13 (Windows), este proceso puede no tener event loop asignado.
    PySNMP asyncio transport llama asyncio.get_event_loop(); si no existe, falla.
    Por eso creamos y asignamos explícitamente el loop.
    """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    snmpEngine = engine.SnmpEngine()

    # Comunidades SNMP v1/v2c
    config.add_v1_system(snmpEngine, "public-area", "public")
    config.add_v1_system(snmpEngine, "test-area", "TACTest")

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
    :root { --bg:#0f172a; --panel:#111c33; --border:#334155; --text:#e5e7eb; --muted:#94a3b8; --accent:#38bdf8; }
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
    div.innerHTML =
      `<div class="time">${t.timestamp}</div>` +
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
  <div style="margin-top:10px">
    <a class="btn" href="/system/clear">Limpiar buffer</a>
  </div>
</div>
"""


# ================== FLASK APP ==================
def create_app() -> Flask:
    app = Flask(__name__)

    def render_page(title: str, headline: str, active: str, body: str, **ctx):
        """
        Renderiza body como mini-template (Jinja), luego lo inyecta en HTML_BASE.
        Esto permite que SYSTEM_BODY use {{ snmp_ip }} etc.
        """
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


# ================== TESTS ==================
import unittest


class TestBufferInsert(unittest.TestCase):
    def test_buffer_respects_max(self):
        buf: List[Dict[str, Any]] = []
        for i in range(10):
            _buffer_insert_front(buf, {"n": i}, max_items=3)
        self.assertEqual(len(buf), 3)
        self.assertEqual(buf[0]["n"], 9)
        self.assertEqual(buf[-1]["n"], 7)


class TestTemplateRendering(unittest.TestCase):
    def test_system_body_renders_vars(self):
        test_app = Flask(__name__)
        with test_app.app_context():
            rendered = render_template_string(
                SYSTEM_BODY,
                snmp_ip="0.0.0.0",
                snmp_port=1162,
                web_host="0.0.0.0",
                web_port=5000,
            )
        self.assertIn("SNMP: 0.0.0.0:1162", rendered)
        self.assertIn("Web: 0.0.0.0:5000", rendered)


class TestExportTxtFormat(unittest.TestCase):
    def test_export_txt_formatting(self):
        traps = [
            {
                "timestamp": "2026-01-28 12:00:00",
                "oids": [
                    {"oid": "1.3.6.1.2.1.1.3.0", "value": "123"},
                    {"oid": "1.3.6.1.2.1.1.5.0", "value": "router-1"},
                ],
            }
        ]
        txt = format_traps_as_txt(traps)
        self.assertIn("[2026-01-28 12:00:00]", txt)
        self.assertIn("  1.3.6.1.2.1.1.3.0 = 123", txt)
        self.assertIn("  1.3.6.1.2.1.1.5.0 = router-1", txt)


# ================== MAIN ==================
def main() -> None:
    global traps_buffer

    # En Windows, spawn es lo más estable
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
