"""
ARGUS - SNMP Trap Receiver + Web UI + Observabilidad (PySNMP 7.1.22)
===================================================================

Observabilidad implementada (orden):
1) Top N por OID ✅
2) Rate por IP (últimos N min) ✅ (Quantity)
3) Detección de bursts ✅ (este commit)
4) Persistencia SQLite (pendiente)
5) Series/graficación mejorada (pendiente)

Requisitos:
  pip install pysnmp flask
"""

from __future__ import annotations

import asyncio
import multiprocessing as mp
import os
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from collections import Counter

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

DEBUG_OBSERVER_ONCE = False  # True si quieres ver keys del observer

# Observabilidad
RATE_WINDOW_MINUTES = 15

# Burst detection (punto 3)
BURST_WINDOW_SECONDS = 60     # ventana (ej. 60s)
BURST_THRESHOLD = 20          # si >= 20 traps en 60s => alerta
BURST_TOP = 10                # mostrar top 10 IPs con más burst

traps_buffer: Optional[Any] = None
WEB_START_EPOCH = time.time()

# (src_ip, src_port, community) visto por observer
_LAST_PEER: Tuple[str, Optional[int], str] = ("", None, "")


# ================== UTILS ==================
def _buffer_insert_front(buffer: Any, item: Dict[str, Any], max_items: int) -> None:
    buffer.insert(0, item)
    del buffer[max_items:]


def _parse_ts(ts: str) -> Optional[datetime]:
    try:
        return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


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


def compute_stats_from_traps(traps: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(traps)
    last = traps[0] if traps else None

    ip_counter = Counter()
    comm_counter = Counter()
    oid_counter = Counter()

    now = datetime.now()
    window_start = now - timedelta(minutes=RATE_WINDOW_MINUTES)
    per_min = Counter()

    # (2) Rate por IP en ventana (15m)
    window_ip_counter = Counter()
    ip_last_seen: Dict[str, str] = {}  # ip -> timestamp más reciente en buffer

    # (3) Burst detection en ventana corta (60s)
    burst_start = now - timedelta(seconds=BURST_WINDOW_SECONDS)
    burst_ip_counter = Counter()
    burst_ip_last_seen: Dict[str, str] = {}  # ip -> último timestamp dentro de burst window

    for t in traps:
        src_ip = t.get("src_ip") or "-"
        community = t.get("community") or "-"

        ip_counter[src_ip] += 1
        comm_counter[community] += 1

        # (1) Top OIDs (varbinds)
        for vb in t.get("oids", []):
            oid = vb.get("oid") or "-"
            oid_counter[oid] += 1

        # last_seen por IP (el buffer es más reciente primero)
        if src_ip not in ip_last_seen:
            ip_last_seen[src_ip] = t.get("timestamp", "")

        ts = _parse_ts(t.get("timestamp", ""))
        if not ts:
            continue

        # Rate global + rate por IP en ventana (15m)
        if ts >= window_start:
            per_min[ts.strftime("%H:%M")] += 1
            window_ip_counter[src_ip] += 1

        # (3) Burst counters (60s)
        if ts >= burst_start:
            burst_ip_counter[src_ip] += 1
            if src_ip not in burst_ip_last_seen:
                burst_ip_last_seen[src_ip] = t.get("timestamp", "")

    # serie por minuto global (rellenar huecos)
    minute_labels: List[str] = []
    cur = window_start.replace(second=0, microsecond=0)
    end = now.replace(second=0, microsecond=0)
    while cur <= end:
        minute_labels.append(cur.strftime("%H:%M"))
        cur += timedelta(minutes=1)
    rate_series = [{"minute": m, "count": int(per_min.get(m, 0))} for m in minute_labels]

    top_ips = [{"src_ip": k, "count": int(v)} for k, v in ip_counter.most_common(10)]
    top_comms = [{"community": k, "count": int(v)} for k, v in comm_counter.most_common(10)]
    top_oids = [{"oid": k, "count": int(v)} for k, v in oid_counter.most_common(15)]

    # (2) Top IPs por rate en ventana (Quantity)
    top_ip_rates = []
    for ip, qty in window_ip_counter.most_common(10):
        top_ip_rates.append(
            {
                "src_ip": ip,
                "quantity": int(qty),
                "avg_per_min": round(qty / max(RATE_WINDOW_MINUTES, 1), 3),
                "last_seen": ip_last_seen.get(ip, ""),
            }
        )

    # (3) Burst alerts: IPs que exceden umbral en ventana corta
    bursts = []
    for ip, qty in burst_ip_counter.most_common(BURST_TOP):
        bursts.append(
            {
                "src_ip": ip,
                "quantity": int(qty),
                "threshold": int(BURST_THRESHOLD),
                "window_seconds": int(BURST_WINDOW_SECONDS),
                "is_alert": bool(qty >= BURST_THRESHOLD),
                "last_seen": burst_ip_last_seen.get(ip, ""),
            }
        )

    # Solo las que están en alerta (para UI y/o automatizar más adelante)
    burst_alerts = [b for b in bursts if b["is_alert"]]

    return {
        "total": total,
        "last_trap": last,

        "top_ips": top_ips,
        "top_communities": top_comms,
        "top_oids": top_oids,

        "rate_window_minutes": RATE_WINDOW_MINUTES,
        "rate_per_minute": rate_series,
        "top_ip_rates": top_ip_rates,  # (2) Quantity

        # (3) Bursts
        "burst": {
            "window_seconds": int(BURST_WINDOW_SECONDS),
            "threshold": int(BURST_THRESHOLD),
            "top": int(BURST_TOP),
        },
        "bursts": bursts,               # top IPs en burst window (incluye is_alert)
        "burst_alerts": burst_alerts,   # solo alertas
    }


# ================== OBSERVER ==================
def _register_observer_compat(snmpEngine, cb, point: str) -> None:
    obs = snmpEngine.observer
    if hasattr(obs, "register_observer"):
        obs.register_observer(cb, point)
        return
    if hasattr(obs, "registerObserver"):
        obs.registerObserver(cb, point)
        return
    raise AttributeError("Observer no soporta register_observer/registerObserver")


def _peer_observer(snmpEngine, execPoint, variables, cbCtx):
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
        pass


# ================== SNMP CALLBACK ==================
def trap_callback(snmpEngine, stateReference, contextEngineId, contextName, varBinds, cbCtx):
    buffer = cbCtx["buffer"]
    max_items = cbCtx["max"]

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
    _register_observer_compat(snmpEngine, _peer_observer, "rfc3412.receiveMessage:request")

    config.add_v1_system(snmpEngine, "public", "public")
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


# ================== WEB UI ==================
HTML_BASE = """
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>{{ title }}</title>
  <style>
    :root { --bg:#0f172a; --panel:#111c33; --border:#334155; --text:#e5e7eb; --muted:#94a3b8; --danger:#fb7185; --warn:#fbbf24; }
    body { margin:0; font-family: Arial, sans-serif; background:var(--bg); color:var(--text) }
    .nav { position:sticky; top:0; background:rgba(15,23,42,.92); border-bottom:1px solid var(--border); padding:12px; display:flex; gap:14px; align-items:center; flex-wrap: wrap; }
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
    table { width:100%; border-collapse:collapse; }
    th, td { text-align:left; padding:8px; border-bottom:1px solid rgba(51,65,85,.5); }
    th { color: var(--muted); font-weight: 600; }
    .grid { display:grid; grid-template-columns: 1fr 1fr; gap: 12px; }
    @media (max-width: 900px) { .grid { grid-template-columns: 1fr; } }
    .badge { display:inline-block; padding:2px 8px; border-radius:999px; font-size:.85rem; border:1px solid rgba(148,163,184,.35); color:var(--muted); }
    .badge.alert { border-color: rgba(251,113,133,.6); color: var(--danger); }
  </style>
</head>
<body>
  <div class="nav">
    <a href="/" class="{{ 'active' if active=='live' else '' }}">Live</a>
    <a href="/observability" class="{{ 'active' if active=='obs' else '' }}">Observabilidad</a>
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

OBS_BODY = """
<div class="card">
  <div style="color:#94a3b8">Auto-refresh cada 5s. APIs: <span class="oid">/api/stats</span>, <span class="oid">/api/health</span></div>
</div>

<div class="grid">
  <div class="card">
    <div class="oid" style="margin-bottom:8px"><b>Resumen</b></div>
    <div id="summary" class="oid"></div>
  </div>

  <div class="card">
    <div class="oid" style="margin-bottom:8px"><b>Rate global (traps/min) últimos {{ window_min }} min</b></div>
    <div id="rate" class="oid"></div>
  </div>
</div>

<div class="card">
  <div class="oid" style="margin-bottom:8px"><b>Burst Alerts</b> <span id="burstBadge" class="badge">-</span></div>
  <div style="color:#94a3b8; margin-bottom:8px">
    Regla: >= <span class="oid">{{ burst_threshold }}</span> traps en <span class="oid">{{ burst_window }}</span>s por IP.
  </div>
  <table>
    <thead><tr><th>Status</th><th>IP</th><th>Quantity</th><th>Threshold</th><th>Window(s)</th><th>Last seen</th></tr></thead>
    <tbody id="burstAlerts"></tbody>
  </table>
</div>

<div class="grid">
  <div class="card">
    <div class="oid" style="margin-bottom:8px"><b>Top IPs por rate (últimos {{ window_min }} min)</b></div>
    <table>
      <thead><tr><th>IP</th><th>Quantity</th><th>Avg/min</th><th>Last seen</th></tr></thead>
      <tbody id="topIpRates"></tbody>
    </table>
  </div>

  <div class="card">
    <div class="oid" style="margin-bottom:8px"><b>Top OIDs (VarBinds)</b></div>
    <table>
      <thead><tr><th>OID</th><th>Count</th></tr></thead>
      <tbody id="topOids"></tbody>
    </table>
  </div>
</div>

<div class="grid">
  <div class="card">
    <div class="oid" style="margin-bottom:8px"><b>Top IPs origen (total)</b></div>
    <table>
      <thead><tr><th>IP</th><th>Count</th></tr></thead>
      <tbody id="topIps"></tbody>
    </table>
  </div>

  <div class="card">
    <div class="oid" style="margin-bottom:8px"><b>Top Communities (total)</b></div>
    <table>
      <thead><tr><th>Community</th><th>Count</th></tr></thead>
      <tbody id="topComms"></tbody>
    </table>
  </div>
</div>

<script>
function esc(s){ return (s ?? '').toString().replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;'); }

async function loadObs() {
  const [statsR, healthR] = await Promise.all([ fetch('/api/stats'), fetch('/api/health') ]);
  const stats = await statsR.json();
  const health = await healthR.json();

  const total = stats.total ?? 0;
  const last = stats.last_trap;
  const lastLine = last
    ? `Último: ${esc(last.timestamp)} | SRC ${esc(last.src_ip)}:${esc(last.src_port)} | COMM ${esc(last.community)}`
    : `Sin traps aún`;

  document.getElementById('summary').innerHTML =
    `Total traps en buffer: ${total}<br/>` +
    `${lastLine}<br/>` +
    `Uptime web: ${esc(health.uptime_seconds)}s`;

  const series = (stats.rate_per_minute ?? []).slice(-20);
  document.getElementById('rate').innerHTML =
    series.map(p => `${esc(p.minute)}=${esc(p.count)}`).join(' | ');

  // Bursts
  const alerts = stats.burst_alerts ?? [];
  const badge = document.getElementById('burstBadge');
  if (alerts.length > 0) {
    badge.textContent = `ALERT: ${alerts.length}`;
    badge.className = 'badge alert';
  } else {
    badge.textContent = 'OK';
    badge.className = 'badge';
  }

  document.getElementById('burstAlerts').innerHTML =
    (alerts.length ? alerts : (stats.bursts ?? [])).map(x => {
      const status = x.is_alert ? 'ALERT' : 'OK';
      return `<tr>
        <td class="oid">${esc(status)}</td>
        <td class="oid">${esc(x.src_ip)}</td>
        <td class="oid">${esc(x.quantity)}</td>
        <td class="oid">${esc(x.threshold)}</td>
        <td class="oid">${esc(x.window_seconds)}</td>
        <td class="oid">${esc(x.last_seen)}</td>
      </tr>`;
    }).join('');

  // Top IP rates (15m)
  const topIpRates = stats.top_ip_rates ?? [];
  document.getElementById('topIpRates').innerHTML =
    topIpRates.map(x => `<tr><td class="oid">${esc(x.src_ip)}</td><td class="oid">${esc(x.quantity)}</td><td class="oid">${esc(x.avg_per_min)}</td><td class="oid">${esc(x.last_seen)}</td></tr>`).join('');

  // Top OIDs
  const topOids = stats.top_oids ?? [];
  document.getElementById('topOids').innerHTML =
    topOids.map(x => `<tr><td class="oid">${esc(x.oid)}</td><td class="oid">${esc(x.count)}</td></tr>`).join('');

  // totals
  const topIps = stats.top_ips ?? [];
  document.getElementById('topIps').innerHTML =
    topIps.map(x => `<tr><td class="oid">${esc(x.src_ip)}</td><td class="oid">${esc(x.count)}</td></tr>`).join('');

  const topComms = stats.top_communities ?? [];
  document.getElementById('topComms').innerHTML =
    topComms.map(x => `<tr><td class="oid">${esc(x.community)}</td><td class="oid">${esc(x.count)}</td></tr>`).join('');
}

setInterval(loadObs, 5000);
loadObs();
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

    @app.route("/observability")
    def observability_page():
        return render_page(
            "Observabilidad",
            "Observabilidad",
            "obs",
            OBS_BODY,
            window_min=RATE_WINDOW_MINUTES,
            burst_window=BURST_WINDOW_SECONDS,
            burst_threshold=BURST_THRESHOLD,
        )

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
            "<div class='card'>Buffer limpiado. <a class='btn' href='/system' style='margin-left:10px'>Volver</a></div>",
        )

    @app.route("/api/traps")
    def api_traps():
        return jsonify(list(traps_buffer) if traps_buffer is not None else [])

    @app.route("/api/stats")
    def api_stats():
        traps = list(traps_buffer) if traps_buffer is not None else []
        return jsonify(compute_stats_from_traps(traps))

    @app.route("/api/health")
    def api_health():
        traps = list(traps_buffer) if traps_buffer is not None else []
        last_ts = traps[0].get("timestamp") if traps else None
        return jsonify(
            {
                "status": "ok",
                "uptime_seconds": int(time.time() - WEB_START_EPOCH),
                "buffer_size": len(traps),
                "last_trap_timestamp": last_ts,
            }
        )

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
