# windows_main_argus.py
"""
ARGUS (Windows - Memory Only)
============================

SNMP Trap Receiver + Web UI + Observabilidad + Export (TXT/JSON)
- Sin SQLite (sin persistencia)
- Buffer en memoria (multiprocessing.Manager().list)
- Log a archivo local
- Observabilidad (Top OIDs, Top IPs, rate por minuto, burst alerts)
- Export TXT/JSON desde memoria
- Hook de integraciones
- UI base de Integraciones

Requisitos:
  pip install pysnmp flask python-dotenv

Ejecución (Windows):
  python windows_main_argus.py

Notas:
- Directorio de trabajo fijo:
    D:\TAC - Python\snmp_server
- El log se escribe en:
    D:\TAC - Python\snmp_server\data\traps_received.log
"""

from __future__ import annotations

import asyncio
import multiprocessing as mp
import os
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from collections import Counter

from flask import Flask, jsonify, render_template_string, request

from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.carrier.asyncio.dgram import udp
from dotenv import load_dotenv

from integrations.dispatcher import dispatch_integrations
from integrations.dpa.memory_store import (
    clear_all,
    configure_store,
    get_active_issues,
    get_recent_events,
    get_summary,
)

load_dotenv()


# ================== CONFIG (WINDOWS) ==================
SNMP_LISTEN_IP = "0.0.0.0"
SNMP_PORT = 162
MAX_TRAPS = 200

WEB_HOST = "0.0.0.0"
WEB_PORT = 5010

# Directorio fijo para Windows (tu ruta)
PROJECT_ROOT = os.getenv("PROJECT_ROOT_PATH") or os.getcwd()
DATA_DIR = os.path.join(PROJECT_ROOT, "data")

# Log dentro de data para evitar problemas con cwd
LOG_FILE = os.path.join(DATA_DIR, "traps_received.log")

DEBUG_OBSERVER_ONCE = False  # True => imprime keys del observer una vez

# Observabilidad
RATE_WINDOW_MINUTES = 15

# Burst detection
BURST_WINDOW_SECONDS = 60
BURST_THRESHOLD = 20
BURST_TOP = 10


traps_buffer: Optional[Any] = None
WEB_START_EPOCH = time.time()

# (src_ip, src_port, community) visto por observer
_LAST_PEER: Tuple[str, Optional[int], str] = ("", None, "")


# ================== UTILS ==================
def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def _buffer_insert_front(buffer: Any, item: Dict[str, Any], max_items: int) -> None:
    buffer.insert(0, item)
    del buffer[max_items:]


def _parse_ts(ts: str) -> Optional[datetime]:
    try:
        return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


def _epoch_now() -> int:
    return int(time.time())


def _fmt_ts_from_epoch(epoch: int) -> str:
    return datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S")


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


# ================== MEM STATS ==================
def compute_stats_from_traps(traps: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(traps)
    last = traps[0] if traps else None

    ip_counter = Counter()
    comm_counter = Counter()
    oid_counter = Counter()

    now = datetime.now()
    window_start = now - timedelta(minutes=RATE_WINDOW_MINUTES)
    per_min = Counter()

    window_ip_counter = Counter()
    ip_last_seen: Dict[str, str] = {}

    burst_start = now - timedelta(seconds=BURST_WINDOW_SECONDS)
    burst_ip_counter = Counter()
    burst_ip_last_seen: Dict[str, str] = {}

    for t in traps:
        src_ip = t.get("src_ip") or "-"
        community = t.get("community") or "-"

        ip_counter[src_ip] += 1
        comm_counter[community] += 1

        for vb in t.get("oids", []):
            oid = vb.get("oid") or "-"
            oid_counter[oid] += 1

        if src_ip not in ip_last_seen:
            ip_last_seen[src_ip] = t.get("timestamp", "")

        ts = _parse_ts(t.get("timestamp", ""))
        if not ts:
            continue

        if ts >= window_start:
            per_min[ts.strftime("%H:%M")] += 1
            window_ip_counter[src_ip] += 1

        if ts >= burst_start:
            burst_ip_counter[src_ip] += 1
            if src_ip not in burst_ip_last_seen:
                burst_ip_last_seen[src_ip] = t.get("timestamp", "")

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
    burst_alerts = [b for b in bursts if b["is_alert"]]

    return {
        "source": "mem",
        "total": total,
        "last_trap": last,
        "top_ips": top_ips,
        "top_communities": top_comms,
        "top_oids": top_oids,
        "rate_window_minutes": RATE_WINDOW_MINUTES,
        "rate_per_minute": rate_series,
        "top_ip_rates": top_ip_rates,
        "burst": {
            "window_seconds": int(BURST_WINDOW_SECONDS),
            "threshold": int(BURST_THRESHOLD),
            "top": int(BURST_TOP),
        },
        "bursts": bursts,
        "burst_alerts": burst_alerts,
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


def process_trap_general(buffer: Any, trap: Dict[str, Any], max_items: int) -> None:
    """
    Flujo principal actual de ARGUS:
    - guardar en buffer
    - escribir log
    - imprimir en consola
    """
    _buffer_insert_front(buffer, trap, max_items)

    dt = datetime.now()
    src_ip = trap.get("src_ip", "")
    src_port = trap.get("src_port", None)
    community = trap.get("community", "")

    try:
        with open(LOG_FILE, "a", encoding="utf-8") as log_trap:
            log_trap.write("\nTrap Received:")
            log_trap.write(f"\n  Datetime: {dt}")
            log_trap.write(f"\n  SRC: {src_ip}:{src_port}")
            log_trap.write(f"\n  COMMUNITY: {community}")
            for vb in trap["oids"]:
                log_trap.write(f"\n  {vb['oid']} = {vb['value']}")
            log_trap.write("\n")
            log_trap.flush()
    except Exception as e:
        print(f"[LOG ERROR] {e} (cwd={os.getcwd()}, abs={os.path.abspath(LOG_FILE)})")

    print(f"Trap recibido (buffer={len(buffer)}) SRC={src_ip}:{src_port} COMMUNITY={community}")


# ================== SNMP CALLBACK ==================
def trap_callback(snmpEngine, stateReference, contextEngineId, contextName, varBinds, cbCtx):
    buffer = cbCtx["buffer"]
    max_items = cbCtx["max"]

    global _LAST_PEER
    src_ip, src_port, community = _LAST_PEER

    ts_epoch = _epoch_now()
    trap = {
        "ts_epoch": ts_epoch,
        "timestamp": _fmt_ts_from_epoch(ts_epoch),
        "src_ip": src_ip,
        "src_port": src_port,
        "community": community,
        "oids": [],
    }

    for name, val in varBinds:
        trap["oids"].append({"oid": name.prettyPrint(), "value": val.prettyPrint()})

    process_trap_general(buffer, trap, max_items)

    try:
        dispatch_integrations(trap)
    except Exception as e:
        print(f"[DISPATCH ERROR] {e}")

# ================== SNMP SERVER (PROCESS) ==================
def start_snmp_server(
    shared_buffer,
    dpa_active_issues,
    dpa_recent_events,
    listen_ip: str,
    listen_port: int,
    max_items: int,
) -> None:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    configure_store(dpa_active_issues, dpa_recent_events)

    snmpEngine = engine.SnmpEngine()
    _register_observer_compat(snmpEngine, _peer_observer, "rfc3412.receiveMessage:request")

    # Comunidades permitidas (v1/v2c)
    config.add_v1_system(snmpEngine, "public", "public")
    config.add_v1_system(snmpEngine, "TACTest", "TACTest")
    config.add_v1_system(snmpEngine, "WIU", "ALSTOM SNMP")
    config.add_v1_system(snmpEngine, "WIU-2", "ALSTOM SNMP Trap")
    config.add_v1_system(snmpEngine, "DAU", "helloworld")
    config.add_v1_system(snmpEngine, "dpa_test", "dpa_test")
    ##config.add_v1_system(snmpEngine, 'router', 'public')

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
    print(f"DATA DIR: {os.path.abspath(DATA_DIR)}")

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
    :root { --bg:#0f172a; --panel:#111c33; --border:#334155; --text:#e5e7eb; --muted:#94a3b8; --danger:#fb7185; --ok:#4ade80; --warn:#fbbf24; --info:#38bdf8; }
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
    th, td { text-align:left; padding:8px; border-bottom:1px solid rgba(51,65,85,.5); vertical-align: top; }
    th { color: var(--muted); font-weight: 600; }
    .grid { display:grid; grid-template-columns: 1fr 1fr; gap: 12px; }
    @media (max-width: 900px) { .grid { grid-template-columns: 1fr; } }
    .badge { display:inline-block; padding:2px 8px; border-radius:999px; font-size:.85rem; border:1px solid rgba(148,163,184,.35); color:var(--muted); }
    .badge.alert { border-color: rgba(251,113,133,.6); color: var(--danger); }
    .badge.ok { border-color: rgba(74,222,128,.5); color: var(--ok); }
    .badge.warn { border-color: rgba(251,191,36,.5); color: var(--warn); }
    .badge.info { border-color: rgba(56,189,248,.5); color: var(--info); }
    .small { color: var(--muted); font-size:.9rem; }
    .btn { display:inline-block; padding:8px 10px; border-radius:10px; border:1px solid var(--border); text-decoration:none; color:var(--text); background:rgba(51,65,85,.25) }
    .btn:hover { border-color:rgba(56,189,248,.6); background:rgba(56,189,248,.10) }
    .empty { color: var(--muted); padding: 10px 0; }
  </style>
</head>
<body>
  <div class="nav">
    <a href="/" class="{{ 'active' if active=='live' else '' }}">Live</a>
    <a href="/observability" class="{{ 'active' if active=='obs' else '' }}">Observabilidad</a>
    <a href="/export" class="{{ 'active' if active=='export' else '' }}">Exportar</a>
    <a href="/system" class="{{ 'active' if active=='system' else '' }}">Sistema</a>
    <a href="/integrations" class="{{ 'active' if active=='integrations' else '' }}">Integraciones</a>
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
  <div class="small">
    Esta versión Windows es <b>solo memoria</b>. API:
    <span class="oid">/api/traps</span> (mem),
    <span class="oid">/api/stats</span>,
    <span class="oid">/api/health</span>
  </div>
</div>

<div id="traps"></div>
<script>
function esc(s){ return (s ?? '').toString().replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;'); }

async function loadTraps() {
  const r = await fetch(`/api/traps?limit=200`);
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
      `<div class="time">${esc(t.timestamp)}</div>` +
      `<div class="meta oid">SRC: ${esc(srcIp)}:${esc(srcPort)}</div>` +
      `<div class="meta oid">COMMUNITY: ${esc(comm)}</div>` +
      (t.oids || []).map(o => `<div class="oid">${esc(o.oid)} = ${esc(o.value)}</div>`).join('');
    c.appendChild(div);
  });
}
setInterval(loadTraps, 2000);
loadTraps();
</script>
"""

OBS_BODY = """
<div class="card">
  <div class="small">
    Observabilidad <b>en memoria</b>. Refresh cada 5s.
  </div>
</div>

<div class="card">
  <div class="oid" style="margin-bottom:8px"><b>Burst Alerts</b> <span id="burstBadge" class="badge">-</span></div>
  <div class="small">
    Regla: >= <span class="oid">{{ burst_threshold }}</span> traps en <span class="oid">{{ burst_window }}</span>s por IP.
  </div>
  <table>
    <thead><tr><th>Status</th><th>IP</th><th>Quantity</th><th>Threshold</th><th>Window(s)</th><th>Last seen</th></tr></thead>
    <tbody id="burstAlerts"></tbody>
  </table>
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
  const [statsR, healthR] = await Promise.all([
    fetch(`/api/stats`),
    fetch('/api/health')
  ]);
  const stats = await statsR.json();
  const health = await healthR.json();

  const total = stats.total ?? 0;
  const last = stats.last_trap;

  const lastLine = last
    ? `Último: ${esc(last.timestamp)} | SRC ${esc(last.src_ip)}:${esc(last.src_port)} | COMM ${esc(last.community)}`
    : `Sin traps aún`;

  document.getElementById('summary').innerHTML =
    `Source: ${esc(stats.source)}<br/>` +
    `Total traps: ${total}<br/>` +
    `${lastLine}<br/>` +
    `Uptime web: ${esc(health.uptime_seconds)}s<br/>` +
    `Log: ${esc(health.log_path)}<br/>` +
    `Data dir: ${esc(health.data_dir)}`;

  const series = (stats.rate_per_minute ?? []).slice(-20);
  document.getElementById('rate').innerHTML =
    series.map(p => `${esc(p.minute)}=${esc(p.count)}`).join(' | ');

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

  const topIpRates = stats.top_ip_rates ?? [];
  document.getElementById('topIpRates').innerHTML =
    topIpRates.map(x => `<tr><td class="oid">${esc(x.src_ip)}</td><td class="oid">${esc(x.quantity)}</td><td class="oid">${esc(x.avg_per_min)}</td><td class="oid">${esc(x.last_seen)}</td></tr>`).join('');

  const topOids = stats.top_oids ?? [];
  document.getElementById('topOids').innerHTML =
    topOids.map(x => `<tr><td class="oid">${esc(x.oid)}</td><td class="oid">${esc(x.count)}</td></tr>`).join('');

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
  <div class="small">Exporta desde memoria.</div>
  <div style="margin-top:10px">
    <a class="btn" href="/export/json">Descargar JSON</a>
    <a class="btn" href="/export/txt" style="margin-left:10px">Descargar TXT</a>
  </div>
</div>
"""

SYSTEM_BODY = """
<div class="card">
  <div class="oid">SNMP: {{ snmp_ip }}:{{ snmp_port }}</div>
  <div class="oid">Web: {{ web_host }}:{{ web_port }}</div>
  <div class="oid">Data Dir: {{ data_dir }}</div>
  <div class="oid">Log: {{ log_path }}</div>
</div>

<div class="card">
  <a class="btn" href="/system/clear">Limpiar buffer (mem)</a>
</div>
"""

INTEGRATIONS_BODY = """
<div class="card">
  <div class="small">
    Módulos de integración registrados en ARGUS.
    Esta vista es la base para mostrar active alerts, health y últimas acciones por integración.
  </div>
</div>

<div class="grid">
  <div class="card">
    <div class="oid" style="margin-bottom:8px"><b>Resumen</b></div>
    <div id="integrationSummary" class="oid"></div>
  </div>

  <div class="card">
    <div class="oid" style="margin-bottom:8px"><b>Health</b></div>
    <table>
      <thead><tr><th>Integración</th><th>Status</th><th>Detalle</th></tr></thead>
      <tbody id="integrationHealth"></tbody>
    </table>
  </div>
</div>

<div class="card">
  <div class="oid" style="margin-bottom:8px"><b>DPA - Active Alerts</b></div>
  <table>
    <thead>
      <tr>
        <th>Status</th>
        <th>Issue Key</th>
        <th>Severity</th>
        <th>Source IP</th>
        <th>DB Instance</th>
        <th>Alert Name</th>
        <th>Last Seen</th>
      </tr>
    </thead>
    <tbody id="dpaActiveAlerts"></tbody>
  </table>
</div>

<div class="card">
  <div class="oid" style="margin-bottom:8px"><b>DPA - Últimos eventos</b></div>
  <table>
    <thead>
      <tr>
        <th>Timestamp</th>
        <th>Action</th>
        <th>Issue Key</th>
        <th>Severity</th>
        <th>Destino</th>
      </tr>
    </thead>
    <tbody id="dpaRecentEvents"></tbody>
  </table>
</div>

<script>
function esc(s){ return (s ?? '').toString().replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;'); }

function renderEmptyRow(colspan, text) {
  return `<tr><td class="empty oid" colspan="${colspan}">${esc(text)}</td></tr>`;
}

async function loadIntegrations() {
  const [summaryR, activeR] = await Promise.all([
    fetch('/api/integrations/summary'),
    fetch('/api/integrations/dpa/active-alerts')
  ]);

  const summary = await summaryR.json();
  const active = await activeR.json();

  document.getElementById('integrationSummary').innerHTML =
    `Integraciones registradas: ${esc(summary.total_integrations)}<br/>` +
    `DPA habilitada: ${esc(summary.dpa_enabled)}<br/>` +
    `Probe API configurado: ${esc(summary.probe_api_enabled)}<br/>` +
    `Active alerts DPA: ${esc(summary.dpa_active_alerts)}`;

  document.getElementById('integrationHealth').innerHTML =
    (summary.health || []).map(x => `
      <tr>
        <td class="oid">${esc(x.name)}</td>
        <td class="oid">${esc(x.status)}</td>
        <td class="oid">${esc(x.detail)}</td>
      </tr>
    `).join('') || renderEmptyRow(3, 'Sin información de health');

  document.getElementById('dpaActiveAlerts').innerHTML =
    ((active.items || []).length
      ? (active.items || []).map(x => `
        <tr>
          <td class="oid">${esc(x.status)}</td>
          <td class="oid">${esc(x.issue_key)}</td>
          <td class="oid">${esc(x.severity)}</td>
          <td class="oid">${esc(x.source_ip)}</td>
          <td class="oid">${esc(x.db_instance)}</td>
          <td class="oid">${esc(x.alert_name)}</td>
          <td class="oid">${esc(x.last_seen)}</td>
        </tr>
      `).join('')
      : renderEmptyRow(7, 'Sin active alerts DPA todavía'));

  document.getElementById('dpaRecentEvents').innerHTML =
    ((active.recent_events || []).length
      ? (active.recent_events || []).map(x => `
        <tr>
          <td class="oid">${esc(x.timestamp)}</td>
          <td class="oid">${esc(x.action)}</td>
          <td class="oid">${esc(x.issue_key)}</td>
          <td class="oid">${esc(x.severity)}</td>
          <td class="oid">${esc(x.target)}</td>
        </tr>
      `).join('')
      : renderEmptyRow(5, 'Sin eventos recientes DPA todavía'));
}

setInterval(loadIntegrations, 5000);
loadIntegrations();
</script>
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
        return render_page("Live", "Traps (Live) - Mem", "live", LIVE_BODY)

    @app.route("/observability")
    def observability_page():
        return render_page(
            "Observabilidad",
            "Observabilidad (Mem)",
            "obs",
            OBS_BODY,
            window_min=RATE_WINDOW_MINUTES,
            burst_window=BURST_WINDOW_SECONDS,
            burst_threshold=BURST_THRESHOLD,
        )

    @app.route("/export")
    def export_page():
        return render_page("Exportar", "Exportar (Mem)", "export", EXPORT_BODY)

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
            data_dir=os.path.abspath(DATA_DIR),
            log_path=os.path.abspath(LOG_FILE),
        )
    
    @app.route("/api/integrations/dpa/active-alerts")
    def api_dpa_active_alerts():
        return jsonify(
            {
                "items": get_active_issues(),
                "recent_events": get_recent_events(),
            }
        )

    
    @app.route("/api/integrations/dpa/events")
    def api_dpa_events():
        return jsonify(get_recent_events())

    @app.route("/api/integrations/summary")
    def api_integrations_summary():
        summary = get_summary()

        return jsonify(
            {
                "total_integrations": 1,
                "dpa_enabled": True,
                "probe_api_enabled": False,
                "dpa_active_alerts": summary["active_count"],
                "health": [
                    {"name": "dpa", "status": "READY", "detail": "Memory store conectado"},
                    {"name": "probe_api", "status": "PENDING", "detail": "Aún no configurado"},
                    {"name": "mssql", "status": "PENDING", "detail": "Sin repositorio conectado"},
                ],
            }
        )

    @app.route("/integrations")
    def integrations_page():
        return render_page(
            "Integraciones",
            "Integraciones",
            "integrations",
            INTEGRATIONS_BODY,
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

        clear_all()

        return render_page(
            "Sistema",
            "Sistema",
            "system",
            "<div class='card'>Buffer (mem) limpiado. <a class='btn' href='/system' style='margin-left:10px'>Volver</a></div>",
        )

    @app.route("/api/traps")
    def api_traps():
        limit = int(request.args.get("limit") or MAX_TRAPS)
        traps = list(traps_buffer) if traps_buffer is not None else []
        return jsonify(traps[: max(0, min(limit, 5000))])

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
                "data_dir": os.path.abspath(DATA_DIR),
                "log_path": os.path.abspath(LOG_FILE),
            }
        )

    @app.route("/export/json")
    def export_json():
        traps = list(traps_buffer) if traps_buffer is not None else []
        return jsonify(traps)

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

    _ensure_dir(DATA_DIR)

    try:
        mp.set_start_method("spawn")
    except RuntimeError:
        pass

    manager = mp.Manager()

    traps_buffer = manager.list()

    dpa_active_issues = manager.dict()
    dpa_recent_events = manager.list()

    configure_store(dpa_active_issues, dpa_recent_events)

    snmp_proc = mp.Process(
        target=start_snmp_server,
        args=(
            traps_buffer,
            dpa_active_issues,
            dpa_recent_events,
            SNMP_LISTEN_IP,
            SNMP_PORT,
            MAX_TRAPS,
        ),
        daemon=True,
    )
    snmp_proc.start()

    app = create_app()
    print(f"Web UI disponible en http://{WEB_HOST}:{WEB_PORT}")
    app.run(host=WEB_HOST, port=WEB_PORT, threaded=False)

if __name__ == "__main__":
    mp.freeze_support()
    main()