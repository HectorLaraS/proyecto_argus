from __future__ import annotations

from threading import Lock
from typing import Any, Dict, List, Optional

from integrations.dpa.models import DpaIssue


_active_issues: Optional[Any] = None
_recent_events: Optional[Any] = None
_lock = Lock()

MAX_RECENT_EVENTS = 100


def configure_store(active_issues: Any, recent_events: Any) -> None:
    global _active_issues, _recent_events
    _active_issues = active_issues
    _recent_events = recent_events


def _ensure_configured() -> None:
    if _active_issues is None or _recent_events is None:
        raise RuntimeError("DPA memory store no ha sido configurado con configure_store()")


def _issue_to_dict(issue: DpaIssue) -> Dict[str, Any]:
    return {
        "issue_key": issue.issue_key,
        "status": issue.status,
        "severity": issue.severity,
        "source_ip": issue.source_ip,
        "community": issue.community,
        "timestamp": issue.timestamp,
        "db_instance_raw": issue.db_instance_raw,
        "server_name": issue.server_name,
        "instance_name": issue.instance_name,
        "alert_name": issue.alert_name,
        "alert_time_text": issue.alert_time_text,
        "query_result": issue.query_result,
        "raw_oids": dict(issue.raw_oids),
    }


def _push_event(timestamp: str, action: str, issue_key: str, severity: str, target: str = "memory") -> None:
    _recent_events.insert(
        0,
        {
            "timestamp": timestamp,
            "action": action,
            "issue_key": issue_key,
            "severity": severity,
            "target": target,
        },
    )
    del _recent_events[MAX_RECENT_EVENTS:]


def upsert_issue(issue: DpaIssue) -> str:
    """
    Inserta o actualiza una alerta activa.
    Regresa:
      - OPEN si no existía
      - UPDATE si ya existía
    """
    _ensure_configured()

    with _lock:
        existed = issue.issue_key in _active_issues
        _active_issues[issue.issue_key] = _issue_to_dict(issue)

        action = "UPDATE" if existed else "OPEN"
        _push_event(issue.timestamp, action, issue.issue_key, issue.severity)
        return action


def close_issue(issue: DpaIssue) -> str:
    """
    Cierra una alerta activa solo si existía.
    Regresa:
      - CLOSE si estaba abierta
      - NOOP si no existía
    """
    _ensure_configured()

    with _lock:
        existed = issue.issue_key in _active_issues

        if existed:
            _active_issues.pop(issue.issue_key, None)
            _push_event(issue.timestamp, "CLOSE", issue.issue_key, issue.severity)
            return "CLOSE"

        return "NOOP"


def get_active_issue(issue_key: str) -> Optional[Dict[str, Any]]:
    _ensure_configured()

    with _lock:
        data = _active_issues.get(issue_key)
        return dict(data) if data else None


def get_active_issues() -> List[Dict[str, Any]]:
    _ensure_configured()

    with _lock:
        items: List[Dict[str, Any]] = []

        for issue in _active_issues.values():
            items.append(
                {
                    "status": issue.get("status", ""),
                    "issue_key": issue.get("issue_key", ""),
                    "severity": issue.get("severity", ""),
                    "source_ip": issue.get("source_ip", ""),
                    "db_instance": issue.get("db_instance_raw", ""),
                    "alert_name": issue.get("alert_name", ""),
                    "last_seen": issue.get("timestamp", ""),
                    "server_name": issue.get("server_name", ""),
                    "instance_name": issue.get("instance_name", ""),
                    "alert_time_text": issue.get("alert_time_text", ""),
                    "query_result": issue.get("query_result", ""),
                }
            )

        items.sort(key=lambda x: x["last_seen"], reverse=True)
        return items


def get_recent_events() -> List[Dict[str, Any]]:
    _ensure_configured()

    with _lock:
        return list(_recent_events)


def get_summary() -> Dict[str, int]:
    _ensure_configured()

    with _lock:
        return {
            "active_count": len(_active_issues),
            "recent_event_count": len(_recent_events),
        }


def clear_all() -> None:
    _ensure_configured()

    with _lock:
        _active_issues.clear()
        _recent_events[:] = []