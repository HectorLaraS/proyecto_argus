from typing import Any, Dict

from integrations.dpa.parser import parse_dpa_trap, build_dpa_issue
from integrations.dpa.memory_store import upsert_issue, close_issue


REQUIRED_DPA_OIDS = {
    "1.3.6.1.4.1.22980.1.1",  # db_instance
    "1.3.6.1.4.1.22980.1.2",  # alert_name
    "1.3.6.1.4.1.22980.1.3",  # alert_status
}


def _extract_oid_set(trap: Dict[str, Any]) -> set[str]:
    oid_set: set[str] = set()

    for vb in trap.get("oids", []):
        oid = str(vb.get("oid", "")).strip()
        if oid:
            oid_set.add(oid)

    return oid_set


def _looks_like_dpa_trap(trap: Dict[str, Any]) -> bool:
    oid_set = _extract_oid_set(trap)
    return REQUIRED_DPA_OIDS.issubset(oid_set)


def handle_dpa_trap(trap: Dict[str, Any]) -> None:
    if not _looks_like_dpa_trap(trap):
        print("[DPA] WARNING: trap enroutado por community pero no parece DPA válido")
        return

    parsed = parse_dpa_trap(trap)
    issue = build_dpa_issue(parsed)

    if issue.status == "OPEN":
        action = upsert_issue(issue)
        print(f"[DPA] Active alert {action} en memoria")
    else:
        action = close_issue(issue)
        print(f"[DPA] Active alert {action} en memoria")

    print(f"[DPA] issue_key={issue.issue_key}")
    print(f"[DPA] status={issue.status}")
    print(f"[DPA] severity={issue.severity}")
    print(f"[DPA] server_name={issue.server_name}")
    print(f"[DPA] instance_name={issue.instance_name}")