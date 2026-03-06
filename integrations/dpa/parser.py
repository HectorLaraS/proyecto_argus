from typing import Any, Dict

from integrations.dpa.models import DpaTrapParsed, DpaIssue


DPA_OID_DB_INSTANCE = "1.3.6.1.4.1.22980.1.1"
DPA_OID_ALERT_NAME = "1.3.6.1.4.1.22980.1.2"
DPA_OID_ALERT_STATUS = "1.3.6.1.4.1.22980.1.3"
DPA_OID_ALERT_TIME = "1.3.6.1.4.1.22980.1.5"
DPA_OID_QUERY_RESULT = "1.3.6.1.4.1.22980.1.8"


def _build_oid_map(trap: Dict[str, Any]) -> Dict[str, str]:
    """
    Convierte la lista trap['oids'] en un diccionario:
    {
        "<oid>": "<value>"
    }
    """
    oid_map: Dict[str, str] = {}

    for vb in trap.get("oids", []):
        oid = str(vb.get("oid", "")).strip()
        value = str(vb.get("value", "")).strip()

        if oid:
            oid_map[oid] = value

    return oid_map


def _parse_db_instance(db_instance_raw: str) -> tuple[str, str]:
    """
    Separa db_instance_raw en:
    - server_name
    - instance_name

    Ejemplos:
      KCTACTOOLSD03\\SQLEXPRESS -> ("KCTACTOOLSD03", "SQLEXPRESS")
      DBSERVER01 -> ("DBSERVER01", "")
    """
    raw = (db_instance_raw or "").strip()

    if "\\" in raw:
        server_name, instance_name = raw.split("\\", 1)
        return server_name.strip(), instance_name.strip()

    return raw, ""


def parse_dpa_trap(trap: Dict[str, Any]) -> DpaTrapParsed:
    """
    Parsea un trap DPA recibido por ARGUS y devuelve un DpaTrapParsed.
    """
    oid_map = _build_oid_map(trap)

    db_instance_raw = oid_map.get(DPA_OID_DB_INSTANCE, "")
    server_name, instance_name = _parse_db_instance(db_instance_raw)

    return DpaTrapParsed(
        source_ip=str(trap.get("src_ip", "")).strip(),
        community=str(trap.get("community", "")).strip(),
        timestamp=str(trap.get("timestamp", "")).strip(),
        db_instance_raw=db_instance_raw,
        server_name=server_name,
        instance_name=instance_name,
        alert_name=oid_map.get(DPA_OID_ALERT_NAME, ""),
        alert_status_raw=oid_map.get(DPA_OID_ALERT_STATUS, ""),
        alert_time_text=oid_map.get(DPA_OID_ALERT_TIME, ""),
        query_result=oid_map.get(DPA_OID_QUERY_RESULT, ""),
        raw_oids=oid_map,
    )

def _build_issue_key(db_instance_raw: str, alert_name: str) -> str:
    """
    Construye una clave estable para correlacionar la alerta.
    """
    left = (db_instance_raw or "").strip()
    right = (alert_name or "").strip()
    return f"{left}|{right}"


def _resolve_issue_status(alert_status_raw: str) -> str:
    """
    Regla de negocio acordada:
    - NORMAL -> CLOSED
    - cualquier otro status -> OPEN
    """
    status = (alert_status_raw or "").strip().upper()

    if status == "NORMAL":
        return "CLOSED"

    return "OPEN"


def build_dpa_issue(parsed: DpaTrapParsed) -> DpaIssue:
    """
    Convierte un DpaTrapParsed en un DpaIssue listo para lógica de negocio.
    """
    issue_key = _build_issue_key(parsed.db_instance_raw, parsed.alert_name)
    status = _resolve_issue_status(parsed.alert_status_raw)
    severity = (parsed.alert_status_raw or "").strip()

    return DpaIssue(
        issue_key=issue_key,
        status=status,
        severity=severity,
        source_ip=parsed.source_ip,
        community=parsed.community,
        timestamp=parsed.timestamp,
        db_instance_raw=parsed.db_instance_raw,
        server_name=parsed.server_name,
        instance_name=parsed.instance_name,
        alert_name=parsed.alert_name,
        alert_time_text=parsed.alert_time_text,
        query_result=parsed.query_result,
        raw_oids=parsed.raw_oids,
    )