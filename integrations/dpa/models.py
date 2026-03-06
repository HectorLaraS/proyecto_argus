from dataclasses import dataclass, field
from typing import Dict


@dataclass(frozen=True)
class DpaTrapParsed:
    source_ip: str
    community: str
    timestamp: str

    db_instance_raw: str
    server_name: str
    instance_name: str

    alert_name: str
    alert_status_raw: str
    alert_time_text: str
    query_result: str

    raw_oids: Dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class DpaIssue:
    issue_key: str
    status: str
    severity: str

    source_ip: str
    community: str
    timestamp: str

    db_instance_raw: str
    server_name: str
    instance_name: str

    alert_name: str
    alert_time_text: str
    query_result: str

    raw_oids: Dict[str, str] = field(default_factory=dict)