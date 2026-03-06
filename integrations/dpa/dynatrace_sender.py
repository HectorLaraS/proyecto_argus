from __future__ import annotations

import os
import time
from typing import Any, Dict, Optional

import requests
from dotenv import load_dotenv

load_dotenv()

EVENT_SENDER_ENABLED = os.getenv("EVENT_SENDER_ENABLED", "false").lower() == "true"
EVENT_INGEST_URL = os.getenv("EVENT_INGEST_URL", "").strip()
EVENT_API_TOKEN = os.getenv("EVENT_API_TOKEN", "").strip()
EVENT_TIMEOUT = int(os.getenv("EVENT_TIMEOUT", "5"))

DEV_MODE = os.getenv("DEV_MODE", "false").lower() == "true"

# Dynatrace real
DT_ENV_URL = os.getenv("DT_ENV_URL", "").strip()
DT_API_TOKEN = os.getenv("DT_API_TOKEN", "").strip()
DT_ENTITY_TIMEOUT = int(os.getenv("DT_ENTITY_TIMEOUT", "5"))

# Cache TTL
ENTITY_CACHE_TTL_SECONDS = int(os.getenv("ENTITY_CACHE_TTL_SECONDS", "86400"))

# Entity fija para DEV / probe_api
DPA_ENTITY_ID = os.getenv("DPA_ENTITY_ID", "").strip()

# Cache en memoria:
# {
#   "SERVER01": {
#       "entity_id": "HOST-XXXX",
#       "expires_at": 1234567890.0
#   }
# }
_ENTITY_CACHE: Dict[str, Dict[str, Any]] = {}


def _normalize_server_name(server_name: str) -> str:
    return (server_name or "").strip().upper()


def _build_entity_selector(entity_id: Optional[str]) -> Optional[str]:
    entity_id = (entity_id or "").strip()
    if not entity_id:
        return None
    return f"entityId({entity_id})"


def _get_cached_entity_id(server_name: str) -> Optional[str]:
    key = _normalize_server_name(server_name)
    if not key:
        return None

    cached = _ENTITY_CACHE.get(key)
    if not cached:
        return None

    expires_at = float(cached.get("expires_at", 0))
    if time.time() >= expires_at:
        _ENTITY_CACHE.pop(key, None)
        print(f"[EVENT SENDER] Cache expirado para {key}")
        return None

    entity_id = str(cached.get("entity_id", "")).strip()
    if entity_id:
        print(f"[EVENT SENDER] Cache hit {key} -> {entity_id}")
        return entity_id

    return None


def _set_cached_entity_id(server_name: str, entity_id: str) -> None:
    key = _normalize_server_name(server_name)
    entity_id = (entity_id or "").strip()

    if not key or not entity_id:
        return

    _ENTITY_CACHE[key] = {
        "entity_id": entity_id,
        "expires_at": time.time() + ENTITY_CACHE_TTL_SECONDS,
    }
    print(f"[EVENT SENDER] Cache set {key} -> {entity_id} (ttl={ENTITY_CACHE_TTL_SECONDS}s)")


def _invalidate_cached_entity_id(server_name: str) -> None:
    key = _normalize_server_name(server_name)
    if not key:
        return

    removed = _ENTITY_CACHE.pop(key, None)
    if removed is not None:
        print(f"[EVENT SENDER] Cache invalidado para {key}")


def _resolve_entity_id_from_dynatrace(server_name: str, force_refresh: bool = False) -> Optional[str]:
    """
    Resuelve el entityId del host en Dynatrace usando:
      /api/v2/entities?entitySelector=type(HOST),entityName.startsWith("server")
    """
    if not DT_ENV_URL:
        print("[EVENT SENDER] DT_ENV_URL no configurada")
        return None

    if not DT_API_TOKEN:
        print("[EVENT SENDER] DT_API_TOKEN no configurado")
        return None

    if not server_name.strip():
        print("[EVENT SENDER] server_name vacío, no se puede resolver entityId")
        return None

    if force_refresh:
        _invalidate_cached_entity_id(server_name)

    cached_entity_id = _get_cached_entity_id(server_name)
    if cached_entity_id:
        return cached_entity_id

    url = f"{DT_ENV_URL}/api/v2/entities"
    headers = {
        "Authorization": f"Api-Token {DT_API_TOKEN}",
    }
    params = {
        "entitySelector": f'type(HOST),entityName.startsWith("{server_name.lower()}")'
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=DT_ENTITY_TIMEOUT,
        )

        if response.status_code >= 300:
            print(
                f"[EVENT SENDER] Error resolviendo entityId HTTP "
                f"{response.status_code}: {response.text}"
            )
            return None

        data = response.json()
        total_count = int(data.get("totalCount", 0))
        entities = data.get("entities", [])

        if total_count == 0 or not entities:
            print(f"[EVENT SENDER] No se encontró entityId para server_name={server_name}")
            return None

        if total_count > 1:
            print(
                f"[EVENT SENDER] WARNING: múltiples entidades para "
                f"{server_name}, usando la primera"
            )

        entity = entities[0]
        entity_id = str(entity.get("entityId", "")).strip()
        display_name = str(entity.get("displayName", "")).strip()

        if not entity_id:
            print(f"[EVENT SENDER] Respuesta sin entityId para server_name={server_name}")
            return None

        _set_cached_entity_id(server_name, entity_id)
        print(f"[EVENT SENDER] entity resolved {server_name} -> {entity_id} ({display_name})")
        return entity_id

    except Exception as exc:
        print(f"[EVENT SENDER] Error resolviendo entityId para {server_name}: {exc}")
        return None


def _resolve_entity_id(
    issue: Any,
    explicit_entity_id: Optional[str] = None,
    force_refresh: bool = False,
) -> Optional[str]:
    """
    Reglas:
    - Si me pasan entity_id explícito, usarlo.
    - Si DEV_MODE=True, usar DPA_ENTITY_ID y NO llamar Dynatrace.
    - Si DEV_MODE=False, intentar resolver en Dynatrace por server_name.
    """
    if explicit_entity_id and explicit_entity_id.strip():
        return explicit_entity_id.strip()

    if DEV_MODE:
        if DPA_ENTITY_ID:
            print(f"[EVENT SENDER] DEV_MODE activo, usando entityId de prueba: {DPA_ENTITY_ID}")
            return DPA_ENTITY_ID

        print("[EVENT SENDER] DEV_MODE activo pero DPA_ENTITY_ID no está configurado")
        return None

    return _resolve_entity_id_from_dynatrace(issue.server_name, force_refresh=force_refresh)


def _should_retry_entity_resolution(response: requests.Response) -> bool:
    """
    Intenta detectar si el fallo del POST puede deberse a un entityId inválido/obsoleto.
    No es perfecto, pero cubre los casos más comunes.
    """
    if response.status_code not in {400, 404, 409, 422}:
        return False

    body = ""
    try:
        body = response.text.lower()
    except Exception:
        return False

    patterns = [
        "entity",
        "selector",
        "entityselector",
        "entityid",
        "unknown entity",
        "invalid entity",
        "cannot find entity",
        "no entity",
    ]

    return any(p in body for p in patterns)


def build_event_payload(issue: Any, entity_id: Optional[str] = None) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "eventType": "CUSTOM_ALERT" if issue.status == "OPEN" else "CUSTOM_INFO",
        "title": issue.alert_name,
        "properties": {
            "source": "argus_dpa",
            "issue_key": issue.issue_key,
            "server_name": issue.server_name,
            "instance_name": issue.instance_name,
            "db_instance": issue.db_instance_raw,
            "severity": issue.severity,
            "status": issue.status,
            "query_result": issue.query_result,
            "community": issue.community,
            "source_ip": issue.source_ip,
            "alert_time_text": issue.alert_time_text,
        },
    }

    entity_selector = _build_entity_selector(entity_id)
    if entity_selector:
        payload["entitySelector"] = entity_selector

    return payload


def _post_event(payload: Dict[str, Any]) -> requests.Response:
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Api-Token {EVENT_API_TOKEN}",
    }

    return requests.post(
        EVENT_INGEST_URL,
        json=payload,
        headers=headers,
        timeout=EVENT_TIMEOUT,
    )


def send_event(issue: Any, entity_id: Optional[str] = None) -> None:
    if not EVENT_SENDER_ENABLED:
        print("[EVENT SENDER] Deshabilitado por configuración")
        return

    if not EVENT_INGEST_URL:
        print("[EVENT SENDER] EVENT_INGEST_URL no configurada")
        return

    if not EVENT_API_TOKEN:
        print("[EVENT SENDER] EVENT_API_TOKEN no configurado")
        return

    resolved_entity_id = _resolve_entity_id(issue, entity_id, force_refresh=False)
    payload = build_event_payload(issue, resolved_entity_id)

    try:
        response = _post_event(payload)

        if response.status_code < 300:
            print("[EVENT SENDER] Evento enviado correctamente")
            if resolved_entity_id:
                print(f"[EVENT SENDER] entitySelector=entityId({resolved_entity_id})")
            else:
                print("[EVENT SENDER] Evento enviado sin entitySelector")
            return

        print(f"[EVENT SENDER] Error HTTP {response.status_code}: {response.text}")

        # Solo en modo real vale la pena re-resolver contra Dynatrace.
        if DEV_MODE:
            return

        # Si el error parece relacionado con entityId inválido/obsoleto,
        # invalidamos cache, resolvemos de nuevo y reintentamos una sola vez.
        if resolved_entity_id and _should_retry_entity_resolution(response):
            print(
                f"[EVENT SENDER] Posible entityId inválido para {issue.server_name}. "
                "Intentando refresh de cache y retry único..."
            )

            refreshed_entity_id = _resolve_entity_id(issue, entity_id=None, force_refresh=True)

            if not refreshed_entity_id:
                print("[EVENT SENDER] No fue posible refrescar entityId, no se reintentará")
                return

            retry_payload = build_event_payload(issue, refreshed_entity_id)
            retry_response = _post_event(retry_payload)

            if retry_response.status_code < 300:
                print("[EVENT SENDER] Evento enviado correctamente después de refresh de entityId")
                print(f"[EVENT SENDER] entitySelector=entityId({refreshed_entity_id})")
                return

            print(
                f"[EVENT SENDER] Retry falló HTTP {retry_response.status_code}: "
                f"{retry_response.text}"
            )

    except Exception as exc:
        print(f"[EVENT SENDER] Error enviando evento: {exc}")