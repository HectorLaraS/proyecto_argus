import os
import requests
from dotenv import load_dotenv

load_dotenv()

DT_ENV_URL = os.getenv("DT_ENV_URL")
DT_API_TOKEN = os.getenv("DT_API_TOKEN")

HEADERS = {
    "Authorization": f"Api-Token {DT_API_TOKEN}"
}


def resolve_host_entity(server_name: str) -> str | None:
    url = f"{DT_ENV_URL}/api/v2/entities"

    params = {
        "entitySelector": f'type(HOST),entityName.startsWith("{server_name.lower()}")'
    }

    try:
        r = requests.get(url, headers=HEADERS, params=params, timeout=5)
        r.raise_for_status()

        data = r.json()

        if data["totalCount"] == 0:
            print(f"[ENTITY RESOLVER] No entity found for {server_name}")
            return None

        entity = data["entities"][0]
        entity_id = entity["entityId"]

        print(f"[ENTITY RESOLVER] {server_name} -> {entity_id}")

        return entity_id

    except Exception as e:
        print(f"[ENTITY RESOLVER] Error resolving {server_name}: {e}")
        return None