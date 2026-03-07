from typing import Any, Dict


DPA_COMMUNITIES = {
    "dpa_test",
    # "dpa_prod",
}

SOLARWINDS_COMMUNITIES = {
    "WIU",
    "WIU-2",
    "TACTest",
}


def _get_trap_community(trap: Dict[str, Any]) -> str:
    return str(trap.get("community", "")).strip()


def _is_dpa_community(community: str) -> bool:
    return community in DPA_COMMUNITIES


def _is_solarwinds_community(community: str) -> bool:
    return community in SOLARWINDS_COMMUNITIES


def dispatch_integrations(trap: Dict[str, Any]) -> None:
    """
    Punto central para enrutar traps a integraciones específicas.
    El routing principal se hace por community.
    """
    try:
        community = _get_trap_community(trap)

        if _is_dpa_community(community):
            from integrations.dpa.service import handle_dpa_trap
            handle_dpa_trap(trap)
            return

        if _is_solarwinds_community(community):
            from integrations.solarwinds.service import handle_solarwinds_trap
            handle_solarwinds_trap(trap)
            return

    except Exception as exc:
        print(f"[INTEGRATIONS ERROR] {exc}")