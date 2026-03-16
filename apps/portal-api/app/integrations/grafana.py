import os

GRAFANA_BASE_URL = os.getenv("GRAFANA_BASE_URL", "http://grafana:3000")

def build_embed_url(grafana_uid: str, panel_id: str | None = None) -> str:
    if panel_id:
        return f"{GRAFANA_BASE_URL}/d-solo/{grafana_uid}?panelId={panel_id}&theme=dark"
    return f"{GRAFANA_BASE_URL}/d/{grafana_uid}"