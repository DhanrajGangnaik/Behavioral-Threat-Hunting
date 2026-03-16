from pydantic import BaseModel
from typing import Optional, List, Dict, Any

class DashboardCreate(BaseModel):
    title: str
    grafana_uid: str
    grafana_panel_id: Optional[str] = None
    app_slug: Optional[str] = None
    visibility: str = "private"
    is_default: bool = False

class DashboardRead(DashboardCreate):
    id: int

    class Config:
        from_attributes = True

class LayoutUpdate(BaseModel):
    layout_json: Dict[str, Any]

class LayoutRead(BaseModel):
    page_name: str
    layout_json: Dict[str, Any]