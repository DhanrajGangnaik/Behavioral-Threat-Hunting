from sqlalchemy.orm import Session
from app.models.dashboard import DashboardRegistry, PageLayout

def create_dashboard(db: Session, payload):
    item = DashboardRegistry(**payload.model_dump())
    db.add(item)
    db.commit()
    db.refresh(item)
    return item

def list_dashboards(db: Session):
    return db.query(DashboardRegistry).order_by(DashboardRegistry.id.desc()).all()

def delete_dashboard(db: Session, dashboard_id: int) -> bool:
    item = db.query(DashboardRegistry).filter(DashboardRegistry.id == dashboard_id).first()
    if not item:
        return False
    db.delete(item)
    db.commit()
    return True

def upsert_layout(db: Session, page_name: str, layout_json: str):
    item = db.query(PageLayout).filter(PageLayout.page_name == page_name).first()
    if not item:
        item = PageLayout(page_name=page_name, layout_json=layout_json)
        db.add(item)
    else:
        item.layout_json = layout_json
    db.commit()
    db.refresh(item)
    return item

def get_layout(db: Session, page_name: str):
    return db.query(PageLayout).filter(PageLayout.page_name == page_name).first()