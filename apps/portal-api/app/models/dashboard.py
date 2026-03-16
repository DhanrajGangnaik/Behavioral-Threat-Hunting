from sqlalchemy import String, Integer, Boolean, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base

class DashboardRegistry(Base):
    __tablename__ = "dashboard_registry"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    title: Mapped[str] = mapped_column(String(255))
    grafana_uid: Mapped[str] = mapped_column(String(255))
    grafana_panel_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    app_slug: Mapped[str | None] = mapped_column(String(128), nullable=True)
    visibility: Mapped[str] = mapped_column(String(50), default="private")
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)

class PageLayout(Base):
    __tablename__ = "page_layouts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    page_name: Mapped[str] = mapped_column(String(255), unique=True)
    layout_json: Mapped[str] = mapped_column(Text)

class ServiceIntegration(Base):
    __tablename__ = "service_integrations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    service_type: Mapped[str] = mapped_column(String(50), unique=True)
    base_url: Mapped[str] = mapped_column(String(255))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)