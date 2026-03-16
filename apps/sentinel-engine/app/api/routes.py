from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

router = APIRouter()

@router.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "sentinel-engine"}

@router.get("/metrics")
def metrics() -> PlainTextResponse:
    return PlainTextResponse(generate_latest(), media_type=CONTENT_TYPE_LATEST)

@router.get("/api/alerts")
def alerts(request: Request) -> dict:
    service = request.app.state.service
    return {"items": list(service.alerts)[:100]}

@router.get("/api/incidents")
def incidents(request: Request) -> dict:
    service = request.app.state.service
    return {"items": service.correlator.list_incidents()}

@router.get("/api/stats")
def stats(request: Request) -> dict:
    service = request.app.state.service
    return service.stats()