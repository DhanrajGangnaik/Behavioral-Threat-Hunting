import os
import threading
import time
from collections import deque
from typing import Dict, List

from fastapi import FastAPI

from app.api.routes import router
from app.correlators.incidents import IncidentCorrelator
from app.detectors.patterns import PatternDetector
from app.metrics.registry import (
    ACTIVE_INCIDENTS,
    ALERTS_TOTAL,
    ALERTS_BY_PATH,
    ALERTS_BY_SOURCE_IP,
    LINES_PROCESSED,
    PARSE_ERRORS,
    PROCESSING_LATENCY,
)
from app.parsers.nginx_access import parse_nginx_access_line

LOG_FILE = os.getenv("LOG_FILE", "/var/log/nginx/access.log")

class SentinelService:
    def __init__(self) -> None:
        self.detector = PatternDetector("/app/rules")
        self.correlator = IncidentCorrelator()
        self.alerts: deque = deque(maxlen=500)
        self.total_lines = 0
        self.total_alerts = 0
        self.running = True

    def stats(self) -> Dict:
        incidents = self.correlator.list_incidents()
        return {
            "total_lines": self.total_lines,
            "total_alerts": self.total_alerts,
            "active_incidents": len(incidents),
            "top_incidents": incidents[:10],
        }

    def process_line(self, line: str) -> None:
        start = time.perf_counter()
        event = parse_nginx_access_line(line)
        if not event:
            PARSE_ERRORS.inc()
            return

        self.total_lines += 1
        LINES_PROCESSED.inc()

        detections = self.detector.detect(event)
        if detections:
            for detection in detections:
                alert = {
                    "source_ip": event["remote_addr"],
                    "path": event["path"],
                    "query": event["query"],
                    "user_agent": event.get("http_user_agent", ""),
                    "category": detection["category"],
                    "pattern": detection["pattern"],
                    "severity": detection["severity"],
                    "status": event["status"],
                    "time_local": event["time_local"],
                }
                self.alerts.appendleft(alert)
                self.total_alerts += 1

                ALERTS_TOTAL.labels(
                    category=detection["category"],
                    severity=detection["severity"],
                ).inc()

                ALERTS_BY_SOURCE_IP.labels(
                    source_ip=event["remote_addr"]
                ).inc()

                ALERTS_BY_PATH.labels(
                    path=event["path"]
                ).inc()

            self.correlator.ingest_alerts(event, detections)
            ACTIVE_INCIDENTS.set(len(self.correlator.list_incidents()))

        PROCESSING_LATENCY.observe(time.perf_counter() - start)

    def tail_loop(self) -> None:
        while self.running:
            try:
                if not os.path.exists(LOG_FILE):
                    time.sleep(2)
                    continue

                with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as handle:
                    handle.seek(0, os.SEEK_END)
                    while self.running:
                        line = handle.readline()
                        if not line:
                            time.sleep(0.5)
                            continue
                        self.process_line(line)
            except Exception as exc:
                print(f"[sentinel] tail loop error: {exc}")
                time.sleep(2)

app = FastAPI(title="Sentinel Engine", version="2.0.0")
service = SentinelService()
app.state.service = service
app.include_router(router)

@app.on_event("startup")
def startup_event() -> None:
    thread = threading.Thread(target=service.tail_loop, daemon=True)
    thread.start()