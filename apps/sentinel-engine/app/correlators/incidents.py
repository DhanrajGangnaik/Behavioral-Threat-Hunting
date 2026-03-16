from collections import defaultdict
from typing import Dict, List, Tuple

class IncidentCorrelator:
    def __init__(self) -> None:
        self._incidents: Dict[Tuple[str, str, str], Dict] = {}

    def ingest_alerts(self, event: Dict, detections: List[Dict]) -> None:
        source_ip = event.get("remote_addr", "unknown")
        path = event.get("path", "unknown")

        for detection in detections:
            key = (source_ip, detection["category"], path)
            current = self._incidents.get(key)
            if not current:
                self._incidents[key] = {
                    "source_ip": source_ip,
                    "category": detection["category"],
                    "path": path,
                    "severity": detection["severity"],
                    "count": 1,
                    "latest_pattern": detection["pattern"],
                }
            else:
                current["count"] += 1
                current["latest_pattern"] = detection["pattern"]

    def list_incidents(self) -> List[Dict]:
        return sorted(
            self._incidents.values(),
            key=lambda item: (item["severity"], item["count"]),
            reverse=True,
        )