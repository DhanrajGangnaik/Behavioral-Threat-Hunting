from prometheus_client import Counter, Gauge, Histogram

LINES_PROCESSED = Counter(
    "sentinel_lines_processed_total",
    "Total log lines processed by sentinel",
)

PARSE_ERRORS = Counter(
    "sentinel_parse_errors_total",
    "Total log parse errors",
)

ALERTS_TOTAL = Counter(
    "sentinel_alerts_total",
    "Total alerts detected by category and severity",
    ["category", "severity"],
)

ALERTS_BY_SOURCE_IP = Counter(
    "sentinel_alerts_by_source_ip_total",
    "Total alerts grouped by source IP",
    ["source_ip"],
)

ALERTS_BY_PATH = Counter(
    "sentinel_alerts_by_path_total",
    "Total alerts grouped by targeted path",
    ["path"],
)

PROCESSING_LATENCY = Histogram(
    "sentinel_processing_latency_seconds",
    "Latency to process a log event",
)

ACTIVE_INCIDENTS = Gauge(
    "sentinel_active_incidents",
    "Current number of active incidents",
)