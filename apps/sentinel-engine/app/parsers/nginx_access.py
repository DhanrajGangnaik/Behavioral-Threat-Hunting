import re
from typing import Optional, Dict

LOG_RE = re.compile(
    r'(?P<remote_addr>\S+) - (?P<remote_user>\S+) '
    r'\[(?P<time_local>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<request>.*?) (?P<protocol>[^"]+)" '
    r'(?P<status>\d{3}) (?P<body_bytes_sent>\d+) '
    r'"(?P<http_referer>[^"]*)" "(?P<http_user_agent>[^"]*)"'
)

def parse_nginx_access_line(line: str) -> Optional[Dict[str, str]]:
    match = LOG_RE.search(line.strip())
    if not match:
        return None

    data = match.groupdict()
    request = data.get("request", "")
    path = request.split("?")[0] if "?" in request else request
    query = request.split("?", 1)[1] if "?" in request else ""

    data["path"] = path
    data["query"] = query
    data["status"] = int(data["status"])
    data["body_bytes_sent"] = int(data["body_bytes_sent"])
    return data