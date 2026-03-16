from pathlib import Path
from typing import Dict, List

RULE_FILES = {
    "sqli": "sqli_patterns.txt",
    "xss": "xss_patterns.txt",
    "traversal": "traversal_patterns.txt",
    "scanner": "scanner_patterns.txt",
    "cmdi": "cmdi_patterns.txt",
}

class PatternDetector:
    def __init__(self, rules_dir: str = "/app/rules") -> None:
        self.rules_dir = Path(rules_dir)
        self.rules: Dict[str, List[str]] = self._load_rules()

    def _load_rules(self) -> Dict[str, List[str]]:
        loaded: Dict[str, List[str]] = {}
        for rule_type, file_name in RULE_FILES.items():
            path = self.rules_dir / file_name
            if path.exists():
                loaded[rule_type] = [
                    line.strip().lower()
                    for line in path.read_text(encoding="utf-8").splitlines()
                    if line.strip() and not line.strip().startswith("#")
                ]
            else:
                loaded[rule_type] = []
        return loaded

    def detect(self, event: Dict) -> List[Dict]:
        hits: List[Dict] = []
        haystack = " ".join(
            [
                str(event.get("request", "")),
                str(event.get("query", "")),
                str(event.get("path", "")),
                str(event.get("http_user_agent", "")),
            ]
        ).lower()

        for category, patterns in self.rules.items():
            for pattern in patterns:
                if pattern in haystack:
                    hits.append(
                        {
                            "category": category,
                            "pattern": pattern,
                            "severity": self._severity_for(category),
                        }
                    )

        if event.get("status") == 404:
            hits.append(
                {
                    "category": "suspicious_404",
                    "pattern": "404-hit",
                    "severity": "low",
                }
            )

        return hits

    @staticmethod
    def _severity_for(category: str) -> str:
        if category in {"sqli", "cmdi"}:
            return "high"
        if category in {"xss", "traversal", "scanner"}:
            return "medium"
        return "low"