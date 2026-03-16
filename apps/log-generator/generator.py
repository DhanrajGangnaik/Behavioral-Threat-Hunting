import os
import random
import time
import requests

TARGET_URL = os.getenv("TARGET_URL", "http://demo-webapp")
INTERVAL_SEC = float(os.getenv("INTERVAL_SEC", "1.0"))

NORMAL_PATHS = [
    "/",
    "/login",
    "/search?q=shoes",
    "/search?q=laptop",
    "/api",
]

ATTACK_PATHS = [
    "/search?q=' OR 1=1 --",
    "/search?q=<script>alert(1)</script>",
    "/../../../../etc/passwd",
    "/admin?cmd=cat+/etc/passwd",
    "/wp-login.php",
    "/phpmyadmin",
    "/.env",
]

USER_AGENTS = [
    "Mozilla/5.0",
    "curl/8.0.1",
    "sqlmap/1.7.10",
    "python-requests/2.32.0",
    "Nikto/2.5.0",
]

def hit(path: str) -> None:
    url = f"{TARGET_URL}{path}"
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    try:
        response = requests.get(url, headers=headers, timeout=3)
        print(f"[GENERATOR] {response.status_code} {url}")
    except Exception as exc:
        print(f"[GENERATOR] request failed for {url}: {exc}")

def main() -> None:
    print(f"[GENERATOR] starting traffic against {TARGET_URL}")
    while True:
        pool = ATTACK_PATHS if random.random() < 0.45 else NORMAL_PATHS
        hit(random.choice(pool))
        time.sleep(INTERVAL_SEC)

if __name__ == "__main__":
    main()