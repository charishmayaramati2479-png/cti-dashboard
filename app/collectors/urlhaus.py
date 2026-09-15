import requests
from ..config import URLHAUS_AUTH_KEY
from ..normalizer import normalize_urlhaus

URLHAUS_RECENT = "https://urlhaus-api.abuse.ch/v1/urls/recent/"


def fetch_urlhaus_recent(limit=100):
    if not URLHAUS_AUTH_KEY:
        print("[urlhaus] skipped: no auth key")
        return []

    try:
        resp = requests.get(
            URLHAUS_RECENT,
            headers={"Auth-Key": URLHAUS_AUTH_KEY},
            timeout=30
        )
    except requests.RequestException as e:
        print(f"[urlhaus] network error: {e}")
        return []

    if resp.status_code == 401:
        print("[urlhaus] skipped: missing auth key")
        return []
    if resp.status_code == 403:
        print("[urlhaus] skipped: invalid auth key")
        return []
    if resp.status_code == 429:
        print("[urlhaus] skipped: rate limit hit")
        return []
    if resp.status_code != 200:
        print(f"[urlhaus] skipped: HTTP {resp.status_code}")
        return []

    return [normalize_urlhaus(u) for u in resp.json().get("urls", [])[:limit]]