import requests
from ..config import THREATFOX_AUTH_KEY
from ..normalizer import normalize_threatfox

THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"


def fetch_threatfox_recent(days=1):
    if not THREATFOX_AUTH_KEY:
        print("[threatfox] skipped: no auth key")
        return []

    payload = {"query": "get_iocs", "days": days}

    try:
        resp = requests.post(
            THREATFOX_API,
            json=payload,
            headers={"Auth-Key": THREATFOX_AUTH_KEY},
            timeout=30
        )
    except requests.RequestException as e:
        print(f"[threatfox] network error: {e}")
        return []

    if resp.status_code == 401:
        print("[threatfox] skipped: missing auth key")
        return []
    if resp.status_code == 403:
        print("[threatfox] skipped: invalid auth key")
        return []
    if resp.status_code == 429:
        print("[threatfox] skipped: rate limit hit")
        return []
    if resp.status_code != 200:
        print(f"[threatfox] skipped: HTTP {resp.status_code}")
        return []

    data = resp.json()
    if data.get("query_status") != "ok":
        print(f"[threatfox] query_status={data.get('query_status')}")
        return []

    return [normalize_threatfox(i) for i in data.get("data", [])]