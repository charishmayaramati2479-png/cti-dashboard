import requests
from ..config import OTX_API_KEY
from ..normalizer import normalize_otx

OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"


def fetch_otx_recent(limit=100):
    if not OTX_API_KEY:
        print("[otx] skipped: no api key")
        return []

    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    params = {"limit": 10}

    try:
        resp = requests.get(OTX_URL, headers=headers, params=params, timeout=30)
    except requests.RequestException as e:
        print(f"[otx] network error: {e}")
        return []

    if resp.status_code in (401, 403):
        print("[otx] skipped: invalid or expired API key")
        return []
    if resp.status_code == 429:
        print("[otx] skipped: rate limit hit")
        return []
    if resp.status_code != 200:
        print(f"[otx] skipped: HTTP {resp.status_code}")
        return []

    out = []
    for pulse in resp.json().get("results", []):
        for ind in pulse.get("indicators", []):
            out.append(normalize_otx({
                "indicator": ind.get("indicator"),
                "type": ind.get("type"),
                "malware_family": (
                    pulse.get("malware_families", [{}])[0].get("display_name")
                    if pulse.get("malware_families") else None
                ),
                "tags": pulse.get("tags", [])
            }))
            if len(out) >= limit:
                return out
    return out