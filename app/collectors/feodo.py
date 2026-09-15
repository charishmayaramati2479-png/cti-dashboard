import requests
from datetime import datetime
import json

FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"


def fetch_feodo_recent(limit=200):
    try:
        resp = requests.get(FEODO_URL, timeout=30)
    except requests.RequestException as e:
        print(f"[feodo] network error: {e}")
        return []

    if resp.status_code != 200:
        print(f"[feodo] skipped: HTTP {resp.status_code}")
        return []

    try:
        data = resp.json()
    except Exception:
        print("[feodo] skipped: invalid json")
        return []

    out = []
    for entry in data[:limit]:
        ip = entry.get("ip_address")
        if not ip:
            continue
        out.append({
            "ioc_type": "ip",
            "value": ip,
            "source": "feodo",
            "threat_type": entry.get("malware") or "botnet_c2",
            "malware_family": entry.get("malware"),
            "confidence": 90,
            "cvss_score": 0.0,
            "first_seen": datetime.utcnow(),
            "last_seen": datetime.utcnow(),
            "tags": json.dumps([entry.get("status", "")]),
            "raw": json.dumps(entry)
        })
    return out