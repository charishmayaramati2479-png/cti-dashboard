import requests
from datetime import datetime, timedelta
from ..normalizer import normalize_nvd

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_recent_cves(days=7, limit=100):
    end = datetime.utcnow()
    start = end - timedelta(days=days)
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": limit
    }

    try:
        resp = requests.get(NVD_API, params=params, timeout=60)
    except requests.RequestException as e:
        print(f"[nvd] network error: {e}")
        return []

    if resp.status_code == 403:
        print("[nvd] skipped: rate limited or forbidden")
        return []
    if resp.status_code == 429:
        print("[nvd] skipped: rate limit hit")
        return []
    if resp.status_code != 200:
        print(f"[nvd] skipped: HTTP {resp.status_code}")
        return []

    items = resp.json().get("vulnerabilities", [])
    return [normalize_nvd(i["cve"]) for i in items if "cve" in i]