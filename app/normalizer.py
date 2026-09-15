from datetime import datetime
import json


_TYPE_MAP = {
    "ip:port": "ip",
    "md5_hash": "hash",
    "sha1_hash": "hash",
    "sha256_hash": "hash",
    "sha256": "hash",
    "md5": "hash",
    "sha1": "hash",
    "domain": "domain",
    "hostname": "domain",
    "url": "url",
    "uri": "url",
    "cve": "cve",
    "ipv4": "ip",
    "ipv6": "ip",
}


def _clean_type(t):
    if not t:
        return "unknown"
    return _TYPE_MAP.get(t.lower(), t.lower())


def _base(ioc_type, value, source, threat_type=None, malware_family=None,
          confidence=50, cvss_score=0.0, tags=None, raw=None):
    return {
        "ioc_type": _clean_type(ioc_type),
        "value": value,
        "source": source,
        "threat_type": threat_type,
        "malware_family": malware_family,
        "confidence": confidence,
        "cvss_score": cvss_score,
        "first_seen": datetime.utcnow(),
        "last_seen": datetime.utcnow(),
        "tags": json.dumps(tags or []),
        "raw": json.dumps(raw or {})
    }


def normalize_urlhaus(entry):
    tags = entry.get("tags") or []
    return _base(
        ioc_type="url",
        value=entry.get("url"),
        source="urlhaus",
        threat_type=entry.get("threat"),
        malware_family=tags[0] if tags else None,
        confidence=70,
        tags=tags,
        raw=entry
    )


def normalize_threatfox(entry):
    return _base(
        ioc_type=entry.get("ioc_type", "unknown"),
        value=entry.get("ioc"),
        source="threatfox",
        threat_type=entry.get("threat_type"),
        malware_family=entry.get("malware_printable"),
        confidence=int(entry.get("confidence_level") or 50),
        tags=entry.get("tags") or [],
        raw=entry
    )


def normalize_otx(entry):
    return _base(
        ioc_type=entry.get("type", "unknown"),
        value=entry.get("indicator"),
        source="otx",
        threat_type="pulse",
        malware_family=entry.get("malware_family"),
        confidence=60,
        tags=entry.get("tags") or [],
        raw=entry
    )


def normalize_nvd(cve):
    metrics = cve.get("metrics", {})
    cvss = 0.0
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            cvss = metrics[key][0]["cvssData"]["baseScore"]
            break
    descriptions = [d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"]
    return _base(
        ioc_type="cve",
        value=cve.get("id"),
        source="nvd",
        threat_type="vulnerability",
        confidence=90,
        cvss_score=cvss,
        tags=descriptions[:1],
        raw=cve
    )