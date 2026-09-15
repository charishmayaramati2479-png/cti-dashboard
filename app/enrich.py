import requests
from time import sleep
import re

GEO_API = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,as"

_IP_PORT_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):\d+$")


def _strip_port(value):
    """Return bare IP if value is ip:port, else the value unchanged."""
    if not value:
        return value
    m = _IP_PORT_RE.match(value.strip())
    return m.group(1) if m else value.strip()


def enrich_ip(ip, timeout=5):
    try:
        r = requests.get(GEO_API.format(ip=ip), timeout=timeout)
    except Exception:
        return {}

    if r.status_code != 200:
        return {}

    try:
        data = r.json()
    except Exception:
        return {}

    if data.get("status") != "success":
        return {}

    return {
        "country": data.get("country"),
        "city": data.get("city"),
        "asn": (data.get("as") or "")[:120]
    }


def enrich_ip_iocs(db, IOC, batch=40, pause=1.5):
    """
    Enrich IP IOCs that don't yet have a country.
    Strips ':port' before lookup so ip-api accepts the address.
    """
    targets = (
        db.query(IOC)
        .filter(IOC.ioc_type == "ip", IOC.country.is_(None))
        .limit(300)
        .all()
    )
    if not targets:
        print("[enrich] nothing to enrich")
        return 0

    print(f"[enrich] attempting {len(targets)} IPs...")
    count = 0
    for i, ioc in enumerate(targets):
        bare_ip = _strip_port(ioc.value)
        geo = enrich_ip(bare_ip)
        if geo:
            ioc.country = geo.get("country")
            ioc.city = geo.get("city")
            ioc.asn = geo.get("asn")
            count += 1
        if (i + 1) % batch == 0:
            db.commit()
            sleep(pause)
    db.commit()
    print(f"[enrich] enriched {count}/{len(targets)} IP IOCs")
    return count