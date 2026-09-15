from .db import IOC, Alert

RULES = [
    {
        "name": "high_risk_score",
        "fn": lambda i: (i.risk_score or 0) >= 75,
        "severity": "high",
        "msg": lambda i: f"High risk score {i.risk_score} on {i.ioc_type} {i.value} ({i.source})"
    },
    {
        "name": "critical_cve",
        "fn": lambda i: i.ioc_type == "cve" and (i.cvss_score or 0) >= 9.0,
        "severity": "critical",
        "msg": lambda i: f"Critical CVE {i.value} (CVSS {i.cvss_score})"
    },
    {
        "name": "anomaly_high_risk",
        "fn": lambda i: bool(i.anomaly) and (i.risk_score or 0) >= 70,
        "severity": "high",
        "msg": lambda i: f"Anomaly + high risk on {i.ioc_type} {i.value} ({i.source})"
    },
    {
        "name": "botnet_c2",
        "fn": lambda i: i.ioc_type == "ip" and i.source == "feodo",
        "severity": "critical",
        "msg": lambda i: f"Botnet C2 IP detected: {i.value} ({i.malware_family or 'unknown'})"
    },
]


def generate_alerts(db, iocs=None):
    """Create alerts for IOCs matching any rule. Deduplicates by (rule, ioc_id)."""
    if iocs is None:
        iocs = db.query(IOC).all()

    existing = {(a.rule, a.ioc_id) for a in db.query(Alert).all()}
    created = 0

    for ioc in iocs:
        for rule in RULES:
            try:
                if not rule["fn"](ioc):
                    continue
            except Exception:
                continue
            key = (rule["name"], ioc.id)
            if key in existing:
                continue
            db.add(Alert(
                rule=rule["name"],
                severity=rule["severity"],
                message=rule["msg"](ioc),
                ioc_id=ioc.id
            ))
            existing.add(key)
            created += 1

    db.commit()
    return created