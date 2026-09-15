from .db import SessionLocal, init_db, IOC
from .collectors.urlhaus import fetch_urlhaus_recent
from .collectors.threatfox import fetch_threatfox_recent
from .collectors.nvd import fetch_recent_cves
from .collectors.otx import fetch_otx_recent
from .collectors.malwarebazaar import fetch_malwarebazaar_recent
from .collectors.feodo import fetch_feodo_recent
from .scoring import score_all, detect_anomalies
from .alerts import generate_alerts
from .enrich import enrich_ip_iocs
from .ml import train_and_score

def save_iocs(iocs):
    db = SessionLocal()
    count = 0
    for ioc in iocs:
        exists = (
            db.query(IOC)
            .filter(IOC.value == ioc["value"], IOC.source == ioc["source"])
            .first()
        )
        if not exists and ioc.get("value"):
            db.add(IOC(**ioc))
            count += 1
    db.commit()
    db.close()
    return count


def collect_all():
    init_db()

    all_iocs = []
    print("Collecting from feeds...")
    all_iocs += fetch_urlhaus_recent(100)
    all_iocs += fetch_threatfox_recent(days=1)
    all_iocs += fetch_recent_cves(days=7, limit=100)
    all_iocs += fetch_otx_recent(limit=100)
    all_iocs += fetch_malwarebazaar_recent(limit=100)
    all_iocs += fetch_feodo_recent(limit=200)

    saved = save_iocs(all_iocs)
    print(f"Fetched {len(all_iocs)} IOCs, saved {saved} new.")

    db = SessionLocal()
    enrich_ip_iocs(db, IOC)
    scored = score_all(db, IOC)
    anomalous = detect_anomalies(db, IOC)
    ml_metrics = train_and_score(db, IOC)
    alerts = generate_alerts(db)
    db.close()

    print(f"Scored {scored} IOCs. "
          f"Flagged {anomalous} as anomalies. "
          f"Created {alerts} alerts.")


if __name__ == "__main__":
    collect_all()