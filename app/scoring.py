from sklearn.ensemble import IsolationForest
import numpy as np


HIGH_RISK_COUNTRIES = {"Russia", "China", "Iran", "North Korea", "Belarus"}


def compute_risk_score(ioc, all_iocs):
    """Risk score 0-100 from weighted signals."""
    score = 0.0

    # Confidence (30%)
    score += min(ioc.confidence or 50, 100) * 0.3

    # CVSS (40%)
    score += min((ioc.cvss_score or 0) * 10, 100) * 0.4

    # Known malware family
    if ioc.malware_family:
        score += 15

    # High-value IOC types
    if ioc.ioc_type in ("hash", "ip", "domain"):
        score += 10

    # Trusted sources
    if ioc.source in ("threatfox", "urlhaus", "nvd", "malwarebazaar", "feodo"):
        score += 5

    # Source rarity boost — rare sources are more interesting
    same_source = sum(1 for x in all_iocs if x.source == ioc.source)
    if same_source and len(all_iocs) / same_source > 3:
        score += 5

    # GeoIP boost for high-risk origins
    if getattr(ioc, "country", None) in HIGH_RISK_COUNTRIES:
        score += 5

    return round(min(score, 100.0), 2)


def score_all(db, IOC):
    iocs = db.query(IOC).all()
    if not iocs:
        return 0
    for ioc in iocs:
        ioc.risk_score = compute_risk_score(ioc, iocs)
    db.commit()
    return len(iocs)


def detect_anomalies(db, IOC, contamination=0.1):
    iocs = db.query(IOC).all()
    if len(iocs) < 10:
        return 0

    X = np.array([
        [i.confidence or 0, i.cvss_score or 0, i.risk_score or 0]
        for i in iocs
    ])
    model = IsolationForest(contamination=contamination, random_state=42)
    preds = model.fit_predict(X)

    count = 0
    for ioc, p in zip(iocs, preds):
        ioc.anomaly = bool(p == -1)
        if ioc.anomaly:
            count += 1
    db.commit()
    return count