import json

from fastapi import FastAPI, Query
from sqlalchemy import func
from typing import Optional
from .db import SessionLocal, init_db, IOC, Alert
from .correlation import build_correlation_graph
from datetime import datetime

app = FastAPI(title="CTI Dashboard API", version="0.1.0")


@app.on_event("startup")
def _startup():
    init_db()


@app.get("/")
def root():
    return {"status": "ok", "service": "cti-dashboard"}


@app.get("/stats")
def stats():
    db = SessionLocal()
    try:
        total = db.query(IOC).count()
        by_source = dict(db.query(IOC.source, func.count(IOC.id)).group_by(IOC.source).all())
        by_type = dict(db.query(IOC.ioc_type, func.count(IOC.id)).group_by(IOC.ioc_type).all())
        anomalies = db.query(IOC).filter(IOC.anomaly == True).count()
        alerts = db.query(Alert).count()
        high_risk = db.query(IOC).filter(IOC.risk_score >= 80).count()
        return {
            "total_iocs": total,
            "by_source": by_source,
            "by_type": by_type,
            "anomalies": anomalies,
            "high_risk": high_risk,
            "alerts": alerts
        }
    finally:
        db.close()


@app.get("/iocs")
def list_iocs(
    source: Optional[str] = None,
    ioc_type: Optional[str] = None,
    min_risk: float = Query(0.0),
    anomaly: Optional[bool] = None,
    limit: int = Query(50, le=500),
    offset: int = 0
):
    db = SessionLocal()
    try:
        q = db.query(IOC)
        if source:
            q = q.filter(IOC.source == source)
        if ioc_type:
            q = q.filter(IOC.ioc_type == ioc_type)
        if min_risk > 0:
            q = q.filter(IOC.risk_score >= min_risk)
        if anomaly is not None:
            q = q.filter(IOC.anomaly == anomaly)
        total = q.count()
        rows = q.order_by(IOC.risk_score.desc()).offset(offset).limit(limit).all()
        return {
            "total": total,
            "items": [{
                "id": i.id, "value": i.value, "ioc_type": i.ioc_type,
                "source": i.source, "threat_type": i.threat_type,
                "malware_family": i.malware_family,
                "confidence": i.confidence, "cvss_score": i.cvss_score,
                "risk_score": i.risk_score, "anomaly": bool(i.anomaly),
                "first_seen": i.first_seen.isoformat() if i.first_seen else None
            } for i in rows]
        }
    finally:
        db.close()


@app.get("/iocs/{ioc_id}")
def get_ioc(ioc_id: int):
    db = SessionLocal()
    try:
        i = db.query(IOC).filter(IOC.id == ioc_id).first()
        if not i:
            return {"error": "not found"}
        return {
            "id": i.id, "value": i.value, "ioc_type": i.ioc_type,
            "source": i.source, "threat_type": i.threat_type,
            "malware_family": i.malware_family,
            "confidence": i.confidence, "cvss_score": i.cvss_score,
            "risk_score": i.risk_score, "anomaly": bool(i.anomaly),
            "tags": i.tags, "raw": i.raw
        }
    finally:
        db.close()


@app.get("/search")
def search(q: str, limit: int = 20):
    db = SessionLocal()
    try:
        rows = db.query(IOC).filter(IOC.value.ilike(f"%{q}%")).limit(limit).all()
        return {"query": q, "count": len(rows),
                "items": [{"id": i.id, "value": i.value, "source": i.source,
                           "risk_score": i.risk_score} for i in rows]}
    finally:
        db.close()


@app.get("/alerts")
def list_alerts(severity: Optional[str] = None, limit: int = 100):
    db = SessionLocal()
    try:
        q = db.query(Alert)
        if severity:
            q = q.filter(Alert.severity == severity)
        rows = q.order_by(Alert.created_at.desc()).limit(limit).all()
        return {"total": q.count(), "items": [{
            "id": a.id, "rule": a.rule, "severity": a.severity,
            "message": a.message, "ioc_id": a.ioc_id,
            "created_at": a.created_at.isoformat() if a.created_at else None
        } for a in rows]}
    finally:
        db.close()


@app.get("/graph")
def graph(limit: int = 300):
    db = SessionLocal()
    try:
        iocs = db.query(IOC).order_by(IOC.risk_score.desc()).limit(limit).all()
        return build_correlation_graph(iocs, max_nodes=limit)
    finally:
        db.close()

from .ml import load_metrics


@app.get("/ml/metrics")
def ml_metrics():
    m = load_metrics()
    if not m:
        return {"error": "model not trained yet"}
    return m


@app.get("/iocs/{ioc_id}/predict")
def predict_ioc(ioc_id: int):
    db = SessionLocal()
    try:
        i = db.query(IOC).filter(IOC.id == ioc_id).first()
        if not i:
            return {"error": "not found"}
        return {
            "id": i.id,
            "value": i.value,
            "risk_score": i.risk_score,
            "anomaly": bool(i.anomaly),
            "ml_probability": i.ml_probability
        }
    finally:
        db.close()
from fastapi.responses import JSONResponse, StreamingResponse
from .export import build_stix_bundle


@app.get("/export/stix")
def export_stix(limit: int = 500):
    """Export top-risk IOCs as a STIX 2.1 bundle."""
    db = SessionLocal()
    try:
        iocs = (
            db.query(IOC)
            .order_by(IOC.risk_score.desc())
            .limit(limit)
            .all()
        )
        bundle, counts = build_stix_bundle(iocs)
        return JSONResponse(content={"counts": counts, "bundle": bundle})
    finally:
        db.close()


@app.get("/export/stix/download")
def export_stix_download(limit: int = 500):
    """Download STIX 2.1 bundle as a .json file."""
    db = SessionLocal()
    try:
        iocs = (
            db.query(IOC)
            .order_by(IOC.risk_score.desc())
            .limit(limit)
            .all()
        )
        bundle, _ = build_stix_bundle(iocs)
        payload = json.dumps(bundle, indent=2)
        return StreamingResponse(
            iter([payload]),
            media_type="application/json",
            headers={
                "Content-Disposition":
                    f"attachment; filename=cti_bundle_{datetime.utcnow():%Y%m%d}.json"
            }
        )
    finally:
        db.close()

from fastapi.responses import Response
from .report import build_pdf
from .ml import load_metrics


@app.get("/report")
def report():
    """Download a PDF threat intelligence report."""
    db = SessionLocal()
    try:
        total = db.query(IOC).count()
        by_source = dict(db.query(IOC.source, func.count(IOC.id)).group_by(IOC.source).all())
        by_type = dict(db.query(IOC.ioc_type, func.count(IOC.id)).group_by(IOC.ioc_type).all())
        anomalies = db.query(IOC).filter(IOC.anomaly == True).count()
        high_risk = db.query(IOC).filter(IOC.risk_score >= 70).count()
        alert_count = db.query(Alert).count()

        stats = {
            "total_iocs": total,
            "by_source": by_source,
            "by_type": by_type,
            "anomalies": anomalies,
            "high_risk": high_risk,
            "alerts": alert_count
        }

        top_iocs_rows = (
            db.query(IOC).order_by(IOC.risk_score.desc()).limit(30).all()
        )
        top_iocs = [{
            "value": i.value,
            "ioc_type": i.ioc_type,
            "source": i.source,
            "risk_score": i.risk_score,
            "country": i.country,
            "malware_family": i.malware_family
        } for i in top_iocs_rows]

        alert_rows = (
            db.query(Alert).order_by(Alert.created_at.desc()).limit(25).all()
        )
        top_alerts = [{
            "severity": a.severity,
            "rule": a.rule,
            "message": a.message,
            "created_at": a.created_at.isoformat() if a.created_at else None
        } for a in alert_rows]

        pdf_bytes = build_pdf(stats, top_iocs, top_alerts, load_metrics())
        filename = f"cti_report_{datetime.utcnow():%Y%m%d}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )
    finally:
        db.close()

@app.get("/geo")
def geo_summary():
    """Aggregate IP IOCs by country for the world map."""
    db = SessionLocal()
    try:
        rows = (
            db.query(IOC.country, func.count(IOC.id))
            .filter(IOC.country.isnot(None), IOC.country != "")
            .group_by(IOC.country)
            .order_by(func.count(IOC.id).desc())
            .all()
        )
        return {"items": [{"country": c, "count": n} for c, n in rows]}
    finally:
        db.close()


@app.get("/timeline")
def timeline(days: int = 14):
    """Daily count of IOCs added, for the timeline chart."""
    db = SessionLocal()
    try:
        rows = db.query(IOC.first_seen).all()
        from collections import Counter
        counter = Counter()
        for (ts,) in rows:
            if ts:
                counter[ts.strftime("%Y-%m-%d")] += 1
        items = [{"date": d, "count": c}
                 for d, c in sorted(counter.items())]
        return {"items": items}
    finally:
        db.close()