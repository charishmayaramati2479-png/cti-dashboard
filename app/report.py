import io
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)


def _styles():
    s = getSampleStyleSheet()
    s.add(ParagraphStyle(
        name="TitleBig", parent=s["Title"], fontSize=22, spaceAfter=6
    ))
    s.add(ParagraphStyle(
        name="Sub", parent=s["Normal"], fontSize=11,
        textColor=colors.grey, spaceAfter=18
    ))
    s.add(ParagraphStyle(
        name="Section", parent=s["Heading2"], fontSize=14,
        spaceBefore=12, spaceAfter=6, textColor=colors.HexColor("#0d47a1")
    ))
    return s


def _table(data, col_widths=None):
    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0d47a1")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#f5f5f5")])
    ]))
    return t


def build_pdf(stats, top_iocs, top_alerts, ml_metrics=None):
    """
    Returns PDF bytes.
      stats      : dict from /stats
      top_iocs   : list of dicts {value, ioc_type, source, risk_score, country, malware_family}
      top_alerts : list of dicts {rule, severity, message, created_at}
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=2 * cm, bottomMargin=2 * cm
    )
    s = _styles()
    story = []

    # ---- Cover ----
    story.append(Paragraph("Cyber Threat Intelligence Report", s["TitleBig"]))
    story.append(Paragraph(
        f"Generated {datetime.utcnow():%Y-%m-%d %H:%M UTC} · CTI Dashboard",
        s["Sub"]
    ))

    # ---- Executive summary ----
    story.append(Paragraph("Executive Summary", s["Section"]))
    story.append(Paragraph(
        f"The pipeline aggregated <b>{stats.get('total_iocs', 0)}</b> "
        f"indicators of compromise across "
        f"<b>{len(stats.get('by_source', {}))}</b> open-source feeds. "
        f"<b>{stats.get('high_risk', 0)}</b> IOCs scored at high risk "
        f"(≥80), and <b>{stats.get('anomalies', 0)}</b> were flagged as "
        f"anomalous by the IsolationForest model. "
        f"<b>{stats.get('alerts', 0)}</b> alerts were generated.",
        s["Normal"]
    ))

    # ---- Source distribution ----
    if stats.get("by_source"):
        story.append(Paragraph("Source Distribution", s["Section"]))
        data = [["Source", "Count"]]
        for k, v in stats["by_source"].items():
            data.append([k, str(v)])
        story.append(_table(data, col_widths=[8 * cm, 4 * cm]))
        story.append(Spacer(1, 8))

    # ---- IOC type distribution ----
    if stats.get("by_type"):
        story.append(Paragraph("IOC Type Distribution", s["Section"]))
        data = [["Type", "Count"]]
        for k, v in stats["by_type"].items():
            data.append([k, str(v)])
        story.append(_table(data, col_widths=[8 * cm, 4 * cm]))

    story.append(PageBreak())

    # ---- Top IOCs ----
    story.append(Paragraph("Top-Risk IOCs", s["Section"]))
    data = [["Value", "Type", "Source", "Risk", "Country", "Malware"]]
    for i in top_iocs[:25]:
        data.append([
            (i.get("value") or "")[:40],
            i.get("ioc_type", ""),
            i.get("source", ""),
            str(i.get("risk_score", "")),
            (i.get("country") or "-")[:14],
            (i.get("malware_family") or "-")[:18]
        ])
    story.append(_table(data, col_widths=[
        6.5 * cm, 2 * cm, 2.4 * cm, 1.4 * cm, 2.5 * cm, 3 * cm
    ]))
    story.append(Spacer(1, 12))

    # ---- Alerts ----
    story.append(Paragraph("Recent Alerts", s["Section"]))
    data = [["Severity", "Rule", "Message"]]
    for a in top_alerts[:20]:
        data.append([
            a.get("severity", ""),
            a.get("rule", ""),
            (a.get("message") or "")[:70]
        ])
    story.append(_table(data, col_widths=[2.2 * cm, 4 * cm, 11 * cm]))

    # ---- ML metrics ----
    if ml_metrics and "accuracy" in ml_metrics:
        story.append(Spacer(1, 12))
        story.append(Paragraph("Machine Learning Metrics", s["Section"]))
        story.append(Paragraph(
            f"Supervised model target: <b>{ml_metrics.get('label', 'n/a')}</b>. "
            f"Trained on {ml_metrics.get('samples_train', '?')} samples, "
            f"tested on {ml_metrics.get('samples_test', '?')}.",
            s["Normal"]
        ))
        data = [["Metric", "Value"]]
        for key in ("baseline_accuracy", "accuracy", "precision",
                    "recall", "f1", "roc_auc"):
            if key in ml_metrics:
                data.append([key, str(ml_metrics[key])])
        story.append(_table(data, col_widths=[6 * cm, 4 * cm]))

    # ---- Footer note ----
    story.append(Spacer(1, 20))
    story.append(Paragraph(
        "This report is generated automatically by the CTI Dashboard. "
        "Indicators originate from open-source threat intelligence feeds "
        "and should be verified before operational use.",
        s["Sub"]
    ))

    doc.build(story)
    return buf.getvalue()