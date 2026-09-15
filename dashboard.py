import streamlit as st
import requests
import pandas as pd
import plotly.express as px
from pyvis.network import Network
import os
from datetime import datetime

API = os.getenv("API", "http://127.0.0.1:8000")

st.set_page_config(
    page_title="CTI Dashboard",
    layout="wide",
    page_icon="🛡️",
    initial_sidebar_state="expanded"
)

# ---------- Custom dark theme ----------
st.markdown("""
<style>
    .stApp {
        background: linear-gradient(180deg, #0a0e1a 0%, #101828 100%);
        color: #e6edf3;
    }
    section[data-testid="stSidebar"] {
        background-color: #0d1424;
        border-right: 1px solid #1f2a44;
    }
    .stMetric {
        background-color: #131b2e;
        padding: 12px;
        border-radius: 10px;
        border: 1px solid #1f2a44;
    }
    .stMetric label { color: #8aa0c0 !important; }
    .stMetric [data-testid="stMetricValue"] {
        color: #4da3ff !important;
        font-weight: 700;
    }
    h1, h2, h3 { color: #e6edf3 !important; }
    .stTabs [data-baseweb="tab"] {
        background-color: #131b2e;
        border-radius: 6px;
        margin-right: 4px;
        color: #8aa0c0;
    }
    .stTabs [aria-selected="true"] {
        background-color: #1e3a8a !important;
        color: #ffffff !important;
    }
    .block-container { padding-top: 1.5rem; }
</style>
""", unsafe_allow_html=True)

st.markdown(
    "<h1 style='margin-bottom:0;'>🛡️ Cyber Threat Intelligence Dashboard</h1>"
    "<p style='color:#8aa0c0;margin-top:0;'>Real-time aggregation of open-source "
    "threat feeds · ML-driven scoring · STIX 2.1 export</p>",
    unsafe_allow_html=True
)

# ---------- Sidebar ----------
st.sidebar.header("Filters")
source_filter = st.sidebar.selectbox(
    "Source",
    ["all", "urlhaus", "threatfox", "nvd", "otx", "malwarebazaar", "feodo"]
)
type_filter = st.sidebar.selectbox(
    "IOC Type",
    ["all", "url", "ip", "domain", "hash", "cve"]
)
min_risk = st.sidebar.slider("Minimum Risk Score", 0, 100, 0)
only_anomalies = st.sidebar.checkbox("Only anomalies", value=False)
search_q = st.sidebar.text_input("Search IOC value")

params = {"limit": 500, "min_risk": min_risk}
if source_filter != "all":
    params["source"] = source_filter
if type_filter != "all":
    params["ioc_type"] = type_filter
if only_anomalies:
    params["anomaly"] = "true"

# ---------- Metrics ----------
try:
    stats = requests.get(f"{API}/stats", timeout=10).json()
except Exception as e:
    st.error(f"Cannot reach API: {e}. Is uvicorn running?")
    st.stop()

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Total IOCs", stats.get("total_iocs", 0))
c2.metric("High Risk (≥70)", stats.get("high_risk", 0))
c3.metric("Anomalies", stats.get("anomalies", 0))
c4.metric("Alerts", stats.get("alerts", 0))
c5.metric("Sources", len(stats.get("by_source", {})))

# ---------- Tabs ----------
tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs(
    ["📊 Charts", "🗺️ World Map", "📈 Timeline", "🔎 Explorer",
     "🚨 Alerts", "🕸️ Graph", "📥 Export"]
)

# ---------- Tab 1: Charts ----------
with tab1:
    col1, col2 = st.columns(2)

    with col1:
        if stats.get("by_source"):
            df = pd.DataFrame(list(stats["by_source"].items()),
                              columns=["Source", "Count"])
            st.plotly_chart(
                px.pie(df, names="Source", values="Count",
                       title="IOCs by Source"),
                use_container_width=True
            )

    with col2:
        if stats.get("by_type"):
            df = pd.DataFrame(list(stats["by_type"].items()),
                              columns=["Type", "Count"])
            st.plotly_chart(
                px.bar(df, x="Type", y="Count", title="IOCs by Type"),
                use_container_width=True
            )

    r = requests.get(f"{API}/iocs", params={"limit": 500}).json().get("items", [])
    if r:
        df = pd.DataFrame(r)
        st.plotly_chart(
            px.histogram(df, x="risk_score", nbins=30,
                         title="Risk Score Distribution"),
            use_container_width=True
        )
        st.plotly_chart(
            px.scatter(df, x="confidence", y="risk_score",
                       color="anomaly", hover_data=["value", "source"],
                       title="Confidence vs Risk (colored by anomaly)"),
            use_container_width=True
        )

# ---------- Tab 2: World Map ----------
with tab2:
    st.caption("Geographic distribution of IP indicators (from GeoIP enrichment)")
    try:
        g = requests.get(f"{API}/geo", timeout=10).json()
        items = g.get("items", [])
        if items:
            df = pd.DataFrame(items)
            fig = px.choropleth(
                df,
                locations="country",
                locationmode="country names",
                color="count",
                color_continuous_scale="Reds",
                title="Malicious IP Origins"
            )
            fig.update_layout(
                geo=dict(bgcolor="rgba(0,0,0,0)"),
                paper_bgcolor="rgba(0,0,0,0)",
                font_color="#e6edf3",
                height=550
            )
            st.plotly_chart(fig, use_container_width=True)
            st.plotly_chart(
                px.bar(df.head(15), x="count", y="country",
                       orientation="h", title="Top 15 Countries",
                       color="count", color_continuous_scale="Reds"),
                use_container_width=True
            )
        else:
            st.info("No geo data yet. Run `python -m app.main` a few times "
                    "to enrich IPs.")
    except Exception as e:
        st.error(str(e))

# ---------- Tab 3: Timeline ----------
with tab3:
    st.caption("IOC ingestion timeline")
    try:
        t = requests.get(f"{API}/timeline", timeout=10).json()
        items = t.get("items", [])
        if items:
            df = pd.DataFrame(items)
            df["date"] = pd.to_datetime(df["date"])
            st.plotly_chart(
                px.area(df, x="date", y="count",
                        title="IOCs Added Over Time",
                        color_discrete_sequence=["#4da3ff"]),
                use_container_width=True
            )
            st.dataframe(df.tail(20), use_container_width=True)
        else:
            st.info("No timeline data yet.")
    except Exception as e:
        st.error(str(e))

# ---------- Tab 4: Explorer ----------
with tab4:
    data = requests.get(f"{API}/iocs", params=params).json()
    st.caption(f"Showing {len(data['items'])} of {data['total']} IOCs")
    if data["items"]:
        df = pd.DataFrame(data["items"])
        st.dataframe(df, use_container_width=True, height=500)
        csv = df.to_csv(index=False).encode("utf-8")
        st.download_button("⬇️ Export CSV", csv, "iocs.csv", "text/csv")

    if search_q:
        st.markdown(f"### Search results for `{search_q}`")
        res = requests.get(f"{API}/search", params={"q": search_q}).json()
        st.write(f"{res['count']} results")
        if res["items"]:
            st.dataframe(pd.DataFrame(res["items"]),
                         use_container_width=True)

# ---------- Tab 5: Alerts ----------
with tab5:
    sev = st.selectbox("Severity",
                       ["all", "low", "medium", "high", "critical"])
    qp = {} if sev == "all" else {"severity": sev}
    alerts = requests.get(f"{API}/alerts", params=qp).json()
    st.caption(f"{alerts['total']} alerts")
    if alerts["items"]:
        st.dataframe(pd.DataFrame(alerts["items"]),
                     use_container_width=True, height=500)

# ---------- Tab 6: Correlation Graph ----------
with tab6:
    st.caption("IOCs linked by shared malware family and source "
               "(top 150 by risk)")
    g = requests.get(f"{API}/graph", params={"limit": 150}).json()
    if g.get("nodes"):
        net = Network(height="650px", width="100%",
                      bgcolor="#111", font_color="white")
        net.barnes_hut()

        color_map = {"ioc": "#4da3ff", "family": "#ff4d4d",
                     "source": "#4dff88"}
        for n in g["nodes"]:
            color = color_map.get(n["kind"], "#888")
            net.add_node(
                n["id"],
                label=n["label"][:30],
                color=color,
                title=f"{n.get('source','')} · {n.get('ioc_type','')} "
                      f"· risk {n.get('risk',0)}"
            )
        for e in g["edges"]:
            net.add_edge(e["from"], e["to"], title=e["kind"])

        out_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "graph.html"
        )
        net.save_graph(out_path)
        with open(out_path, "r", encoding="utf-8") as fh:
            html = fh.read()

        st.components.v1.html(html, height=680)
        st.caption(f"Nodes: {g['stats']['node_count']} | "
                   f"Edges: {g['stats']['edge_count']}")
        st.download_button("⬇️ Download graph.html", html,
                           "graph.html", "text/html")
    else:
        st.info("No graph data yet. Run `python -m app.main` first.")

# ---------- Tab 7: Export ----------
with tab7:
    st.subheader("Export")
    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown("**PDF Report**")
        st.markdown(
            "Executive summary, source distribution, top-risk IOCs, "
            "recent alerts, and ML metrics."
        )
        if st.button("📄 Generate PDF Report"):
            r = requests.get(f"{API}/report")
            if r.status_code == 200:
                st.download_button(
                    "⬇️ Download PDF",
                    data=r.content,
                    file_name="cti_report.pdf",
                    mime="application/pdf"
                )
            else:
                st.error(f"API returned {r.status_code}")

    with col2:
        st.markdown("**STIX 2.1 Bundle**")
        st.markdown(
            "Top 500 IOCs formatted for ingestion into MISP, OpenCTI, "
            "or TheHive."
        )
        st.markdown(f"[Open JSON preview]({API}/export/stix)")
        st.markdown(f"[Download STIX bundle]({API}/export/stix/download)")

    with col3:
        st.markdown("**ML Metrics**")
        try:
            m = requests.get(f"{API}/ml/metrics").json()
            if "error" in m:
                st.info(m["error"])
            else:
                st.json({
                    "label": m.get("label"),
                    "baseline_accuracy": m.get("baseline_accuracy"),
                    "accuracy": m.get("accuracy"),
                    "f1": m.get("f1"),
                    "roc_auc": m.get("roc_auc"),
                    "samples_train": m.get("samples_train"),
                    "samples_test": m.get("samples_test")
                })
        except Exception as e:
            st.error(str(e))

st.sidebar.markdown("---")
st.sidebar.caption("CTI Dashboard · Sep 2026")