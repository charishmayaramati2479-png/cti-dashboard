# 🛡️ CTI Dashboard

A Cyber Threat Intelligence (CTI) aggregation, analysis, and visualization platform that combines **multi-source threat feeds**, **machine learning based risk scoring**, and **standards-compliant export** (STIX 2.1) with an interactive **Streamlit dashboard** and a **FastAPI** backend.

![Python](https://img.shields.io/badge/Python-3.12-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.141-green)
![Streamlit](https://img.shields.io/badge/Streamlit-1.63-red)
![scikit-learn](https://img.shields.io/badge/scikit--learn-1.9-orange)
![License](https://img.shields.io/badge/License-Educational-lightgrey)

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Screenshots](#screenshots)
- [Setup](#setup)
- [Usage](#usage)
- [API Endpoints](#api-endpoints)
- [Machine Learning](#machine-learning)
- [Docker](#docker)
- [Project Structure](#project-structure)
- [Testing](#testing)
- [Limitations](#limitations)
- [Future Work](#future-work)
- [License](#license)

---

## Overview

Modern cyber threat intelligence is fragmented across dozens of open-source feeds, each with its own schema, IOC types, and reliability level. Analysts waste hours manually correlating indicators instead of acting on them.

**CTI Dashboard** solves this by:

1. Ingesting from **6 open-source feeds** (URLhaus, ThreatFox, NVD, AlienVault OTX, MalwareBazaar, Feodo Tracker)
2. **Normalizing** every IOC into a unified schema
3. **Enriching** IP indicators with GeoIP (country, city, ASN)
4. **Scoring** each IOC with a weighted risk engine
5. Applying **two ML models** — unsupervised anomaly detection and supervised malware attribution
6. Generating **rule-based alerts** with severity levels
7. Exposing everything through a **REST API** and a **7-tab Streamlit dashboard**
8. Exporting results as **STIX 2.1 bundles** and **PDF reports**

The result: a single analyst-facing tool that turns raw feed noise into prioritized, exportable intelligence.

---

## Features

### Data Ingestion
- **6 concurrent feed collectors** with graceful degradation (a failing feed never crashes the pipeline)
- **Deduplication** at the (value, source) level
- **Unified IOC schema** across IP, domain, URL, hash, and CVE types
- **Type normalization** (`ip:port` → `ip`, `sha256_hash` → `hash`, etc.)

### Enrichment
- **GeoIP** lookup for every IP IOC (country, city, ASN) via `ip-api.com`
- **High-risk country boost** applied to risk scoring

### Machine Learning
- **IsolationForest** (unsupervised) — detects anomalous IOCs based on confidence, CVSS, and risk score
- **RandomForest** (supervised) — predicts malware family attribution from structural + geolocation features
- **Balanced training** via majority-class undersampling to avoid trivial 90% baselines
- **Disjoint feature sets** between the two models to prevent label leakage

### Analytics & Visualization
- **Risk scoring** with a weighted formula (confidence, CVSS, malware family, source, geo)
- **Rule-based alerts** across 4 rules: critical CVE, high-risk score, anomaly + high risk, botnet C2
- **Correlation graph** linking IOCs by shared malware family and source (NetworkX + PyVis)
- **World map** of malicious IP origins (Plotly choropleth)
- **Timeline** of IOC ingestion
- **Dark-theme dashboard** with 7 tabs

### Interoperability
- **STIX 2.1 export** — Indicator, Vulnerability, Malware, and Relationship objects
- **PDF report generation** — executive summary, top IOCs, alerts, ML metrics
- **REST API** with 14 endpoints and Swagger docs
- **CSV export** from the dashboard

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  CTI Feeds                                                  │
│  URLhaus · ThreatFox · NVD · OTX · MalwareBazaar · Feodo    │
└──────────────────────────┬──────────────────────────────────┘
                           │
                    ┌──────▼──────┐
                    │ Collectors  │
                    └──────┬──────┘
                           │
                    ┌──────▼────────┐
                    │ Normalizer    │  unified schema + type mapping
                    └──────┬────────┘
                           │
                    ┌──────▼────────┐
                    │ SQLite        │  SQLAlchemy ORM
                    └──────┬────────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
   ┌────▼────┐        ┌────▼─────┐       ┌────▼──────┐
   │ Enrich  │        │ Scoring  │       │    ML     │
   │ GeoIP   │        │ weighted │       │ ISO + RF  │
   └────┬────┘        └────┬─────┘       └────┬──────┘
        │                  │                  │
        └──────────────────┼──────────────────┘
                           │
                    ┌──────▼────────┐
                    │ Alert Engine  │  4 rules · 4 severities
                    └──────┬────────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
   ┌────▼────┐        ┌────▼─────┐       ┌────▼──────┐
   │ FastAPI │        │ Streamlit│       │  Exports  │
   │ 14 APIs │        │ 7 tabs   │       │ STIX · PDF│
   └─────────┘        └──────────┘       └───────────┘
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.12 |
| API | FastAPI + Uvicorn |
| Database | SQLite + SQLAlchemy |
| ML | scikit-learn (IsolationForest, RandomForest) |
| Dashboard | Streamlit + Plotly + PyVis |
| Graph | NetworkX |
| STIX Export | `stix2` |
| PDF | ReportLab |
| Scheduling | APScheduler (optional) |
| Container | Docker + docker-compose |
| Testing | pytest |

---

## Screenshots

### CLI Pipeline

![CLI Output](docs/screenshots/01-cli.png)

### Swagger API Docs

![Swagger](docs/screenshots/02-swagger.png)

### API Stats

![Stats](docs/screenshots/03-stats.png)

### Dashboard — Charts

![Charts](docs/screenshots/04-charts.png)

### Dashboard — World Map

![World Map](docs/screenshots/05-map.png)

### Dashboard — Timeline

![Timeline](docs/screenshots/06-timeline.png)

### Dashboard — IOC Explorer

![Explorer](docs/screenshots/07-explorer.png)

### Dashboard — Alerts

![Alerts](docs/screenshots/08-alerts.png)

### Dashboard — Correlation Graph

![Graph](docs/screenshots/09-graph.png)

### Dashboard — Export Tab

![Export](docs/screenshots/10-export.png)

### PDF Report

![PDF](docs/screenshots/11-pdf.png)

### STIX 2.1 Bundle

![STIX](docs/screenshots/12-stix.png)

### Project Structure

![Tree](docs/screenshots/13-tree.png)

---

## Setup

### Prerequisites

- Python 3.12+
- Git
- (Optional) Docker Desktop
- A free abuse.ch key from https://auth.abuse.ch/
- (Optional) AlienVault OTX key from https://otx.alienvault.com/

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/cti-dashboard.git
cd cti-dashboard
```

### 2. Create a virtual environment

**Windows:**
```powershell
python -m venv venv
venv\Scripts\activate
```

**Linux/macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment

```bash
copy .env.example .env     # Windows
cp .env.example .env       # Linux/macOS
```

Edit `.env` and add your keys:

```env
URLHAUS_AUTH_KEY=your_key_here
THREATFOX_AUTH_KEY=your_key_here
OTX_API_KEY=optional
DATABASE_URL=sqlite:///./data/cti.db
```

> **Note:** The pipeline runs even without keys. Feeds requiring keys are skipped gracefully.

---

## Usage

### Step 1 — Run the ingestion pipeline

```bash
python -m app.main
```

Expected output:

```
Collecting from feeds...
[otx] skipped: invalid or expired API key
Fetched 1408 IOCs, saved 1408 new.
[enrich] enriched 177/300 IP IOCs
[ml] balanced train set: 212 (pos=106, neg=106)
[ml] label=attribution pos_rate=0.9 baseline=0.9 → acc=0.876 f1=0.926 auc=0.986
Scored 1408 IOCs. Flagged 138 as anomalies. Created 34 alerts.
```

Run it again to enrich the next batch of IPs (capped at 300 per run).

### Step 2 — Start the API

**Terminal 1:**
```bash
uvicorn app.api:app --reload
```

API: http://127.0.0.1:8000/docs

### Step 3 — Start the dashboard

**Terminal 2:**
```bash
streamlit run dashboard.py
```

Dashboard: http://localhost:8501

### Step 4 (optional) — Run on a schedule

```bash
python -m app.scheduler
```

Refreshes feeds every 6 hours.

---

## API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/` | Health check |
| GET | `/stats` | Overview metrics |
| GET | `/iocs` | List IOCs (filters: source, type, min_risk, anomaly) |
| GET | `/iocs/{id}` | Single IOC detail |
| GET | `/iocs/{id}/predict` | ML probability for one IOC |
| GET | `/search?q=` | Search IOC values |
| GET | `/alerts` | Alerts (filter by severity) |
| GET | `/graph` | Correlation graph JSON |
| GET | `/geo` | Country distribution |
| GET | `/timeline` | Daily IOC counts |
| GET | `/ml/metrics` | Supervised model metrics |
| GET | `/export/stix` | STIX 2.1 bundle (JSON) |
| GET | `/export/stix/download` | STIX 2.1 bundle (file) |
| GET | `/report` | PDF report |

Full interactive documentation: http://127.0.0.1:8000/docs

---

## Machine Learning

The dashboard applies **two independent models** to every IOC.

### 1. IsolationForest (unsupervised)

- **Goal:** discover anomalous IOCs without labels
- **Features:** confidence, CVSS score, risk score
- **Output:** binary anomaly flag (`anomaly = True/False`)
- **Tuning:** `contamination=0.1` (approximately 10% flagged)

Use case: catch IOCs that don't fit the "normal" pattern of the dataset — for example, a rare source combined with an unusual confidence/CVSS combination.

### 2. RandomForest (supervised)

- **Goal:** predict whether an IOC will be attributed to a known malware family
- **Label:** `has_malware_family`
- **Features (deliberately disjoint from label):**
  - Numeric: `is_high_risk_country`, `has_asn`, `value_length`, `digit_ratio`
  - Categorical: `ioc_type`
- **Balancing:** majority class undersampled during training only
- **Metrics reported:** accuracy, precision, recall, F1, ROC-AUC, confusion matrix

### Design note: avoiding label leakage

An earlier version of this pipeline used `confidence`, `cvss_score`, and `risk_score` as features for the supervised model. Because the label was derived from those same fields, the model achieved a suspicious **99.7% accuracy** — a clear case of target leakage.

This was corrected by:
1. Choosing an **independent label** (`has_malware_family`)
2. Using **disjoint feature sets** from the IsolationForest
3. Applying **undersampling** so the model cannot trivially predict the majority class
4. Reporting the **baseline accuracy** alongside model accuracy for honest comparison

The current model achieves ~87% accuracy against a ~90% trivial baseline on an imbalanced dataset, which is a realistic and defensible result.

### Example metrics

```json
{
  "label": "malware_family_attribution",
  "baseline_accuracy": 0.9,
  "accuracy": 0.876,
  "precision": 0.914,
  "recall": 0.939,
  "f1": 0.926,
  "roc_auc": 0.986,
  "samples_train": 212,
  "samples_test": 352
}
```

---

## Docker

Build and run both services:

```bash
docker compose up --build
```

- API: http://localhost:8000
- Dashboard: http://localhost:8501

Stop:

```bash
docker compose down
```

---

## Project Structure

```
cti-dashboard/
├── app/
│   ├── __init__.py
│   ├── config.py                  # env variables
│   ├── db.py                      # SQLAlchemy models (IOC, Alert)
│   ├── normalizer.py              # feed-specific normalizers
│   ├── enrich.py                  # GeoIP enrichment
│   ├── scoring.py                 # risk scoring + IsolationForest
│   ├── ml.py                      # RandomForest attribution classifier
│   ├── alerts.py                  # rule-based alert engine
│   ├── correlation.py             # NetworkX graph builder
│   ├── export.py                  # STIX 2.1 export
│   ├── report.py                  # PDF report generator
│   ├── api.py                     # FastAPI app
│   ├── main.py                    # pipeline entry point
│   ├── scheduler.py               # APScheduler runner
│   └── collectors/
│       ├── urlhaus.py
│       ├── threatfox.py
│       ├── nvd.py
│       ├── otx.py
│       ├── malwarebazaar.py
│       └── feodo.py
├── tests/
│   ├── __init__.py
│   └── test_pipeline.py
├── docs/
│   └── screenshots/
├── data/                          # SQLite DB (gitignored)
├── dashboard.py                   # Streamlit dashboard
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```

---

## Testing

```bash
pytest tests/ -v
```

Expected output: **8 passed**

Tests cover:
- IOC type normalization
- URLhaus / NVD / ThreatFox normalizer output shape
- High-risk scoring for critical CVEs
- Low-risk scoring for weak indicators
- High-risk country boost behaviour
- Digit ratio helper used in ML features

---

## Limitations

This project is a **functional prototype**, not a production system. Known limitations:

- **Storage:** SQLite is used for simplicity. It handles ~100k IOCs comfortably but is not horizontally scalable.
- **API security:** No authentication is enabled by default. A production deployment would require OAuth2 or API keys.
- **Rate limits:** `ip-api.com` free tier limits enrichment to ~300 IPs per run. Multiple runs are needed for large datasets.
- **Batch ingestion:** Feeds refresh on demand or via the scheduler — not real-time streaming.
- **ML dataset size:** The supervised model trains on the ingested IOCs (1,400+). Larger datasets would improve generalization.
- **Feed coverage:** OTX requires a valid API key; abuse.ch feeds require an abuse.ch key.
- **No monitoring:** No Prometheus, Grafana, or health checks.

---

## Future Work

- Migrate to PostgreSQL for horizontal scale
- Add TAXII 2.1 server for native CTI exchange
- Deploy the pipeline on Kubernetes with horizontal pod autoscaling
- Add authentication and RBAC for multi-analyst deployments
- Integrate with MISP / OpenCTI via their APIs
- Real-time ingestion via Kafka
- Add a dedicated threat-actor attribution model (multi-class)
- Prometheus metrics + Grafana dashboards for operational visibility

---

## License

This project is released under an **educational / academic use** license. It is intended as a portfolio and learning project, not for production deployment.

---

## Acknowledgements

- [abuse.ch](https://abuse.ch/) for URLhaus, ThreatFox, MalwareBazaar, and Feodo Tracker
- [NIST NVD](https://nvd.nist.gov/) for CVE data
- [AlienVault OTX](https://otx.alienvault.com/) for community pulses
- [ip-api.com](http://ip-api.com/) for GeoIP enrichment
- [OASIS](https://oasis-open.github.io/cti-documentation/) for the STIX 2.1 specification
