import os
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, roc_auc_score
)
from sklearn.utils import resample

MODEL_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models"
)
MODEL_PATH = os.path.join(MODEL_DIR, "attribution_classifier.pkl")
os.makedirs(MODEL_DIR, exist_ok=True)

HIGH_RISK_COUNTRIES = {"russia", "china", "iran", "north korea", "belarus"}

# Features deliberately exclude confidence / cvss_score / risk_score / anomaly
# to prevent label leakage from the IsolationForest scoring pipeline.
NUMERIC_FEATURES = [
    "is_high_risk_country",
    "has_asn",
    "value_length",
    "digit_ratio",
]
CATEGORICAL_FEATURES = ["ioc_type"]


def _digit_ratio(s):
    if not s:
        return 0.0
    digits = sum(c.isdigit() for c in s)
    return round(digits / len(s), 3)


def _to_dataframe(iocs):
    rows = []
    for i in iocs:
        country = (getattr(i, "country", None) or "").lower()
        value = i.value or ""
        rows.append({
            "is_high_risk_country": int(country in HIGH_RISK_COUNTRIES),
            "has_asn": int(bool(i.asn)),
            "value_length": len(value),
            "digit_ratio": _digit_ratio(value),
            "ioc_type": i.ioc_type or "unknown",
            "source": i.source or "unknown"
        })
    return pd.DataFrame(rows)


def _build_pipeline():
    return Pipeline([
        ("pre", ColumnTransformer([
            ("num", "passthrough", NUMERIC_FEATURES),
            ("cat", OneHotEncoder(handle_unknown="ignore"),
             CATEGORICAL_FEATURES)
        ])),
        ("clf", RandomForestClassifier(
            n_estimators=200, max_depth=8,
            random_state=42, n_jobs=-1,
            class_weight="balanced"
        ))
    ])


def train_and_score(db, IOC):
    """
    Supervised model: predicts whether an IOC will be attributed
    to a known malware family.

    Label    = has_malware_family (independent of scoring features)
    Features = structural + geolocation signals (no confidence/cvss/risk)
    Balance  = majority class undersampled in training set only
    """
    iocs = db.query(IOC).all()
    if len(iocs) < 50:
        print("[ml] not enough IOCs to train (need 50+)")
        return {}

    X = _to_dataframe(iocs)
    y = np.array([int(bool(i.malware_family)) for i in iocs])

    if y.sum() < 10 or (1 - y).sum() < 10:
        print(f"[ml] not enough class diversity (pos={y.sum()}, neg={(1-y).sum()})")
        return {}

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    # ---- Balance training classes by undersampling majority ----
    train_df = X_train.copy()
    train_df["_y"] = y_train
    pos = train_df[train_df["_y"] == 1]
    neg = train_df[train_df["_y"] == 0]
    n = min(len(pos), len(neg))
    if n < 10:
        print("[ml] not enough samples after balancing")
        return {}
    pos_s = resample(pos, n_samples=n, random_state=42, replace=False)
    neg_s = resample(neg, n_samples=n, random_state=42, replace=False)
    balanced = pd.concat([pos_s, neg_s]).sample(frac=1, random_state=42)
    X_train = balanced.drop(columns=["_y"])
    y_train = balanced["_y"].values

    print(f"[ml] balanced train set: {len(X_train)} "
          f"(pos={int(y_train.sum())}, neg={int((1 - y_train).sum())})")

    # ---- Train ----
    pipe = _build_pipeline()
    pipe.fit(X_train, y_train)
    y_pred = pipe.predict(X_test)

    try:
        y_proba = pipe.predict_proba(X_test)[:, 1]
        auc = round(float(roc_auc_score(y_test, y_proba)), 3)
    except Exception:
        auc = None

    metrics = {
        "label": "malware_family_attribution",
        "features": NUMERIC_FEATURES + CATEGORICAL_FEATURES,
        "baseline_accuracy": round(float(max(y.mean(), 1 - y.mean())), 3),
        "samples_total": len(iocs),
        "samples_train": len(X_train),
        "samples_test": len(X_test),
        "positive_rate": round(float(y.mean()), 3),
        "accuracy": round(float(accuracy_score(y_test, y_pred)), 3),
        "precision": round(float(precision_score(y_test, y_pred, zero_division=0)), 3),
        "recall": round(float(recall_score(y_test, y_pred, zero_division=0)), 3),
        "f1": round(float(f1_score(y_test, y_pred, zero_division=0)), 3),
        "roc_auc": auc,
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist()
    }

    # ---- Predict probability for all IOCs ----
    probs = pipe.predict_proba(X)[:, 1]
    for ioc, p in zip(iocs, probs):
        ioc.ml_probability = round(float(p), 4)
    db.commit()

    joblib.dump({"pipeline": pipe, "metrics": metrics}, MODEL_PATH)
    print(f"[ml] label=attribution pos_rate={metrics['positive_rate']} "
          f"baseline={metrics['baseline_accuracy']} "
          f"→ acc={metrics['accuracy']} f1={metrics['f1']} auc={auc}")
    return metrics


def load_metrics():
    if os.path.exists(MODEL_PATH):
        return joblib.load(MODEL_PATH).get("metrics", {})
    return {}