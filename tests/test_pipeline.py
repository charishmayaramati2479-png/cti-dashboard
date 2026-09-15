import os
import sys
sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
))

from app.normalizer import (
    _clean_type, normalize_urlhaus, normalize_nvd, normalize_threatfox
)
from app.scoring import compute_risk_score
from app.ml import _digit_ratio


class FakeIOC:
    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)


def test_clean_type_normalization():
    assert _clean_type("ip:port") == "ip"
    assert _clean_type("MD5_HASH") == "hash"
    assert _clean_type("sha256") == "hash"
    assert _clean_type(None) == "unknown"


def test_urlhaus_normalizer_shape():
    entry = {"url": "http://evil.com/a", "threat": "malware_download",
             "tags": ["emotet"]}
    out = normalize_urlhaus(entry)
    assert out["ioc_type"] == "url"
    assert out["source"] == "urlhaus"
    assert out["value"] == "http://evil.com/a"
    assert out["malware_family"] == "emotet"


def test_nvd_extracts_cvss():
    cve = {
        "id": "CVE-2025-1234",
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
        "descriptions": [{"lang": "en", "value": "RCE"}]
    }
    out = normalize_nvd(cve)
    assert out["ioc_type"] == "cve"
    assert out["cvss_score"] == 9.8
    assert out["value"] == "CVE-2025-1234"


def test_threatfox_normalizer():
    entry = {
        "ioc": "1.2.3.4:443",
        "ioc_type": "ip:port",
        "threat_type": "botnet_cc",
        "malware_printable": "Emotet",
        "confidence_level": 90,
        "tags": ["c2"]
    }
    out = normalize_threatfox(entry)
    assert out["ioc_type"] == "ip"
    assert out["source"] == "threatfox"
    assert out["malware_family"] == "Emotet"


def test_risk_score_high_for_critical():
    ioc = FakeIOC(confidence=90, cvss_score=10.0, malware_family="emotet",
                  ioc_type="cve", source="nvd", country=None)
    score = compute_risk_score(ioc, [ioc])
    assert score >= 70


def test_risk_score_low_for_weak_ioc():
    ioc = FakeIOC(confidence=30, cvss_score=0.0, malware_family=None,
                  ioc_type="domain", source="unknown", country=None)
    score = compute_risk_score(ioc, [ioc])
    assert score <= 40


def test_digit_ratio():
    assert _digit_ratio("abc") == 0.0
    assert _digit_ratio("123") == 1.0
    assert _digit_ratio("a1b2") == 0.5


def test_high_risk_country_boost():
    base = FakeIOC(confidence=50, cvss_score=0.0, malware_family=None,
                   ioc_type="ip", source="feodo", country=None)
    boosted = FakeIOC(confidence=50, cvss_score=0.0, malware_family=None,
                      ioc_type="ip", source="feodo", country="Russia")
    s1 = compute_risk_score(base, [base])
    s2 = compute_risk_score(boosted, [boosted])
    assert s2 > s1