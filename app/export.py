import io
import json
from datetime import datetime, timezone
from stix2 import (
    Bundle, Indicator, Identity, Vulnerability,
    Relationship, Malware
)

STIX_TYPE_MAP = {
    "ip": "ipv4-addr",
    "domain": "domain-name",
    "url": "url",
    "hash": "file",
    "cve": "vulnerability",
}


def _ioc_to_pattern(ioc):
    """Map an IOC to a STIX 2.1 pattern."""
    t = ioc.ioc_type
    v = (ioc.value or "").replace("'", "\\'")
    if t == "ip":
        # strip port if present
        ip = v.split(":")[0]
        return f"[ipv4-addr:value = '{ip}']"
    if t == "domain":
        return f"[domain-name:value = '{v}']"
    if t == "url":
        return f"[url:value = '{v}']"
    if t == "hash":
        if len(v) == 32:
            return f"[file:hashes.'MD5' = '{v}']"
        if len(v) == 40:
            return f"[file:hashes.'SHA-1' = '{v}']"
        if len(v) == 64:
            return f"[file:hashes.'SHA-256' = '{v}']"
        return f"[file:hashes.'SHA-256' = '{v}']"
    return None


def build_stix_bundle(iocs, identity_name="CTI Dashboard"):
    """
    Convert a list of IOC ORM objects into a STIX 2.1 Bundle.
    Returns (bundle_dict, counts_dict).
    """
    identity = Identity(
        name=identity_name,
        identity_class="system"
    )

    objects = [identity]
    indicator_count = 0
    vuln_count = 0
    malware_seen = {}

    for ioc in iocs:
        # CVEs → Vulnerability objects
        if ioc.ioc_type == "cve":
            vuln = Vulnerability(
                name=ioc.value,
                description=f"CVSS {ioc.cvss_score} (source {ioc.source})",
                created_by_ref=identity.id
            )
            objects.append(vuln)
            vuln_count += 1
            continue

        # Other IOCs → Indicator objects
        pattern = _ioc_to_pattern(ioc)
        if not pattern:
            continue

        labels = []
        if ioc.threat_type:
            labels.append(ioc.threat_type)
        if ioc.malware_family:
            labels.append(ioc.malware_family)

        indicator = Indicator(
            name=f"{ioc.ioc_type}: {ioc.value[:80]}",
            description=(
                f"Source: {ioc.source} | Risk: {ioc.risk_score} | "
                f"Confidence: {ioc.confidence}"
            ),
            pattern=pattern,
            pattern_type="stix",
            valid_from=(ioc.first_seen or datetime.now(timezone.utc)),
            labels=labels or ["malicious-activity"],
            created_by_ref=identity.id,
            confidence=max(0, min(100, int(ioc.confidence or 50)))
        )
        objects.append(indicator)
        indicator_count += 1

        # Malware objects (deduplicated)
        if ioc.malware_family and ioc.malware_family not in malware_seen:
            mw = Malware(
                name=ioc.malware_family,
                is_family=True,
                created_by_ref=identity.id
            )
            malware_seen[ioc.malware_family] = mw
            objects.append(mw)
            objects.append(Relationship(
                relationship_type="indicates",
                source_ref=indicator.id,
                target_ref=mw.id,
                created_by_ref=identity.id
            ))

    bundle = Bundle(objects=objects, allow_custom=True)
    counts = {
        "total_objects": len(objects),
        "indicators": indicator_count,
        "vulnerabilities": vuln_count,
        "malware_families": len(malware_seen),
        "identity": 1
    }
    return json.loads(bundle.serialize()), counts