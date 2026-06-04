"""
IEEE CyberSalukis HealthGuard OSINT
Utility: normalizer.py — Findings Normalization & Deduplication
"""

import hashlib
from typing import List, Dict, Any


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def normalize_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Normalize, deduplicate, and sort findings from all modules.
    Deduplication is based on a hash of (module, title, url).
    Returns sorted by severity (critical first).
    """
    seen = set()
    normalized = []

    for f in findings:
        # Ensure required fields
        f.setdefault("id", "unknown")
        f.setdefault("module", "unknown")
        f.setdefault("source", "unknown")
        f.setdefault("query", "")
        f.setdefault("url", "")
        f.setdefault("title", "Untitled Finding")
        f.setdefault("description", "")
        f.setdefault("severity", "info")
        f.setdefault("tippss", [])
        f.setdefault("remediation", "")
        f.setdefault("timestamp", "")
        f.setdefault("raw", {})

        # Normalize severity
        f["severity"] = f["severity"].lower()
        if f["severity"] not in SEVERITY_ORDER:
            f["severity"] = "info"

        # Deduplication key
        dedup_key = hashlib.md5(
            f"{f['module']}|{f['title']}|{f['url']}".encode()
        ).hexdigest()

        if dedup_key not in seen:
            seen.add(dedup_key)
            normalized.append(f)

    # Sort by severity
    normalized.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))

    return normalized


def group_by_severity(findings: List[Dict]) -> Dict[str, List[Dict]]:
    """Group findings by severity level."""
    groups = {s: [] for s in SEVERITY_ORDER}
    for f in findings:
        groups[f.get("severity", "info")].append(f)
    return groups


def group_by_tippss(findings: List[Dict]) -> Dict[str, List[Dict]]:
    """Group findings by TIPPSS category."""
    categories = ["Trust", "Identity", "Privacy", "Protection", "Safety", "Security"]
    groups = {c: [] for c in categories}
    for f in findings:
        for cat in f.get("tippss", []):
            if cat in groups:
                groups[cat].append(f)
    return groups


def count_by_severity(findings: List[Dict]) -> Dict[str, int]:
    """Count findings by severity."""
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
    return counts
