"""
IEEE CyberSalukis HealthGuard OSINT
Report Generator — Produces TIPPSS-mapped attack surface assessment reports
"""

import json
import datetime
from typing import Dict, Any
from src.utils.normalizer import group_by_severity, count_by_severity
from src.utils.tippss_mapper import get_tippss_summary, TIPPSS_DEFINITIONS


SEVERITY_ICONS = {
    "critical": "[CRITICAL]",
    "high":     "[HIGH]    ",
    "medium":   "[MEDIUM]  ",
    "low":      "[LOW]     ",
    "info":     "[INFO]    ",
}

DIVIDER = "=" * 80
SUBDIV  = "-" * 80


class ReportGenerator:
    """Generates structured assessment reports from normalized findings."""

    def __init__(self, config: dict = None):
        self.config = config or {}

    def generate_text_report(self, report_data: Dict[str, Any], output_path: str):
        """Generate a human-readable plain-text assessment report."""
        findings = report_data.get("findings", [])
        target = report_data.get("target", "Unknown")
        domain = report_data.get("domain", "Unknown")
        timestamp = report_data.get("timestamp", "Unknown")
        modules_run = report_data.get("modules_run", [])
        session_id = report_data.get("session_id", "Unknown")

        severity_counts = count_by_severity(findings)
        tippss_summary = get_tippss_summary(findings)
        by_severity = group_by_severity(findings)

        lines = []

        # ── Header ────────────────────────────────────────────────────────────
        lines.append(DIVIDER)
        lines.append("  IEEE CyberSalukis HealthGuard OSINT")
        lines.append("  Healthcare AI Attack Surface Assessment Report")
        lines.append("  Open-Source Digital Public Good (DPG)")
        lines.append("  IEEE SA Cybersecurity Hackathon 2026")
        lines.append(DIVIDER)
        lines.append(f"  Target Organization : {target}")
        lines.append(f"  Target Domain       : {domain}")
        lines.append(f"  Assessment Date     : {timestamp}")
        lines.append(f"  Session ID          : {session_id}")
        lines.append(f"  Modules Run         : {', '.join(modules_run) if modules_run else 'N/A'}")
        lines.append(f"  Total Findings      : {len(findings)}")
        lines.append(DIVIDER)
        lines.append("")
        lines.append("  ⚠  AUTHORIZED USE ONLY — This report is for the security team of the")
        lines.append("     assessed organization only. Do not distribute externally.")
        lines.append("")

        # ── Executive Summary ─────────────────────────────────────────────────
        lines.append(DIVIDER)
        lines.append("  EXECUTIVE SUMMARY")
        lines.append(DIVIDER)
        lines.append("")

        total = len(findings)
        crit = severity_counts.get("critical", 0)
        high = severity_counts.get("high", 0)
        med  = severity_counts.get("medium", 0)
        low  = severity_counts.get("low", 0)
        info = severity_counts.get("info", 0)

        if crit > 0:
            risk_level = "CRITICAL — Immediate action required"
        elif high > 0:
            risk_level = "HIGH — Urgent remediation recommended"
        elif med > 0:
            risk_level = "MEDIUM — Remediation should be prioritized"
        else:
            risk_level = "LOW / INFORMATIONAL — Continue monitoring"

        lines.append(f"  Overall Risk Level  : {risk_level}")
        lines.append("")
        lines.append(f"  FINDING SEVERITY BREAKDOWN")
        lines.append(f"  {'Critical':<12}: {crit:>4}  {'█' * min(crit, 40)}")
        lines.append(f"  {'High':<12}: {high:>4}  {'█' * min(high, 40)}")
        lines.append(f"  {'Medium':<12}: {med:>4}  {'█' * min(med, 40)}")
        lines.append(f"  {'Low':<12}: {low:>4}  {'█' * min(low, 40)}")
        lines.append(f"  {'Info':<12}: {info:>4}  {'█' * min(info, 40)}")
        lines.append(f"  {'TOTAL':<12}: {total:>4}")
        lines.append("")

        # ── TIPPSS Summary ────────────────────────────────────────────────────
        lines.append(DIVIDER)
        lines.append("  TIPPSS FRAMEWORK MAPPING")
        lines.append(DIVIDER)
        lines.append("")

        tippss_letters = {
            "Trust": "T", "Identity": "I", "Privacy": "P",
            "Protection": "P", "Safety": "S", "Security": "S"
        }

        for cat, data in tippss_summary.items():
            count = data["finding_count"]
            bar = "█" * min(count, 30) if count > 0 else "░ (no findings)"
            lines.append(f"  [{tippss_letters.get(cat, '?')}] {cat:<12}: {count:>3} finding(s)  {bar}")

        lines.append("")
        lines.append("  TIPPSS CATEGORY DEFINITIONS:")
        for cat, definition in TIPPSS_DEFINITIONS.items():
            lines.append(f"")
            lines.append(f"  [{tippss_letters.get(cat, '?')}] {cat}")
            lines.append(f"      {definition}")

        lines.append("")

        # ── Key Recommendations ───────────────────────────────────────────────
        lines.append(DIVIDER)
        lines.append("  KEY REMEDIATION RECOMMENDATIONS")
        lines.append(DIVIDER)
        lines.append("")

        # Pull top 10 unique remediations from critical/high findings
        seen_remediations = set()
        priority_findings = by_severity.get("critical", []) + by_severity.get("high", [])
        rec_num = 1
        for f in priority_findings[:20]:
            rem = f.get("remediation", "").strip()
            if rem and rem not in seen_remediations:
                seen_remediations.add(rem)
                # Truncate long remediations to first sentence for summary
                short = rem.split(".")[0] + "." if "." in rem else rem
                lines.append(f"  {rec_num:>2}. [{f.get('severity', 'info').upper()}] {short}")
                rec_num += 1
                if rec_num > 10:
                    break

        if rec_num == 1:
            lines.append("  No critical or high findings requiring immediate action.")

        lines.append("")

        # ── Detailed Findings ─────────────────────────────────────────────────
        lines.append(DIVIDER)
        lines.append("  DETAILED FINDINGS")
        lines.append(DIVIDER)

        finding_num = 0
        for severity in ["critical", "high", "medium", "low", "info"]:
            sev_findings = by_severity.get(severity, [])
            if not sev_findings:
                continue

            lines.append("")
            lines.append(f"  ── {severity.upper()} FINDINGS ({len(sev_findings)}) ──")
            lines.append("")

            for f in sev_findings:
                finding_num += 1
                lines.append(SUBDIV)
                lines.append(f"  Finding #{finding_num:03d}  {SEVERITY_ICONS.get(severity, '')}  ID: {f.get('id', 'N/A')}")
                lines.append(f"  Title       : {f.get('title', 'N/A')}")
                lines.append(f"  Module      : {f.get('module', 'N/A')}")
                lines.append(f"  Source      : {f.get('source', 'N/A')}")
                lines.append(f"  TIPPSS      : {', '.join(f.get('tippss', []))}")
                lines.append(f"  URL         : {f.get('url', 'N/A') or 'N/A'}")
                lines.append(f"  Query       : {f.get('query', 'N/A')[:100]}")
                lines.append(f"  Timestamp   : {f.get('timestamp', 'N/A')}")
                lines.append("")
                lines.append("  DESCRIPTION:")
                for line in self._wrap(f.get("description", ""), 74):
                    lines.append(f"    {line}")
                lines.append("")
                lines.append("  REMEDIATION:")
                for line in self._wrap(f.get("remediation", "No remediation provided."), 74):
                    lines.append(f"    {line}")
                lines.append("")

        # ── Footer ────────────────────────────────────────────────────────────
        lines.append(DIVIDER)
        lines.append("  IEEE CyberSalukis HealthGuard OSINT — Digital Public Good (DPG)")
        lines.append("  IEEE SA Cybersecurity Hackathon 2026")
        lines.append(f"  Report generated: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append("  https://github.com/CyberSalukis/CyberSalukis-Healthguard-OSINT-")
        lines.append(DIVIDER)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    def generate_json_report(self, report_data: Dict[str, Any], output_path: str):
        """Generate a structured JSON report for SIEM integration."""
        findings = report_data.get("findings", [])
        severity_counts = count_by_severity(findings)
        tippss_summary = get_tippss_summary(findings)

        report = {
            "report_meta": {
                "framework": "IEEE CyberSalukis HealthGuard OSINT",
                "version": "1.0.0",
                "type": "Healthcare AI Attack Surface Assessment",
                "dpg": True,
                "generated": datetime.datetime.utcnow().isoformat() + "Z",
            },
            "assessment": {
                "target": report_data.get("target"),
                "domain": report_data.get("domain"),
                "timestamp": report_data.get("timestamp"),
                "session_id": report_data.get("session_id"),
                "modules_run": report_data.get("modules_run", []),
            },
            "summary": {
                "total_findings": len(findings),
                "by_severity": severity_counts,
                "by_tippss": {
                    cat: data["finding_count"]
                    for cat, data in tippss_summary.items()
                },
            },
            "findings": findings,
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

    @staticmethod
    def _wrap(text: str, width: int) -> list:
        """Simple word wrapper."""
        if not text:
            return [""]
        words = text.split()
        lines = []
        current = []
        current_len = 0
        for word in words:
            if current_len + len(word) + 1 > width and current:
                lines.append(" ".join(current))
                current = [word]
                current_len = len(word)
            else:
                current.append(word)
                current_len += len(word) + 1
        if current:
            lines.append(" ".join(current))
        return lines if lines else [""]
