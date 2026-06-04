"""
IEEE CyberSalukis HealthGuard OSINT
Module: vendor_intel.py — Vendor & Supply Chain Intelligence

Discovers AI vendor relationships, third-party LLM integrations,
and supply chain dependencies visible in public sources including
procurement records, press releases, job postings, and regulatory filings.
"""

import requests
from typing import List, Dict, Any
from .base import BaseModule


class VendorIntel(BaseModule):
    """
    Vendor and supply chain intelligence module.

    Maps publicly visible AI vendor relationships for the target healthcare
    organization. Supply chain visibility enables:
    - Targeted vendor-specific vulnerability research
    - Monitoring of vendor breach disclosures
    - Identification of shared infrastructure risks
    - Third-party AI risk assessment
    """

    MODULE_NAME = "vendor-intel"
    MODULE_LABEL = "Vendor Supply Chain Intel"

    # Known healthcare AI vendors to check for association
    HEALTHCARE_AI_VENDORS = [
        # EHR with AI
        ("Epic Systems", "Epic", "EHR with embedded AI — DAX, Suki integrations, AI-generated notes"),
        ("Oracle Cerner", "Cerner", "EHR with AI clinical decision support"),
        ("Meditech", "Meditech", "EHR with AI-assisted documentation"),
        # Clinical AI
        ("Nuance / Microsoft", "Nuance DAX", "AI ambient clinical documentation — high PHI access"),
        ("Suki AI", "Suki", "AI clinical documentation assistant"),
        ("Abridge", "Abridge", "AI medical note generation"),
        ("Nabla", "Nabla", "AI clinical notes"),
        # Diagnostic AI
        ("Aidoc", "Aidoc", "AI radiology triage — FDA-cleared"),
        ("Viz.ai", "Viz.ai", "AI stroke and cardiac care coordination"),
        ("Annalise.ai", "Annalise", "AI diagnostic imaging"),
        # Infrastructure / Cloud
        ("Microsoft Azure OpenAI", "Azure OpenAI", "HIPAA-eligible LLM cloud service"),
        ("Amazon AWS HealthLake", "AWS HealthLake", "AI-powered FHIR data store"),
        ("Google Cloud Healthcare AI", "Google Health AI", "Healthcare-specific AI services"),
        # Patient engagement
        ("Hyro", "Hyro", "AI healthcare virtual agents"),
        ("Conversica", "Conversica", "AI patient outreach automation"),
        ("Notable Health", "Notable", "AI care coordination"),
        # Cybersecurity AI
        ("Darktrace", "Darktrace", "AI cybersecurity — network anomaly detection"),
        ("CrowdStrike", "CrowdStrike", "AI endpoint security"),
        ("SentinelOne", "SentinelOne", "AI endpoint detection"),
    ]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.api_key = self.config.get("api_keys", {}).get("google_cse_api_key", "")
        self.cx = self.config.get("api_keys", {}).get("google_cse_cx", "")

    def run(self) -> List[Dict[str, Any]]:
        """Execute vendor intelligence gathering."""
        findings = []
        findings.extend(self._detect_vendor_associations())
        findings.extend(self._supply_chain_risk_summary())
        return findings

    def _detect_vendor_associations(self) -> List[Dict[str, Any]]:
        """
        Search for target-vendor association signals in public sources.
        Uses Google CSE if available, otherwise returns documented search queries.
        """
        findings = []
        org_name = self.target or self.domain

        for vendor_full, vendor_short, vendor_desc in self.HEALTHCARE_AI_VENDORS:
            query = f'"{org_name}" "{vendor_short}" OR "{vendor_full}" "healthcare" OR "AI" OR "clinical"'
            self._log(f"Vendor search: {vendor_short}")

            if self.api_key and self.cx:
                results = self._google_search(query)
                if results:
                    for item in results[:2]:
                        finding = self._make_finding(
                            source="Vendor Intelligence — Google Search",
                            query=query,
                            title=f"AI Vendor Association Detected: {vendor_full}",
                            description=(
                                f"Public sources indicate a potential relationship between "
                                f"{org_name} and {vendor_full}. "
                                f"Vendor profile: {vendor_desc}. "
                                f"Source: {item.get('title', '')} — {item.get('snippet', '')} "
                                f"This vendor relationship enables targeted supply chain "
                                f"reconnaissance including monitoring for vendor-specific "
                                f"vulnerabilities, breach disclosures, and shared infrastructure risks."
                            ),
                            severity="medium",
                            tippss=["Trust", "Security"],
                            remediation=(
                                f"Monitor {vendor_full} security advisories and breach disclosures. "
                                f"Conduct vendor security assessment. "
                                f"Review data processing agreements for AI data handling. "
                                f"Ensure vendor HIPAA BAA is in place."
                            ),
                            url=item.get("link", ""),
                            raw={"vendor": vendor_full, "query": query}
                        )
                        findings.append(finding)
            else:
                # No API key — return as documented query for manual execution
                finding = self._make_finding(
                    source="Vendor Intelligence Query Library (configure Google CSE to automate)",
                    query=query,
                    title=f"[MANUAL] Vendor Association Check: {vendor_full}",
                    description=(
                        f"Manual search recommended: {query}\n\n"
                        f"Vendor profile: {vendor_desc}. "
                        f"Execute this query in Google to identify public associations "
                        f"between {org_name} and {vendor_full}."
                    ),
                    severity="info",
                    tippss=["Trust", "Security"],
                    remediation=(
                        f"If association confirmed: Monitor {vendor_full} security advisories. "
                        f"Ensure HIPAA BAA is in place. Conduct vendor risk assessment."
                    ),
                )
                findings.append(finding)

            self._throttle()

        return findings

    def _google_search(self, query: str) -> List[Dict]:
        """Execute Google CSE search."""
        try:
            resp = requests.get(
                "https://www.googleapis.com/customsearch/v1",
                params={"key": self.api_key, "cx": self.cx, "q": query, "num": 5},
                timeout=15
            )
            resp.raise_for_status()
            return resp.json().get("items", [])
        except Exception as e:
            self._log(f"Google search error: {e}", "error")
            return []

    def _supply_chain_risk_summary(self) -> List[Dict[str, Any]]:
        """Return supply chain risk framework findings."""
        supply_chain_risks = [
            {
                "title": "Third-Party AI Model Dependency Risk",
                "description": (
                    f"Healthcare organizations using third-party LLM APIs (OpenAI, Anthropic, "
                    f"Google, Azure) transmit potentially sensitive clinical queries to external "
                    f"infrastructure. Supply chain risks include: vendor data breach exposing "
                    f"query history, API service outage disrupting clinical AI tools, "
                    f"vendor model updates changing AI behavior without notice, and "
                    f"insufficient BAA coverage for PHI transmitted to AI APIs."
                ),
                "severity": "high",
                "tippss": ["Trust", "Privacy", "Security"],
                "remediation": (
                    "Audit all LLM API integrations for PHI transmission. "
                    "Ensure HIPAA BAAs with all AI vendors. "
                    "Implement data minimization in AI prompts. "
                    "Evaluate on-premise or private cloud LLM deployment for PHI use cases. "
                    "Monitor vendor security advisories."
                )
            },
            {
                "title": "Open-Source AI Model Supply Chain Risk",
                "description": (
                    "Healthcare organizations deploying open-source AI models (Llama, Mistral, "
                    "Phi, etc.) from HuggingFace or similar repositories face supply chain risks "
                    "including: malicious model uploads, model weight poisoning, "
                    "dependency vulnerabilities in model serving frameworks, and "
                    "lack of security validation on model behavior in clinical contexts."
                ),
                "severity": "medium",
                "tippss": ["Trust", "Safety", "Security"],
                "remediation": (
                    "Validate model provenance before deployment. "
                    "Use only verified, checksummed model weights. "
                    "Conduct adversarial testing before clinical deployment. "
                    "Implement model integrity monitoring."
                )
            },
        ]

        findings = []
        for risk in supply_chain_risks:
            finding = self._make_finding(
                source="Supply Chain Risk Assessment",
                query=f"AI supply chain risk: {self.target or self.domain}",
                title=risk["title"],
                description=risk["description"],
                severity=risk["severity"],
                tippss=risk["tippss"],
                remediation=risk["remediation"],
            )
            findings.append(finding)

        return findings
