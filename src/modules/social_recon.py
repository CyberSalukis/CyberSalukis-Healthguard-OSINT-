"""
IEEE CyberSalukis HealthGuard OSINT
Module: social_recon.py — Social Engineering Surface Analyzer

Discovers personnel-level AI tool disclosure, employee digital footprint
related to healthcare AI systems, and social engineering attack surface
through passive OSINT on public professional profiles and content.
"""

import requests
from typing import List, Dict, Any
from .base import BaseModule


class SocialRecon(BaseModule):
    """
    Social engineering surface reconnaissance module.

    Targets:
    - LinkedIn employee disclosures of AI tools
    - Conference presentations revealing AI architecture
    - Academic publications disclosing clinical AI systems
    - Job postings revealing technology stack
    - Twitter/X posts disclosing AI tool usage by clinical staff
    """

    MODULE_NAME = "social-recon"
    MODULE_LABEL = "Social Engineering Surface Analyzer"

    # AI tools commonly disclosed by healthcare employees
    HEALTHCARE_AI_TOOLS = [
        "ChatGPT", "Copilot", "Epic AI", "DAX", "Suki",
        "Abridge", "Nuance", "AI scribe", "ambient AI",
        "clinical AI", "AI assistant", "LLM", "GPT-4",
        "AI documentation", "AI notes", "generative AI"
    ]

    # Clinical roles most likely to disclose AI tool usage
    CLINICAL_ROLES = [
        "physician", "nurse", "clinician", "doctor",
        "radiologist", "pharmacist", "therapist",
        "care coordinator", "clinical informatics",
        "health IT", "CMIO", "CNIO", "CIO"
    ]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.api_key = self.config.get("api_keys", {}).get("google_cse_api_key", "")
        self.cx = self.config.get("api_keys", {}).get("google_cse_cx", "")

    def run(self) -> List[Dict[str, Any]]:
        """Execute social engineering surface analysis."""
        findings = []
        findings.extend(self._linkedin_ai_disclosure_queries())
        findings.extend(self._job_posting_tech_disclosure())
        findings.extend(self._conference_presentation_exposure())
        findings.extend(self._academic_publication_disclosure())
        findings.extend(self._social_engineering_risk_summary())
        return findings

    def _linkedin_ai_disclosure_queries(self) -> List[Dict[str, Any]]:
        """Generate LinkedIn OSINT queries for employee AI disclosure."""
        findings = []
        org_name = self.target or self.domain

        linkedin_queries = []
        for tool in self.HEALTHCARE_AI_TOOLS[:6]:
            for role in self.CLINICAL_ROLES[:3]:
                query = f'site:linkedin.com "{org_name}" "{tool}" "{role}"'
                linkedin_queries.append((query, tool, role))

        # Add org-level queries
        linkedin_queries.extend([
            (f'site:linkedin.com "{org_name}" "AI" "implementation" "healthcare"', "AI Implementation", "staff"),
            (f'site:linkedin.com "{org_name}" "LLM" OR "GPT" OR "generative AI" "clinical"', "LLM Usage", "clinical staff"),
        ])

        for query, tool, role in linkedin_queries[:8]:
            self._log(f"LinkedIn OSINT: {query[:60]}...")

            results = self._google_search(query) if (self.api_key and self.cx) else []

            if results:
                for item in results[:2]:
                    finding = self._make_finding(
                        source="LinkedIn OSINT (via Google)",
                        query=query,
                        title=f"Employee AI Tool Disclosure: {tool} by {role}",
                        description=(
                            f"LinkedIn search revealed potential disclosure of '{tool}' usage "
                            f"by {role} staff at {org_name}. "
                            f"Profile: {item.get('title', 'unknown')}. "
                            f"Snippet: {item.get('snippet', '')}. "
                            f"Personnel disclosures of AI tools provide adversaries with: "
                            f"specific AI products in use, workflow integration details, "
                            f"social engineering targets with AI access, and potential "
                            f"prompt injection vectors via trusted user impersonation."
                        ),
                        severity="low",
                        tippss=["Trust", "Identity", "Security"],
                        remediation=(
                            "Train clinical staff on responsible AI tool disclosure policies. "
                            "Include AI tools in acceptable use and social media policies. "
                            "Educate staff on social engineering risks from technology disclosure."
                        ),
                        url=item.get("link", ""),
                        raw={"tool": tool, "role": role, "query": query}
                    )
                    findings.append(finding)
            else:
                # Return as documented query
                finding = self._make_finding(
                    source="LinkedIn OSINT Query (configure Google CSE to automate)",
                    query=query,
                    title=f"[MANUAL] LinkedIn Disclosure Check: {tool} / {role}",
                    description=(
                        f"Execute manually: {query}\n\n"
                        f"This query identifies {org_name} {role} staff publicly disclosing "
                        f"use of '{tool}' on LinkedIn, revealing AI tools in use and "
                        f"creating social engineering attack surface."
                    ),
                    severity="info",
                    tippss=["Trust", "Identity", "Security"],
                    remediation="Train staff on responsible AI tool disclosure in public profiles.",
                )
                findings.append(finding)

            self._throttle()

        return findings

    def _job_posting_tech_disclosure(self) -> List[Dict[str, Any]]:
        """Analyze job postings for technology stack disclosure."""
        findings = []
        org_name = self.target or self.domain

        job_queries = [
            (f'"{org_name}" job hiring "LLM" OR "GPT" OR "AI" "Epic" OR "Cerner" OR "EHR" "healthcare"',
             "EHR + AI Stack Disclosure in Job Posting"),
            (f'"{org_name}" "machine learning engineer" OR "AI engineer" "healthcare" OR "clinical"',
             "AI Engineering Role Revealing Tech Stack"),
            (f'"{org_name}" "prompt engineer" OR "AI developer" "clinical" OR "patient"',
             "Prompt Engineering Role — Clinical AI Context"),
            (f'"{org_name}" "Azure OpenAI" OR "AWS Bedrock" OR "Google Vertex" "healthcare"',
             "Cloud AI Platform Disclosure in Hiring"),
        ]

        for query, title in job_queries:
            self._log(f"Job posting search: {title}")
            results = self._google_search(query) if (self.api_key and self.cx) else []

            if results:
                for item in results[:2]:
                    finding = self._make_finding(
                        source="Job Posting OSINT",
                        query=query,
                        title=title,
                        description=(
                            f"Job posting associated with {org_name} reveals AI technology "
                            f"stack details. Source: {item.get('title', '')}. "
                            f"Snippet: {item.get('snippet', '')}. "
                            f"Job postings routinely disclose specific AI platforms, cloud "
                            f"providers, EHR versions, and integration requirements, providing "
                            f"adversarial reconnaissance value equivalent to a technology inventory."
                        ),
                        severity="low",
                        tippss=["Trust", "Security"],
                        remediation=(
                            "Review job postings for specific technology disclosure. "
                            "Use generic descriptions (e.g., 'enterprise AI platform') "
                            "rather than product names where possible. "
                            "HR should review AI-related job postings with security team."
                        ),
                        url=item.get("link", ""),
                        raw={"query": query}
                    )
                    findings.append(finding)
            else:
                finding = self._make_finding(
                    source="Job Posting OSINT Query (configure Google CSE to automate)",
                    query=query,
                    title=f"[MANUAL] {title}",
                    description=f"Execute manually in Google: {query}",
                    severity="info",
                    tippss=["Trust", "Security"],
                    remediation="Minimize technology stack disclosure in job postings.",
                )
                findings.append(finding)

            self._throttle()

        return findings

    def _conference_presentation_exposure(self) -> List[Dict[str, Any]]:
        """Search for conference presentations revealing AI architecture."""
        org_name = self.target or self.domain
        findings = []

        conf_queries = [
            (f'"{org_name}" "HIMSS" OR "RSNA" OR "AHA" "AI" OR "LLM" OR "machine learning" filetype:pdf OR filetype:pptx',
             "Conference Presentation Revealing AI Architecture"),
            (f'"{org_name}" "case study" "AI implementation" OR "AI deployment" "healthcare"',
             "Public Case Study Disclosing AI Implementation"),
        ]

        for query, title in conf_queries:
            self._log(f"Conference search: {title}")
            results = self._google_search(query) if (self.api_key and self.cx) else []

            if results:
                for item in results[:2]:
                    finding = self._make_finding(
                        source="Conference Presentation OSINT",
                        query=query,
                        title=title,
                        description=(
                            f"Public conference or case study content from {org_name} "
                            f"appears to discuss AI implementation details. "
                            f"Source: {item.get('title', '')}. "
                            f"Conference presentations often disclose system architecture, "
                            f"vendor names, implementation challenges, and data workflows "
                            f"that provide detailed attack surface intelligence."
                        ),
                        severity="medium",
                        tippss=["Trust", "Security"],
                        remediation=(
                            "Review all conference presentations and case studies before publication "
                            "for sensitive architecture details. Obtain security review sign-off "
                            "for external presentations involving AI systems."
                        ),
                        url=item.get("link", ""),
                        raw={"query": query}
                    )
                    findings.append(finding)
            else:
                finding = self._make_finding(
                    source="Conference OSINT Query (configure Google CSE to automate)",
                    query=query,
                    title=f"[MANUAL] {title}",
                    description=f"Execute manually: {query}",
                    severity="info",
                    tippss=["Trust", "Security"],
                    remediation="Review external presentations for AI architecture disclosure.",
                )
                findings.append(finding)

            self._throttle()

        return findings

    def _academic_publication_disclosure(self) -> List[Dict[str, Any]]:
        """Search for academic publications disclosing AI systems."""
        org_name = self.target or self.domain
        query = f'site:pubmed.ncbi.nlm.nih.gov OR site:arxiv.org "{org_name}" "AI" OR "machine learning" OR "deep learning" "clinical" OR "patient"'

        self._log("Academic publication search...")
        results = self._google_search(query) if (self.api_key and self.cx) else []

        findings = []
        if results:
            for item in results[:3]:
                finding = self._make_finding(
                    source="Academic Publication OSINT",
                    query=query,
                    title="Academic Publication Disclosing Clinical AI System",
                    description=(
                        f"Academic publication associated with {org_name} discloses "
                        f"clinical AI system details. "
                        f"Title: {item.get('title', '')}. "
                        f"Publications frequently disclose model architecture, training data "
                        f"sources, performance characteristics, and system limitations, "
                        f"all of which provide adversarial reconnaissance value."
                    ),
                    severity="low",
                    tippss=["Trust", "Security"],
                    remediation=(
                        "Review publications for sensitive system details before submission. "
                        "Avoid disclosing specific model vulnerabilities or data source details."
                    ),
                    url=item.get("link", ""),
                    raw={"query": query}
                )
                findings.append(finding)
        else:
            findings.append(self._make_finding(
                source="Academic OSINT Query",
                query=query,
                title="[MANUAL] Academic Publication Disclosure Check",
                description=f"Execute manually: {query}",
                severity="info",
                tippss=["Trust", "Security"],
                remediation="Review publications for AI system disclosure.",
            ))

        return findings

    def _social_engineering_risk_summary(self) -> List[Dict[str, Any]]:
        """Return social engineering risk framework assessment."""
        finding = self._make_finding(
            source="Social Engineering Risk Assessment",
            query=f"Social engineering surface: {self.target or self.domain}",
            title="Healthcare AI Social Engineering Attack Surface Summary",
            description=(
                f"Healthcare organizations with AI deployments face elevated social engineering "
                f"risk due to: (1) Clinical staff regularly disclosing AI tool usage on "
                f"professional networks, creating impersonation targets; (2) IT and informatics "
                f"staff publishing technical details of AI integrations in job postings and "
                f"conference presentations; (3) Vendor relationships disclosed in press releases "
                f"enabling vendor impersonation attacks; (4) AI chatbot interfaces providing "
                f"reconnaissance opportunities through interaction; (5) AI-powered phishing "
                f"that leverages knowledge of specific AI tools in use to craft more convincing "
                f"pretexts targeting clinical staff."
            ),
            severity="medium",
            tippss=["Trust", "Identity", "Security"],
            remediation=(
                "Implement AI security awareness training for all clinical staff. "
                "Develop AI tool disclosure policy covering social media and publications. "
                "Conduct simulated AI-themed phishing exercises. "
                "Establish vendor communication verification procedures. "
                "Train help desk on AI tool impersonation scenarios."
            ),
        )
        return [finding]

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
