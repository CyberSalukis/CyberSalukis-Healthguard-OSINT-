"""
IEEE CyberSalukis HealthGuard OSINT
Module: llm_recon.py — LLM Vulnerability Surface Reconnaissance

Discovers LLM-specific attack surface including exposed API endpoints,
prompt injection vectors, model fingerprinting signals, jailbreak research
exposure, and AI governance weaknesses in healthcare environments.
"""

import re
import requests
import yaml
from pathlib import Path
from typing import List, Dict, Any
from .base import BaseModule


class LLMRecon(BaseModule):
    """
    LLM-specific OSINT reconnaissance module.

    Targets:
    - Exposed LLM API endpoints (OpenAI-compatible, Ollama, vLLM, etc.)
    - Prompt injection surface indicators
    - Model fingerprinting via public disclosures
    - API key exposure in code repositories
    - AI governance and policy documentation
    - Jailbreak and red-team research tied to target
    """

    MODULE_NAME = "llm-recon"
    MODULE_LABEL = "LLM Vulnerability Recon"

    # Common LLM API endpoint patterns for optional authorized HTTP checks
    LLM_ENDPOINT_PATHS = [
        "/v1/chat/completions",
        "/v1/completions",
        "/v1/models",
        "/api/generate",        # Ollama
        "/api/chat",            # Ollama
        "/generate",            # vLLM / LM Studio
        "/v1/engines",
        "/openai/deployments",  # Azure OpenAI
        "/predict",             # BentoML / generic
        "/inference",
        "/api/v1/chat",
        "/chat",
    ]

    # Headers that indicate LLM services
    LLM_HEADERS = [
        "x-openai-organization",
        "x-ratelimit-limit-requests",
        "openai-organization",
        "x-request-id",
    ]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.queries = self._load_query_library()

    def _load_query_library(self) -> List[Dict]:
        """Load LLM-specific queries from YAML library."""
        queries = []
        query_file = Path("queries/dorks/llm_endpoints.yaml")
        if query_file.exists():
            try:
                with open(query_file) as f:
                    data = yaml.safe_load(f) or {}
                queries = data.get("queries", [])
            except Exception as e:
                self._log(f"Could not load LLM query library: {e}", "warn")

        return queries or self._builtin_queries()

    def run(self) -> List[Dict[str, Any]]:
        """Execute LLM recon and return findings."""
        findings = []

        passive_only = self.config.get("scope", {}).get("passive_only", True)
        if self.domain and not passive_only:
            findings.extend(self._probe_llm_endpoints())
        elif self.domain:
            self._log("Passive-only mode enabled — skipping direct HTTP endpoint checks")

        findings.extend(self._llm_documentation_findings())
        findings.extend(self._governance_gap_indicators())

        return findings

    def _probe_llm_endpoints(self) -> List[Dict[str, Any]]:
        """
        Perform optional low-impact HTTP checks for known LLM API endpoint paths.
        This mode only checks HTTP response codes and headers; it does not send prompts,
        payloads, exploit strings, or authentication attempts. Use only when authorized.
        """
        findings = []
        base_urls = [
            f"https://{self.domain}",
            f"https://api.{self.domain}",
            f"https://ai.{self.domain}",
            f"https://llm.{self.domain}",
            f"https://chat.{self.domain}",
        ]

        for base in base_urls:
            for path in self.LLM_ENDPOINT_PATHS:
                url = base + path
                self._log(f"Checking endpoint path: {url}")
                result = self._http_endpoint_check(url)

                if result["accessible"]:
                    severity = "critical" if result["status"] == 200 else "high"
                    finding = self._make_finding(
                        source="Authorized HTTP Endpoint Check",
                        query=f"GET {url}",
                        title=f"Potentially Exposed LLM Endpoint: {path}",
                        description=(
                            f"LLM API endpoint path {path} returned HTTP {result['status']} "
                            f"on {base}. This may indicate an exposed language model API "
                            f"accessible without authentication. In healthcare environments, "
                            f"exposed LLM endpoints enable unauthorized model access, prompt "
                            f"injection attacks, data extraction, and jailbreaking."
                        ),
                        severity=severity,
                        tippss=["Identity", "Protection", "Safety", "Security"],
                        remediation=(
                            "Immediately restrict LLM API endpoints behind authentication. "
                            "Implement API key rotation. Apply IP allowlisting. "
                            "Audit endpoint for unauthorized usage logs."
                        ),
                        url=url,
                        raw=result
                    )
                    findings.append(finding)

                self._throttle()

        return findings

    def _http_endpoint_check(self, url: str) -> Dict:
        """
        Low-impact HTTP endpoint check: only checks response code and headers.
        Does not send prompts, payloads, exploit code, or credential guesses.
        """
        try:
            resp = requests.get(
                url,
                timeout=8,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (Security Assessment; Authorized)"}
            )
            llm_headers_found = [
                h for h in self.LLM_HEADERS
                if h in {k.lower() for k in resp.headers.keys()}
            ]
            return {
                "accessible": resp.status_code in (200, 401, 403, 405, 422),
                "status": resp.status_code,
                "llm_headers": llm_headers_found,
                "content_type": resp.headers.get("content-type", ""),
                "server": resp.headers.get("server", ""),
            }
        except Exception:
            return {"accessible": False, "status": None, "llm_headers": [], "content_type": "", "server": ""}

    def _llm_documentation_findings(self) -> List[Dict[str, Any]]:
        """
        Return documented LLM vulnerability categories relevant to healthcare
        as informational findings that guide manual investigation.
        These represent the OSINT research baseline for the assessment.
        """
        findings = []
        for query_def in self._builtin_queries():
            finding = self._make_finding(
                source="LLM Vulnerability Research Library",
                query=query_def["query"].replace("{domain}", self.domain).replace("{target}", self.target),
                title=query_def["title"],
                description=query_def["description"],
                severity=query_def.get("severity", "medium"),
                tippss=query_def.get("tippss", ["Security"]),
                remediation=query_def.get("remediation", ""),
                url="",
            )
            findings.append(finding)
        return findings

    def _governance_gap_indicators(self) -> List[Dict[str, Any]]:
        """
        OSINT-detectable AI governance gap indicators for healthcare organizations.
        These are signals of weak AI security governance visible from public sources.
        """
        indicators = [
            {
                "title": "No Public AI Use Policy Detected",
                "description": (
                    f"A search of {self.domain} found no publicly accessible AI acceptable use "
                    f"policy, AI governance framework, or AI risk management documentation. "
                    f"Absence of public governance signals may indicate immature AI security "
                    f"posture or ungoverned AI deployments. Under HIPAA and emerging AI "
                    f"regulations, healthcare organizations are expected to demonstrate "
                    f"governance over AI systems that process PHI."
                ),
                "severity": "medium",
                "tippss": ["Trust", "Security"],
                "remediation": (
                    "Develop and publish an AI acceptable use policy. Document AI governance "
                    "framework aligned with NIST AI RMF and applicable healthcare regulations."
                )
            },
            {
                "title": "AI Vendor Relationship Visible in Public Domain",
                "description": (
                    f"Public sources associated with {self.target} reveal AI vendor "
                    f"relationships. Vendor identity enables targeted supply chain reconnaissance, "
                    f"including searching for known vulnerabilities in the vendor's AI products, "
                    f"monitoring vendor breach disclosures, and identifying shared infrastructure."
                ),
                "severity": "low",
                "tippss": ["Trust", "Security"],
                "remediation": (
                    "Minimize public disclosure of specific AI vendor names. Monitor vendor "
                    "security advisories. Implement vendor security assessment program for AI tools."
                )
            },
        ]

        findings = []
        for ind in indicators:
            finding = self._make_finding(
                source="AI Governance OSINT Assessment",
                query=f"AI governance policy: {self.domain}",
                title=ind["title"],
                description=ind["description"],
                severity=ind["severity"],
                tippss=ind["tippss"],
                remediation=ind["remediation"],
            )
            findings.append(finding)
        return findings

    def _builtin_queries(self) -> List[Dict]:
        """Built-in LLM vulnerability OSINT query library."""
        return [
            {
                "title": "Prompt Injection Surface — Public AI Chat Interface",
                "query": 'site:{domain} "chat" OR "assistant" OR "ask AI" "healthcare" OR "clinical"',
                "description": (
                    "Public-facing AI chat interfaces in healthcare contexts are high-risk "
                    "prompt injection targets. If the AI assistant has access to patient data, "
                    "scheduling systems, or clinical decision support, successful injection could "
                    "extract PHI, manipulate clinical guidance, or exfiltrate system context."
                ),
                "severity": "high",
                "tippss": ["Trust", "Identity", "Safety", "Security"],
                "remediation": (
                    "Implement prompt injection defenses (input validation, output filtering). "
                    "Isolate AI chat interfaces from sensitive data systems. Implement "
                    "content moderation and anomaly detection on AI interface inputs."
                )
            },
            {
                "title": "LLM API Key Exposure — Healthcare Application Context",
                "query": 'site:github.com "{target}" "OPENAI_API_KEY" OR "ANTHROPIC_API_KEY" OR "AZURE_OPENAI_KEY"',
                "description": (
                    "API keys for LLM providers exposed in public GitHub repositories enable "
                    "unauthorized model access at the organization's expense, and may allow "
                    "adversaries to use the organization's AI context and fine-tuned models."
                ),
                "severity": "critical",
                "tippss": ["Identity", "Security"],
                "remediation": (
                    "Immediately rotate all exposed API keys. Implement GitHub secret scanning. "
                    "Use pre-commit hooks. Store secrets in vault solutions (HashiCorp Vault, "
                    "AWS Secrets Manager). Audit all repositories for historical key exposure."
                )
            },
            {
                "title": "Model Fingerprinting — Public Disclosure of LLM in Use",
                "query": '"{target}" "GPT-4" OR "Claude" OR "Gemini" OR "Llama" OR "Mistral" "healthcare" OR "clinical" "deployed" OR "using" OR "integrated"',
                "description": (
                    "Public disclosure of specific LLM models in use enables targeted "
                    "adversarial attacks using known model-specific jailbreaks, prompt injection "
                    "patterns, and vulnerabilities. Model identity also reveals capability and "
                    "data access that may be exploitable."
                ),
                "severity": "medium",
                "tippss": ["Trust", "Security"],
                "remediation": (
                    "Minimize public disclosure of specific AI model identities. Use generic "
                    "descriptions in public communications. Monitor for unauthorized disclosure."
                )
            },
            {
                "title": "RAG System Data Source Exposure",
                "query": 'site:{domain} "knowledge base" OR "document store" OR "vector database" "patient" OR "clinical" OR "EHR"',
                "description": (
                    "Retrieval Augmented Generation (RAG) systems used in healthcare AI often "
                    "connect to document stores containing patient records, clinical protocols, "
                    "or sensitive institutional knowledge. Exposed RAG data source references "
                    "reveal attack vectors for data extraction through the AI interface."
                ),
                "severity": "high",
                "tippss": ["Privacy", "Protection", "Security"],
                "remediation": (
                    "Restrict RAG data source references from public documentation. Implement "
                    "access controls on vector databases. Monitor AI query logs for "
                    "data extraction patterns."
                )
            },
            {
                "title": "Agentic AI Capability Disclosure",
                "query": '"{target}" "AI agent" OR "agentic AI" OR "autonomous AI" "healthcare" OR "patient" OR "clinical"',
                "description": (
                    "Public disclosure of agentic AI deployments (AI systems with tool use, "
                    "autonomous action capability, or system access) in healthcare reveals "
                    "high-value attack targets. Compromised AI agents with EHR, scheduling, "
                    "or communication access represent critical risk to patient safety and "
                    "data privacy."
                ),
                "severity": "high",
                "tippss": ["Trust", "Identity", "Safety", "Security"],
                "remediation": (
                    "Limit public disclosure of agentic AI capabilities and system access. "
                    "Implement least-privilege tool access for AI agents. Deploy agent "
                    "monitoring and anomaly detection."
                )
            },
        ]
