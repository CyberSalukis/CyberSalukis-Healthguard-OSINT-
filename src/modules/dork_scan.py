"""
IEEE CyberSalukis HealthGuard OSINT
Module: dork_scan.py — Google Dork Scanner

Executes healthcare AI-specific Google dorks to discover externally visible
attack surface including exposed endpoints, configuration files, APIs,
and sensitive documentation.
"""

import os
import yaml
import requests
from pathlib import Path
from typing import List, Dict, Any
from .base import BaseModule


class DorkScanner(BaseModule):
    """
    Google Custom Search API-based dork scanner.
    Executes a curated library of healthcare AI-specific dorks
    and returns structured findings.

    If no Google API key is configured, runs in DRY-RUN mode,
    returning the dork library itself as documentation output.
    """

    MODULE_NAME = "dork-scan"
    MODULE_LABEL = "Google Dork Scanner"

    GOOGLE_CSE_URL  = "https://www.googleapis.com/customsearch/v1"
    BING_SEARCH_URL  = "https://api.bing.microsoft.com/v7.0/search"
    BRAVE_SEARCH_URL = "https://api.search.brave.com/res/v1/web/search"
    MOJEEK_SEARCH_URL = "https://www.mojeek.com/search"

    ENGINE_LABELS = {
        "google": "Google Custom Search",
        "bing":   "Bing Web Search (Microsoft)",
        "brave":  "Brave Search (Independent Index)",
        "mojeek": "Mojeek Search (Independent Index)",
    }

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Google CSE
        self.google_api_key = self.config.get("api_keys", {}).get("google_cse_api_key", "")
        self.google_cx      = self.config.get("api_keys", {}).get("google_cse_cx", "")
        # Bing Web Search API
        self.bing_api_key   = self.config.get("api_keys", {}).get("bing_api_key", "")
        # Brave Search API
        self.brave_api_key  = self.config.get("api_keys", {}).get("brave_api_key", "")
        # Mojeek Search API
        self.mojeek_api_key = self.config.get("api_keys", {}).get("mojeek_api_key", "")
        # Legacy alias for any internal references
        self.api_key = self.google_api_key
        self.cx      = self.google_cx
        self.max_results = self.config.get("scope", {}).get("max_results_per_query", 10)
        self.dork_library = self._load_dork_library()

    def _load_dork_library(self) -> List[Dict]:
        """Load dorks from YAML query library files."""
        dorks = []
        dork_dir = Path("queries/dorks")
        if dork_dir.exists():
            for yaml_file in dork_dir.glob("*.yaml"):
                try:
                    with open(yaml_file) as f:
                        data = yaml.safe_load(f) or {}
                    dorks.extend(data.get("dorks", []))
                except Exception as e:
                    self._log(f"Could not load {yaml_file}: {e}", "warn")

        # Fallback: use built-in dork library if no YAML files present
        if not dorks:
            dorks = self._builtin_dorks()

        # Filter to target-relevant dorks
        if self.domain:
            for d in dorks:
                if "{domain}" in d.get("query", ""):
                    d["query"] = d["query"].replace("{domain}", self.domain)
        if self.target:
            for d in dorks:
                if "{target}" in d.get("query", ""):
                    d["query"] = d["query"].replace("{target}", self.target)

        return dorks

    def run(self) -> List[Dict[str, Any]]:
        """
        Execute dork queries across all configured search engines.
        Runs Google, Bing, Brave, and Mojeek in sequence.
        Falls back to DRY-RUN mode if no engines are configured.
        """
        findings = []

        # Determine which engines are configured
        engines = []
        if self.google_api_key and self.google_cx:
            engines.append("google")
        if self.bing_api_key:
            engines.append("bing")
        if self.brave_api_key:
            engines.append("brave")
        if self.mojeek_api_key:
            engines.append("mojeek")

        if not engines:
            self._log("No search engine API keys configured — running in DRY-RUN mode", "warn")
            return self._dry_run_findings()

        self._log(f"Active search engines: {', '.join(engines)}")

        for dork in self.dork_library:
            query = dork.get("query", "")
            if not query:
                continue

            for engine in engines:
                self._log(f"[{engine.upper()}] Querying: {query[:70]}...")
                results = self._execute_query(engine, query)

                for item in results:
                    finding = self._make_finding(
                        source=self.ENGINE_LABELS.get(engine, engine),
                        query=query,
                        title=f"[{engine.upper()}] {dork.get('title', item.get('title', 'Dork Result'))}",
                        description=(
                            f"{dork.get('description', '')}\n\n"
                            f"Search Engine: {self.ENGINE_LABELS.get(engine, engine)}\n"
                            f"Result: {item.get('title', '')}\n"
                            f"Snippet: {item.get('snippet', '')}"
                        ).strip(),
                        severity=dork.get("severity", "medium"),
                        tippss=dork.get("tippss", ["Security"]),
                        remediation=dork.get("remediation", "Review and restrict external access to this resource."),
                        url=item.get("link", item.get("url", "")),
                        raw={**item, "engine": engine}
                    )
                    findings.append(finding)

                self._throttle()

        return findings

    def _execute_query(self, engine: str, query: str) -> List[Dict]:
        """Dispatch query to the appropriate search engine."""
        dispatch = {
            "google": self._execute_google,
            "bing":   self._execute_bing,
            "brave":  self._execute_brave,
            "mojeek": self._execute_mojeek,
        }
        fn = dispatch.get(engine)
        if fn:
            return fn(query)
        return []

    def _execute_dork(self, query: str) -> List[Dict]:
        """Legacy method — delegates to Google. Kept for backward compatibility."""
        return self._execute_google(query)

    def _execute_google(self, query: str) -> List[Dict]:
        """Execute dork via Google Custom Search API."""
        params = {
            "key": self.google_api_key,
            "cx":  self.google_cx,
            "q":   query,
            "num": min(self.max_results, 10),
        }
        try:
            resp = requests.get(self.GOOGLE_CSE_URL, params=params, timeout=15)
            resp.raise_for_status()
            return resp.json().get("items", [])
        except requests.exceptions.HTTPError as e:
            if hasattr(e, 'response') and e.response.status_code == 429:
                self._log("Google rate limit hit — pausing 60s", "warn")
                import time; time.sleep(60)
            else:
                self._log(f"Google HTTP error: {e}", "error")
        except Exception as e:
            self._log(f"Google request error: {e}", "error")
        return []

    def _execute_bing(self, query: str) -> List[Dict]:
        """
        Execute dork via Bing Web Search API v7.
        Free tier: 1,000 queries/month via Azure Cognitive Services.
        Sign up: https://azure.microsoft.com/en-us/services/cognitive-services/bing-web-search-api/
        """
        headers = {
            "Ocp-Apim-Subscription-Key": self.bing_api_key,
            "Accept": "application/json"
        }
        params = {
            "q":     query,
            "count": min(self.max_results, 50),
            "mkt":   "en-US",
        }
        try:
            resp = requests.get(self.BING_SEARCH_URL, headers=headers, params=params, timeout=15)
            resp.raise_for_status()
            data = resp.json()
            raw_results = data.get("webPages", {}).get("value", [])
            # Normalize to common schema
            return [
                {
                    "title":   r.get("name", ""),
                    "snippet": r.get("snippet", ""),
                    "link":    r.get("url", ""),
                    "url":     r.get("url", ""),
                }
                for r in raw_results
            ]
        except requests.exceptions.HTTPError as e:
            if hasattr(e, 'response') and e.response.status_code == 429:
                self._log("Bing rate limit hit — pausing 30s", "warn")
                import time; time.sleep(30)
            else:
                self._log(f"Bing HTTP error: {e}", "error")
        except Exception as e:
            self._log(f"Bing request error: {e}", "error")
        return []

    def _execute_brave(self, query: str) -> List[Dict]:
        """
        Execute dork via Brave Search API.
        Fully independent index — no Google or Bing dependency.
        Free tier: 2,000 queries/month.
        Sign up: https://brave.com/search/api/
        """
        headers = {
            "Accept":               "application/json",
            "Accept-Encoding":      "gzip",
            "X-Subscription-Token": self.brave_api_key,
        }
        params = {
            "q":     query,
            "count": min(self.max_results, 20),
        }
        try:
            resp = requests.get(self.BRAVE_SEARCH_URL, headers=headers, params=params, timeout=15)
            resp.raise_for_status()
            data = resp.json()
            raw_results = data.get("web", {}).get("results", [])
            # Normalize to common schema
            return [
                {
                    "title":   r.get("title", ""),
                    "snippet": r.get("description", ""),
                    "link":    r.get("url", ""),
                    "url":     r.get("url", ""),
                }
                for r in raw_results
            ]
        except requests.exceptions.HTTPError as e:
            if hasattr(e, 'response') and e.response.status_code == 429:
                self._log("Brave rate limit hit — pausing 30s", "warn")
                import time; time.sleep(30)
            else:
                self._log(f"Brave HTTP error: {e}", "error")
        except Exception as e:
            self._log(f"Brave request error: {e}", "error")
        return []

    def _execute_mojeek(self, query: str) -> List[Dict]:
        """
        Execute dork via Mojeek Search API.
        Privacy-focused, fully independent crawler — no Big Tech index.
        Free API tier available.
        Sign up: https://www.mojeek.com/services/search/web-search-api/
        """
        params = {
            "q":   query,
            "api_key": self.mojeek_api_key,
            "fmt": "json",
            "n":   min(self.max_results, 10),
        }
        try:
            resp = requests.get(self.MOJEEK_SEARCH_URL, params=params, timeout=15)
            resp.raise_for_status()
            data = resp.json()
            raw_results = data.get("response", {}).get("results", [])
            # Normalize to common schema
            return [
                {
                    "title":   r.get("title", ""),
                    "snippet": r.get("desc", ""),
                    "link":    r.get("url", ""),
                    "url":     r.get("url", ""),
                }
                for r in raw_results
            ]
        except requests.exceptions.HTTPError as e:
            if hasattr(e, 'response') and e.response.status_code == 429:
                self._log("Mojeek rate limit hit — pausing 30s", "warn")
                import time; time.sleep(30)
            else:
                self._log(f"Mojeek HTTP error: {e}", "error")
        except Exception as e:
            self._log(f"Mojeek request error: {e}", "error")
        return []

    def _dry_run_findings(self) -> List[Dict[str, Any]]:
        """
        In DRY-RUN mode (no API key), return the dork library as
        informational findings so the output is still useful.
        """
        findings = []
        for dork in self.dork_library:
            finding = self._make_finding(
                source="Dork Library (DRY-RUN — configure API key to execute)",
                query=dork.get("query", ""),
                title=f"[DRY-RUN] {dork.get('title', 'Healthcare AI Dork')}",
                description=(
                    f"{dork.get('description', '')}\n\n"
                    f"Dry-run only: this is a query-library entry, not a discovered exposure. "
                    f"Intended severity if confirmed by search results: {dork.get('severity', 'info')}.\n"
                    f"Configure GOOGLE_CSE_API_KEY and GOOGLE_CSE_CX to execute this dork automatically."
                ),
                severity="info",
                tippss=dork.get("tippss", ["Security"]),
                remediation=dork.get("remediation", ""),
                url="",
                raw={"dry_run": True, "intended_severity": dork.get("severity", "info")},
            )
            findings.append(finding)
        return findings

    def _builtin_dorks(self) -> List[Dict]:
        """
        Built-in healthcare AI dork library.
        These dorks are also maintained in queries/dorks/*.yaml for community extension.
        """
        return [
            # ── LLM / AI Endpoint Exposure ────────────────────────────────────
            {
                "title": "Exposed LLM API Endpoint (OpenAI-compatible)",
                "query": 'site:{domain} inurl:"/v1/chat/completions" OR inurl:"/v1/completions"',
                "description": "Searches for publicly exposed OpenAI-compatible LLM API endpoints on target domain. Exposed endpoints may allow unauthorized model access, prompt injection, or data extraction.",
                "severity": "critical",
                "tippss": ["Identity", "Protection", "Security"],
                "remediation": "Immediately restrict LLM API endpoints behind authentication. Rotate any exposed API keys. Implement IP allowlisting for API access."
            },
            {
                "title": "Exposed AI Model Configuration File",
                "query": 'site:{domain} filetype:yaml OR filetype:json "model" "api_key" OR "openai" OR "anthropic" OR "llm"',
                "description": "Searches for publicly accessible AI model configuration files that may contain API keys, model names, endpoint URLs, or system prompt content.",
                "severity": "critical",
                "tippss": ["Identity", "Privacy", "Security"],
                "remediation": "Remove configuration files from public-facing directories. Use environment variables for API keys. Add .yaml and .json to .gitignore."
            },
            {
                "title": "Exposed Gradio / Streamlit AI Demo Interface",
                "query": 'site:{domain} "Running on" "gradio" OR "streamlit" "healthcare" OR "clinical" OR "patient"',
                "description": "Gradio and Streamlit are commonly used to deploy AI demos rapidly. Healthcare-context AI demos may expose patient data, model parameters, or provide unauthenticated LLM access.",
                "severity": "high",
                "tippss": ["Identity", "Privacy", "Protection"],
                "remediation": "Disable public access to AI demo interfaces. Require authentication before deployment. Remove healthcare data from demo environments."
            },
            {
                "title": "Exposed Jupyter Notebook with AI/ML Content",
                "query": 'site:{domain} inurl:jupyter OR inurl:notebook "import openai" OR "import transformers" OR "patient" OR "PHI"',
                "description": "Publicly accessible Jupyter notebooks may contain AI model code, training data references, API keys, patient data samples, or sensitive clinical logic.",
                "severity": "critical",
                "tippss": ["Identity", "Privacy", "Protection", "Security"],
                "remediation": "Immediately restrict Jupyter server access. Audit notebooks for sensitive data. Require authentication for all notebook servers."
            },
            # ── PHI / Data Leakage ────────────────────────────────────────────
            {
                "title": "PHI in Public-Facing Document (Healthcare Context)",
                "query": 'site:{domain} filetype:pdf OR filetype:xlsx "patient" "date of birth" OR "SSN" OR "medical record"',
                "description": "Searches for publicly accessible documents that may contain protected health information (PHI) including patient names, dates of birth, SSNs, or medical record numbers.",
                "severity": "critical",
                "tippss": ["Privacy", "Protection", "Security"],
                "remediation": "Immediately remove documents containing PHI from public access. Audit all public-facing document repositories. Implement DLP controls."
            },
            {
                "title": "AI Training Data Exposure — Healthcare Dataset",
                "query": 'site:{domain} "training data" OR "dataset" "patient" OR "clinical" OR "EHR" filetype:csv OR filetype:json',
                "description": "Searches for publicly accessible healthcare AI training datasets that may contain de-identified or re-identifiable patient data.",
                "severity": "high",
                "tippss": ["Privacy", "Protection"],
                "remediation": "Remove training datasets from public access. Verify de-identification compliance. Implement access controls on data storage."
            },
            # ── AI Vendor / Procurement Disclosure ───────────────────────────
            {
                "title": "AI Vendor Procurement Record or Contract",
                "query": '"{target}" "artificial intelligence" OR "machine learning" OR "LLM" "vendor" OR "contract" OR "RFP" filetype:pdf',
                "description": "Searches for publicly accessible procurement records, RFPs, or contracts disclosing AI vendor relationships, which reveal supply chain dependencies and potential attack paths.",
                "severity": "medium",
                "tippss": ["Trust", "Security"],
                "remediation": "Review public procurement disclosure policies. Minimize vendor detail in publicly accessible documents. Monitor for unauthorized disclosure."
            },
            {
                "title": "AI System Architecture Documentation Exposure",
                "query": 'site:{domain} "AI" OR "LLM" OR "machine learning" filetype:pdf "architecture" OR "integration" OR "API" OR "workflow"',
                "description": "Publicly accessible architecture documentation reveals AI system design, integration points, and data flows that inform targeted attack planning.",
                "severity": "medium",
                "tippss": ["Trust", "Protection", "Security"],
                "remediation": "Restrict system architecture documentation to internal access only. Remove detailed integration diagrams from public documentation."
            },
            # ── GitHub / Code Repository ──────────────────────────────────────
            {
                "title": "GitHub Repository — AI Code with Healthcare Context",
                "query": 'site:github.com "{target}" "openai" OR "anthropic" OR "langchain" "healthcare" OR "clinical" OR "EHR" OR "HIPAA"',
                "description": "Searches GitHub for repositories associated with the target organization containing AI/LLM code in a healthcare context, which may reveal internal tools, API usage, or system architecture.",
                "severity": "medium",
                "tippss": ["Identity", "Security"],
                "remediation": "Audit GitHub organization repositories for sensitive content. Remove API keys and internal details. Set sensitive repositories to private."
            },
            {
                "title": "Exposed API Keys in GitHub — Healthcare AI",
                "query": 'site:github.com "{target}" "OPENAI_API_KEY" OR "anthropic" OR "AZURE_OPENAI" filename:.env OR filename:config',
                "description": "Searches GitHub for accidentally committed API keys associated with the target organization's AI systems.",
                "severity": "critical",
                "tippss": ["Identity", "Security"],
                "remediation": "Immediately rotate all exposed API keys. Implement pre-commit hooks to prevent secret commits. Use GitHub secret scanning alerts."
            },
            # ── IoT / Connected Medical Devices ──────────────────────────────
            {
                "title": "Exposed Medical Device Management Interface",
                "query": 'site:{domain} inurl:admin OR inurl:management "device" OR "monitor" OR "infusion" OR "imaging"',
                "description": "Searches for publicly accessible management interfaces for medical devices or AI-connected monitoring systems.",
                "severity": "high",
                "tippss": ["Protection", "Safety", "Security"],
                "remediation": "Restrict device management interfaces to internal networks. Implement authentication on all administrative interfaces. Conduct network segmentation audit."
            },
            # ── Employee / Personnel Disclosure ──────────────────────────────
            {
                "title": "Employee Disclosure of AI Tools on LinkedIn",
                "query": 'site:linkedin.com "{target}" "ChatGPT" OR "Copilot" OR "Epic AI" OR "AI assistant" "nurse" OR "physician" OR "clinician"',
                "description": "LinkedIn profiles of healthcare employees mentioning AI tools reveal which AI systems are in use, providing intelligence for targeted social engineering or AI-specific attacks.",
                "severity": "low",
                "tippss": ["Trust", "Identity", "Security"],
                "remediation": "Train staff on responsible disclosure of AI tool usage on public platforms. Include AI tool references in acceptable use policy."
            },
            {
                "title": "Job Posting Revealing AI System Details",
                "query": '"{target}" "job" OR "hiring" "LLM" OR "AI" OR "machine learning" "Epic" OR "Cerner" OR "Azure" OR "AWS" "healthcare"',
                "description": "Job postings routinely reveal specific AI platforms, cloud providers, EHR systems, and technology stacks in use, providing adversarial reconnaissance value.",
                "severity": "low",
                "tippss": ["Trust", "Security"],
                "remediation": "Review job postings for excessive technology disclosure. Use generic technology descriptions rather than specific product names where possible."
            },
            # ── Prompt Injection / Jailbreak Surface ─────────────────────────
            {
                "title": "Public System Prompt or AI Instruction Disclosure",
                "query": 'site:{domain} "system prompt" OR "you are an AI" OR "you are a helpful assistant" "healthcare" OR "clinical" OR "patient"',
                "description": "Publicly accessible AI system prompts reveal the behavioral instructions and context given to AI assistants, enabling targeted prompt injection and jailbreak attacks.",
                "severity": "high",
                "tippss": ["Trust", "Identity", "Safety", "Security"],
                "remediation": "Remove system prompt content from public-facing interfaces. Implement prompt injection defenses. Treat system prompts as sensitive configuration data."
            },
            # ── Cloud / Infrastructure ────────────────────────────────────────
            {
                "title": "Exposed Cloud Storage Bucket — AI/Healthcare Content",
                "query": 'site:s3.amazonaws.com OR site:storage.googleapis.com OR site:blob.core.windows.net "{target}" "patient" OR "clinical" OR "model" OR "AI"',
                "description": "Searches for publicly accessible cloud storage buckets associated with the target that may contain healthcare AI models, training data, or patient data.",
                "severity": "critical",
                "tippss": ["Privacy", "Protection", "Security"],
                "remediation": "Audit all cloud storage bucket permissions. Remove public access from all buckets containing healthcare or AI data. Implement cloud security posture management (CSPM)."
            },
            {
                "title": "Exposed AI Model Serving Endpoint (HuggingFace / BentoML)",
                "query": 'site:huggingface.co "{target}" OR site:{domain} inurl:predict OR inurl:inference "healthcare" OR "clinical" OR "medical"',
                "description": "Searches for publicly exposed AI model serving endpoints associated with the target, which may allow unauthorized model querying or data extraction.",
                "severity": "high",
                "tippss": ["Identity", "Protection", "Security"],
                "remediation": "Restrict model serving endpoints to authorized users. Implement authentication on all inference APIs. Monitor for unauthorized model access."
            },
        ]
