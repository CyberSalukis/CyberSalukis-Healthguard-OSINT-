"""
IEEE CyberSalukis HealthGuard OSINT
Module: leakix_scan.py — LeakIX Exposed Service & Data Leak Intelligence

LeakIX is a search engine focused on exposed services and data leaks,
with particular strength in identifying misconfigured databases,
cloud storage, and services leaking sensitive data.

LeakIX API: https://leakix.net
Free tier: Public API with rate limiting
Documentation: https://leakix.net/docs

LeakIX is specifically valuable for healthcare AI OSINT because it:
- Indexes exposed databases and cloud storage with content inspection
- Identifies services leaking data (not just open ports)
- Provides plugin-based detection of common misconfigurations
- Focuses on data exposure rather than generic port enumeration
"""

import requests
import yaml
from pathlib import Path
from typing import List, Dict, Any
from .base import BaseModule


class LeakIXScanner(BaseModule):
    """
    LeakIX-based reconnaissance module.

    LeakIX complements Shodan and Censys by focusing on:
    - Actual data leakage indicators (not just open ports)
    - Database content sampling for exposure confirmation
    - Cloud storage misconfiguration detection
    - Service-level vulnerability indicators

    Free tier provides ~50 queries/day with API key.
    No API key required for basic domain queries (lower rate limit).
    """

    MODULE_NAME = "leakix-scan"
    MODULE_LABEL = "LeakIX Data Leak & Exposure Scanner"

    LEAKIX_BASE_URL  = "https://leakix.net"
    LEAKIX_SEARCH    = "https://leakix.net/search"
    LEAKIX_HOST_URL  = "https://leakix.net/host"
    LEAKIX_DOMAIN    = "https://leakix.net/domain"

    # LeakIX plugin names relevant to healthcare AI
    HEALTHCARE_PLUGINS = [
        "ElasticSearchOpenPlugin",
        "MongoOpenPlugin",
        "RedisOpenPlugin",
        "CouchDbOpenPlugin",
        "PostgresqlOpenPlugin",
        "MysqlOpenPlugin",
        "S3BucketOpenPlugin",
        "JupyterOpenPlugin",
        "GrafanaOpenPlugin",
        "MinioOpenPlugin",
        "DockerOpenPlugin",
        "GitlabOpenPlugin",
        "GitConfigPlugin",
        "EnvFilePlugin",
    ]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.api_key = self.config.get("api_keys", {}).get("leakix_api_key", "")
        self.headers = {"Accept": "application/json"}
        if self.api_key:
            self.headers["api-key"] = self.api_key
        self.query_library = self._load_query_library()

    def _load_query_library(self) -> List[Dict]:
        path = Path("queries/leakix/healthcare_leaks.yaml")
        if path.exists():
            try:
                with open(path) as f:
                    data = yaml.safe_load(f) or {}
                return data.get("queries", [])
            except Exception as e:
                self._log(f"Could not load LeakIX query library: {e}", "warn")
        return self._builtin_queries()

    def run(self) -> List[Dict[str, Any]]:
        """Execute LeakIX reconnaissance."""
        findings = []

        if self.domain:
            findings.extend(self._domain_lookup())

        findings.extend(self._plugin_searches())
        return findings

    def _domain_lookup(self) -> List[Dict[str, Any]]:
        """
        Look up target domain in LeakIX domain index.
        Returns services and leaks associated with the domain.
        """
        findings = []
        url = f"{self.LEAKIX_DOMAIN}/{self.domain}"
        self._log(f"LeakIX domain lookup: {self.domain}")

        try:
            resp = requests.get(url, headers=self.headers, timeout=15)

            if resp.status_code == 404:
                self._log(f"Domain {self.domain} not in LeakIX index", "info")
                return findings

            if resp.status_code == 429:
                self._log("LeakIX rate limit hit — pausing", "warn")
                import time; time.sleep(30)
                return findings

            if resp.status_code != 200:
                self._log(f"LeakIX domain lookup returned {resp.status_code}", "warn")
                return findings

            data = resp.json()

            # Process services (open ports with service data)
            services = data.get("Services", []) or []
            for svc in services[:10]:
                port = svc.get("port", "unknown")
                protocol = svc.get("protocol", "")
                summary = svc.get("summary", "")
                ip = svc.get("ip", "unknown")
                geoip = svc.get("geoip", {})

                # Flag high-interest AI/healthcare services
                interest = self._assess_service_interest(port, protocol, summary)
                if interest:
                    finding = self._make_finding(
                        source="LeakIX Domain Service Index",
                        query=f"LeakIX domain: {self.domain}",
                        title=f"LeakIX: Exposed Service on {self.domain} — Port {port} ({interest['label']})",
                        description=(
                            f"LeakIX service index shows {interest['label']} (port {port}) "
                            f"exposed on {ip} associated with {self.domain}. "
                            f"Country: {geoip.get('country_name', 'unknown')}. "
                            f"Service summary: {summary[:200] if summary else 'N/A'}. "
                            f"{interest['description']}"
                        ),
                        severity=interest["severity"],
                        tippss=interest["tippss"],
                        remediation=interest["remediation"],
                        url=f"{self.LEAKIX_HOST_URL}/{ip}",
                        raw={"ip": ip, "port": port, "protocol": protocol}
                    )
                    findings.append(finding)

            # Process leaks (actual data exposure confirmed by LeakIX)
            leaks = data.get("Leaks", []) or []
            for leak in leaks[:5]:
                plugin = leak.get("plugin", "unknown")
                severity_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
                sev = severity_map.get(leak.get("severity", "medium").lower(), "medium")
                ip = leak.get("ip", "unknown")
                summary = leak.get("summary", "")

                # All confirmed leaks on a healthcare domain are high/critical
                if sev in ("low", "info"):
                    sev = "medium"

                finding = self._make_finding(
                    source="LeakIX Confirmed Data Leak",
                    query=f"LeakIX domain leak: {self.domain}",
                    title=f"CONFIRMED LEAK: {plugin} on {self.domain}",
                    description=(
                        f"LeakIX has confirmed a data exposure on {self.domain} via "
                        f"plugin {plugin}. Host: {ip}. "
                        f"Summary: {summary[:300] if summary else 'N/A'}. "
                        f"Unlike port scans, LeakIX confirmed leaks indicate actual "
                        f"data accessibility — not just open ports. In a healthcare "
                        f"AI context this may represent direct PHI exposure."
                    ),
                    severity=sev,
                    tippss=["Privacy", "Protection", "Security"],
                    remediation=(
                        "Immediately investigate this confirmed exposure. "
                        "Restrict service access. Assess HIPAA breach notification obligations. "
                        "Review all data accessible through this service for PHI content. "
                        "Notify legal and compliance teams."
                    ),
                    url=f"{self.LEAKIX_HOST_URL}/{ip}",
                    raw={"plugin": plugin, "ip": ip, "severity": sev}
                )
                findings.append(finding)

        except Exception as e:
            self._log(f"LeakIX domain lookup error: {e}", "error")

        self._throttle()
        return findings

    def _plugin_searches(self) -> List[Dict[str, Any]]:
        """Search LeakIX by plugin for healthcare-relevant exposure patterns."""
        findings = []

        # Only run plugin searches if we have domain to narrow scope
        if not self.domain and not self.target:
            return findings

        scope = self.domain or self.target

        for plugin in self.HEALTHCARE_PLUGINS[:6]:
            query = f'+plugin:"{plugin}" +host:"{scope}"'
            self._log(f"LeakIX plugin search: {plugin}")

            try:
                resp = requests.get(
                    self.LEAKIX_SEARCH,
                    headers=self.headers,
                    params={"q": query, "scope": "leak"},
                    timeout=15
                )

                if resp.status_code == 429:
                    self._log("LeakIX rate limit — pausing", "warn")
                    import time; time.sleep(30)
                    continue

                if resp.status_code != 200:
                    continue

                results = resp.json() or []
                if results:
                    for item in results[:2]:
                        ip = item.get("ip", "unknown")
                        summary = item.get("summary", "")
                        finding = self._make_finding(
                            source=f"LeakIX Plugin Search: {plugin}",
                            query=query,
                            title=f"LeakIX {plugin} Detected on {scope}",
                            description=(
                                f"LeakIX plugin '{plugin}' detected on {ip} associated with "
                                f"{scope}. Summary: {summary[:200] if summary else 'N/A'}. "
                                f"LeakIX plugin detection indicates a confirmed misconfiguration "
                                f"or data exposure pattern, not just an open port."
                            ),
                            severity="high",
                            tippss=["Privacy", "Protection", "Security"],
                            remediation=(
                                f"Investigate {plugin} finding on {ip}. "
                                "Restrict access, enable authentication, audit for PHI. "
                                "Assess HIPAA breach notification obligations."
                            ),
                            url=f"{self.LEAKIX_HOST_URL}/{ip}",
                            raw={"plugin": plugin, "ip": ip}
                        )
                        findings.append(finding)

            except Exception as e:
                self._log(f"LeakIX plugin search error: {e}", "error")

            self._throttle()

        return findings

    def _assess_service_interest(self, port, protocol, summary) -> Dict:
        """Assess whether a LeakIX service finding is relevant to healthcare AI."""
        port = int(port) if str(port).isdigit() else 0
        summary_lower = (summary or "").lower()

        service_map = {
            11434: {"label": "Ollama LLM Server", "severity": "critical",
                    "tippss": ["Identity", "Protection", "Security"],
                    "description": "Ollama LLM server directly exposes AI model inference without authentication.",
                    "remediation": "Bind Ollama to localhost. Place behind authenticated proxy."},
            7860:  {"label": "Gradio AI Interface", "severity": "high",
                    "tippss": ["Identity", "Protection", "Security"],
                    "description": "Gradio AI interface — potential healthcare AI demo with patient data access.",
                    "remediation": "Require authentication. Restrict to internal network."},
            8501:  {"label": "Streamlit Application", "severity": "high",
                    "tippss": ["Identity", "Protection", "Security"],
                    "description": "Streamlit AI application — may expose clinical AI tools without authentication.",
                    "remediation": "Enable Streamlit auth. Restrict to internal network."},
            9200:  {"label": "Elasticsearch", "severity": "critical",
                    "tippss": ["Privacy", "Protection", "Security"],
                    "description": "Elasticsearch — potential healthcare data store or RAG vector index exposed.",
                    "remediation": "Enable X-Pack security. Restrict to internal network. Audit for PHI."},
            6333:  {"label": "Qdrant Vector DB", "severity": "critical",
                    "tippss": ["Privacy", "Protection", "Security"],
                    "description": "Qdrant vector database — likely stores clinical document embeddings for RAG.",
                    "remediation": "Enable API key auth. Restrict to internal network."},
            8888:  {"label": "Jupyter Notebook", "severity": "critical",
                    "tippss": ["Identity", "Privacy", "Protection", "Security"],
                    "description": "Jupyter notebook — may contain PHI, API keys, or clinical AI code.",
                    "remediation": "Enable authentication and SSL. Restrict to internal network."},
            27017: {"label": "MongoDB", "severity": "critical",
                    "tippss": ["Privacy", "Protection", "Security"],
                    "description": "MongoDB — unauthenticated database may contain AI output logs or clinical data.",
                    "remediation": "Enable authentication. Restrict to internal network."},
            6379:  {"label": "Redis", "severity": "high",
                    "tippss": ["Privacy", "Protection", "Security"],
                    "description": "Redis — may cache LLM conversation context including PHI.",
                    "remediation": "Enable Redis AUTH. Restrict to internal network."},
        }

        if port in service_map:
            return service_map[port]

        # Check summary for healthcare AI keywords
        healthcare_keywords = ["patient", "phi", "ehr", "clinical", "health", "medical", "dicom", "hl7"]
        if any(kw in summary_lower for kw in healthcare_keywords):
            return {
                "label": f"Healthcare Context Service (port {port})",
                "severity": "high",
                "tippss": ["Privacy", "Security"],
                "description": "Service summary contains healthcare keywords indicating potential PHI exposure.",
                "remediation": "Investigate service for PHI exposure. Restrict access. Assess HIPAA obligations."
            }

        return None  # Not relevant enough to report

    def _builtin_queries(self) -> List[Dict]:
        """Built-in LeakIX query patterns for healthcare AI."""
        return [
            {
                "title": "LeakIX: Elasticsearch PHI Exposure",
                "query": '+plugin:"ElasticSearchOpenPlugin" +host:"{domain}"',
                "description": "LeakIX confirmed open Elasticsearch on target domain. High risk of healthcare AI data exposure.",
                "severity": "critical",
                "tippss": ["Privacy", "Protection", "Security"],
                "remediation": "Enable X-Pack security. Restrict to internal network. Immediately audit for PHI."
            },
            {
                "title": "LeakIX: Open MongoDB — Healthcare AI",
                "query": '+plugin:"MongoOpenPlugin" +host:"{domain}"',
                "description": "LeakIX confirmed open MongoDB. May contain clinical AI logs, patient interactions, or model outputs.",
                "severity": "critical",
                "tippss": ["Privacy", "Protection", "Security"],
                "remediation": "Enable MongoDB authentication. Restrict to internal network."
            },
            {
                "title": "LeakIX: Exposed .env File",
                "query": '+plugin:"EnvFilePlugin" +host:"{domain}"',
                "description": "LeakIX detected an exposed .env file. Healthcare AI .env files commonly contain LLM API keys and database credentials.",
                "severity": "critical",
                "tippss": ["Identity", "Security"],
                "remediation": "Immediately rotate all credentials in .env. Remove from public access. Implement secrets management."
            },
            {
                "title": "LeakIX: Git Config Exposure",
                "query": '+plugin:"GitConfigPlugin" +host:"{domain}"',
                "description": "LeakIX detected an exposed .git/config. May reveal repository URLs, remote branches, and deployment details for healthcare AI systems.",
                "severity": "high",
                "tippss": ["Identity", "Security"],
                "remediation": "Block .git directory access via web server config. Audit repository for sensitive content."
            },
            {
                "title": "LeakIX: Jupyter Notebook Confirmed Open",
                "query": '+plugin:"JupyterOpenPlugin" +host:"{domain}"',
                "description": "LeakIX confirmed open Jupyter notebook server. Healthcare AI development environment — high PHI and credential exposure risk.",
                "severity": "critical",
                "tippss": ["Identity", "Privacy", "Protection", "Security"],
                "remediation": "Enable Jupyter authentication. Restrict to internal network. Audit for PHI and API keys."
            },
        ]
