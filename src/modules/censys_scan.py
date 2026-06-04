"""
IEEE CyberSalukis HealthGuard OSINT
Module: censys_scan.py — Censys Infrastructure & Certificate Intelligence

Discovers exposed healthcare AI infrastructure using Censys internet-wide
scan data. Censys provides certificate intelligence, service fingerprinting,
and host enumeration complementing Shodan coverage.

Censys API: https://search.censys.io
Free community tier: 250 queries/month
"""

import requests
import yaml
from pathlib import Path
from typing import List, Dict, Any
from .base import BaseModule


class CensysScanner(BaseModule):
    """
    Censys-based reconnaissance module.

    Uses Censys Search API v2 to identify:
    - Exposed AI serving infrastructure via certificate metadata
    - Misconfigured healthcare services visible on internet scans
    - TLS certificate relationships revealing AI system deployments
    - IPv4 hosts running known AI/healthcare services

    Falls back to documented query library if no API credentials configured.
    """

    MODULE_NAME = "censys-scan"
    MODULE_LABEL = "Censys Infrastructure Scanner"

    CENSYS_HOSTS_URL    = "https://search.censys.io/api/v2/hosts/search"
    CENSYS_CERTS_URL    = "https://search.censys.io/api/v2/certificates/search"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.api_id     = self.config.get("api_keys", {}).get("censys_api_id", "")
        self.api_secret = self.config.get("api_keys", {}).get("censys_api_secret", "")
        self.auth       = (self.api_id, self.api_secret) if (self.api_id and self.api_secret) else None
        self.query_library = self._load_query_library()

    def _load_query_library(self) -> List[Dict]:
        path = Path("queries/censys/health_networks.yaml")
        if path.exists():
            try:
                with open(path) as f:
                    data = yaml.safe_load(f) or {}
                return data.get("queries", [])
            except Exception as e:
                self._log(f"Could not load Censys query library: {e}", "warn")
        return self._builtin_queries()

    def run(self) -> List[Dict[str, Any]]:
        """Execute Censys reconnaissance."""
        findings = []

        if not self.auth:
            self._log("No Censys credentials — returning documented query library", "warn")
            return self._library_findings()

        if self.domain:
            findings.extend(self._certificate_recon())

        findings.extend(self._host_search())
        return findings

    def _certificate_recon(self) -> List[Dict[str, Any]]:
        """
        Query Censys certificates for the target domain.
        Certificate transparency logs reveal subdomains, service names,
        and infrastructure that may host AI systems.
        """
        findings = []
        query = f'parsed.names: "{self.domain}"'
        self._log(f"Censys cert recon: {query}")

        try:
            resp = requests.get(
                self.CENSYS_CERTS_URL,
                auth=self.auth,
                params={"q": query, "per_page": 20},
                timeout=15
            )
            if resp.status_code == 429:
                self._log("Censys rate limit hit", "warn")
                return findings
            resp.raise_for_status()
            data = resp.json()

            hits = data.get("result", {}).get("hits", [])
            ai_keywords = [
                "ai", "llm", "ml", "model", "inference", "predict",
                "chat", "api", "jupyter", "ollama", "gradio", "streamlit",
                "ehr", "clinical", "patient", "health"
            ]

            for cert in hits:
                names = cert.get("parsed", {}).get("names", [])
                ai_names = [n for n in names if any(kw in n.lower() for kw in ai_keywords)]

                if ai_names:
                    finding = self._make_finding(
                        source="Censys Certificate Transparency",
                        query=query,
                        title=f"AI/Healthcare Subdomain via Certificate: {', '.join(ai_names[:3])}",
                        description=(
                            f"Censys certificate transparency data reveals subdomains of "
                            f"{self.domain} containing AI or healthcare keywords: "
                            f"{', '.join(ai_names)}. "
                            f"These subdomains may host AI model APIs, clinical interfaces, "
                            f"or data systems not visible through standard DNS enumeration. "
                            f"Each represents a potential attack surface entry point."
                        ),
                        severity="medium",
                        tippss=["Protection", "Security"],
                        remediation=(
                            "Audit all discovered subdomains for running services. "
                            "Ensure AI-related subdomains require authentication. "
                            "Implement certificate transparency monitoring (crt.sh alerts) "
                            "to detect new subdomain certificates proactively."
                        ),
                        url=f"https://search.censys.io/certificates?q={query}",
                        raw={"names": ai_names, "fingerprint": cert.get("fingerprint_sha256", "")}
                    )
                    findings.append(finding)

        except Exception as e:
            self._log(f"Censys cert recon error: {e}", "error")

        self._throttle()
        return findings

    def _host_search(self) -> List[Dict[str, Any]]:
        """Execute Censys host searches for AI/healthcare infrastructure."""
        findings = []

        for q in self.query_library[:8]:
            query_str = q.get("query", "").replace("{domain}", self.domain).replace("{target}", self.target)
            if not query_str:
                continue

            self._log(f"Censys host search: {query_str[:60]}...")
            try:
                resp = requests.get(
                    self.CENSYS_HOSTS_URL,
                    auth=self.auth,
                    params={"q": query_str, "per_page": 5},
                    timeout=15
                )
                if resp.status_code == 429:
                    self._log("Censys rate limit hit — pausing", "warn")
                    import time; time.sleep(30)
                    continue
                if resp.status_code != 200:
                    continue

                data = resp.json()
                hits = data.get("result", {}).get("hits", [])
                total = data.get("result", {}).get("total", 0)

                if total > 0:
                    for host in hits[:3]:
                        ip = host.get("ip", "unknown")
                        services = host.get("services", [])
                        service_names = [s.get("service_name", "") for s in services]

                        finding = self._make_finding(
                            source="Censys Host Search",
                            query=query_str,
                            title=q.get("title", "Censys Host Result"),
                            description=(
                                f"{q.get('description', '')} "
                                f"Censys found {total} total result(s). "
                                f"Host: {ip}, "
                                f"Services: {', '.join(s for s in service_names if s) or 'unknown'}"
                            ),
                            severity=q.get("severity", "medium"),
                            tippss=q.get("tippss", ["Security"]),
                            remediation=q.get("remediation", "Review and restrict external access."),
                            url=f"https://search.censys.io/hosts/{ip}",
                            raw={"ip": ip, "total": total, "services": service_names}
                        )
                        findings.append(finding)

            except Exception as e:
                self._log(f"Censys host search error: {e}", "error")

            self._throttle()

        return findings

    def _library_findings(self) -> List[Dict[str, Any]]:
        """Return query library as informational findings when no credentials."""
        findings = []
        for q in self.query_library:
            query_str = q.get("query", "").replace("{domain}", self.domain).replace("{target}", self.target)
            finding = self._make_finding(
                source="Censys Query Library (DRY-RUN — configure CENSYS_API_ID + CENSYS_API_SECRET)",
                query=query_str,
                title=f"[DRY-RUN] {q.get('title', 'Censys Query')}",
                description=f"{q.get('description', '')}\n\nConfigure Censys credentials to execute automatically.",
                severity=q.get("severity", "info"),
                tippss=q.get("tippss", ["Security"]),
                remediation=q.get("remediation", ""),
            )
            findings.append(finding)
        return findings

    def _builtin_queries(self) -> List[Dict]:
        """Built-in Censys query library for healthcare AI infrastructure."""
        return [
            {
                "title": "Exposed Jupyter Notebook (Censys)",
                "query": 'services.http.response.html_title: "Jupyter" and services.port: 8888',
                "description": "Censys host scan data showing Jupyter notebook servers on port 8888. Healthcare AI context — may contain PHI, API keys, or clinical model code.",
                "severity": "critical",
                "tippss": ["Identity", "Privacy", "Protection", "Security"],
                "remediation": "Enable Jupyter authentication and SSL. Restrict to internal network."
            },
            {
                "title": "Exposed Elasticsearch (Censys)",
                "query": 'services.elasticsearch.cluster_name: * and services.port: 9200',
                "description": "Unauthenticated Elasticsearch instances. Healthcare AI RAG systems commonly use Elasticsearch as a document store or vector index.",
                "severity": "critical",
                "tippss": ["Privacy", "Protection", "Security"],
                "remediation": "Enable X-Pack security. Restrict to internal network. Audit for PHI."
            },
            {
                "title": "AI/ML Port Exposure via Censys (8000, 8080, 5000)",
                "query": f'(services.port: 8000 or services.port: 5000) and ip: [{"{domain}"}]',
                "description": "Common AI model serving ports open on target IP range. May indicate exposed vLLM, BentoML, Flask ML API, or similar AI inference services.",
                "severity": "high",
                "tippss": ["Identity", "Protection", "Security"],
                "remediation": "Audit all services on these ports. Restrict AI APIs to authenticated access."
            },
            {
                "title": "Expired or Self-Signed TLS Certificate on Healthcare Service",
                "query": f'parsed.names: "{"{domain}"}" and parsed.validity.end: [* TO now]',
                "description": "Expired TLS certificates on target domain services indicate certificate management gaps. Healthcare AI systems with expired certs are vulnerable to MITM attacks on clinical data in transit.",
                "severity": "high",
                "tippss": ["Protection", "Security"],
                "remediation": "Immediately renew expired certificates. Implement automated certificate lifecycle management (Let's Encrypt, AWS ACM)."
            },
            {
                "title": "Open MongoDB — Potential Healthcare AI Data Store",
                "query": "services.mongodb.server_status.ok: 1 and services.port: 27017",
                "description": "Unauthenticated MongoDB instances. Healthcare AI applications sometimes use MongoDB for patient interaction logs, AI output storage, or clinical data.",
                "severity": "critical",
                "tippss": ["Privacy", "Protection", "Security"],
                "remediation": "Enable MongoDB authentication. Restrict to internal network. Audit collections for PHI."
            },
            {
                "title": "Redis Instance Exposed (AI Session/Cache Store)",
                "query": "services.redis.ping_response: PONG and services.port: 6379",
                "description": "Unauthenticated Redis. Healthcare AI systems use Redis for session caching, rate limiting, and storing LLM conversation context that may include PHI.",
                "severity": "high",
                "tippss": ["Privacy", "Protection", "Security"],
                "remediation": "Enable Redis AUTH. Restrict to internal network. Audit stored keys for PHI."
            },
            {
                "title": "Grafana Dashboard Exposed (AI Monitoring)",
                "query": 'services.http.response.html_title: "Grafana" and services.port: 3000',
                "description": "Grafana dashboards exposed publicly. Healthcare AI monitoring dashboards may reveal system performance, model metrics, error logs, and infrastructure topology.",
                "severity": "medium",
                "tippss": ["Trust", "Protection", "Security"],
                "remediation": "Enable Grafana authentication. Restrict to internal network. Disable anonymous access."
            },
            {
                "title": "MinIO / S3-Compatible Storage Exposed",
                "query": 'services.http.response.html_title: "MinIO" and services.port: 9000',
                "description": "MinIO object storage exposed. Commonly used to store AI training data and model artifacts in healthcare AI pipelines.",
                "severity": "high",
                "tippss": ["Privacy", "Protection", "Security"],
                "remediation": "Enable MinIO authentication. Apply bucket policies. Restrict public access. Audit for PHI."
            },
        ]
