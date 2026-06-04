"""
IEEE CyberSalukis HealthGuard OSINT
Module: shodan_scan.py — Shodan IoT & AI Infrastructure Scanner

Discovers exposed medical IoT devices, AI model serving infrastructure,
and misconfigured health system services using Shodan search API.
"""

import yaml
import requests
from pathlib import Path
from typing import List, Dict, Any
from .base import BaseModule


class ShodanScanner(BaseModule):
    """
    Shodan-based reconnaissance module.
    Queries Shodan for exposed medical IoT devices, AI infrastructure,
    and misconfigured services in healthcare network ranges.

    Falls back to documented query library if no API key is configured.
    """

    MODULE_NAME = "shodan-scan"
    MODULE_LABEL = "Shodan IoT/Infrastructure Scanner"

    SHODAN_SEARCH_URL = "https://api.shodan.io/shodan/host/search"
    SHODAN_DNS_URL = "https://api.shodan.io/dns/resolve"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.api_key = self.config.get("api_keys", {}).get("shodan", "")
        self.query_library = self._load_query_library()

    def _load_query_library(self) -> List[Dict]:
        """Load Shodan queries from YAML library."""
        queries = []
        for yaml_file in ["queries/shodan/medical_iot.yaml", "queries/shodan/ai_infrastructure.yaml"]:
            path = Path(yaml_file)
            if path.exists():
                try:
                    with open(path) as f:
                        data = yaml.safe_load(f) or {}
                    queries.extend(data.get("queries", []))
                except Exception as e:
                    self._log(f"Could not load {yaml_file}: {e}", "warn")

        return queries or self._builtin_queries()

    def run(self) -> List[Dict[str, Any]]:
        """Execute Shodan reconnaissance."""
        findings = []

        if not self.api_key:
            self._log("No Shodan API key — returning documented query library as findings", "warn")
            return self._library_findings()

        if self.domain:
            findings.extend(self._resolve_and_scan_domain())

        findings.extend(self._execute_queries())
        return findings

    def _resolve_and_scan_domain(self) -> List[Dict[str, Any]]:
        """Resolve domain to IP(s) and look up in Shodan."""
        findings = []
        try:
            resp = requests.get(
                self.SHODAN_DNS_URL,
                params={"hostnames": self.domain, "key": self.api_key},
                timeout=10
            )
            if resp.status_code == 200:
                ips = resp.json()
                for hostname, ip in ips.items():
                    self._log(f"Resolved {hostname} -> {ip}")
                    host_findings = self._lookup_host(ip)
                    findings.extend(host_findings)
        except Exception as e:
            self._log(f"DNS resolution error: {e}", "error")
        return findings

    def _lookup_host(self, ip: str) -> List[Dict[str, Any]]:
        """Look up a specific IP in Shodan."""
        findings = []
        try:
            resp = requests.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": self.api_key},
                timeout=15
            )
            if resp.status_code != 200:
                return findings

            data = resp.json()
            ports = data.get("ports", [])
            vulns = data.get("vulns", {})
            hostnames = data.get("hostnames", [])
            org = data.get("org", "Unknown")

            # Flag interesting open ports in healthcare context
            interesting_ports = {
                4440: "Rundeck (Automation Server)",
                8080: "HTTP Alt — possible admin interface",
                8443: "HTTPS Alt — possible admin interface",
                9200: "Elasticsearch — possible data store",
                9300: "Elasticsearch cluster",
                6333: "Qdrant Vector DB",
                6334: "Qdrant gRPC",
                8001: "Possible AI API server",
                11434: "Ollama LLM Server",
                5000: "Flask/ML API common port",
                7860: "Gradio AI Interface default port",
                8501: "Streamlit AI Interface default port",
            }

            for port in ports:
                if port in interesting_ports:
                    finding = self._make_finding(
                        source="Shodan Host Lookup",
                        query=f"Shodan host lookup: {ip}",
                        title=f"Interesting Port Open: {port} ({interesting_ports[port]})",
                        description=(
                            f"Shodan reports port {port} ({interesting_ports[port]}) open "
                            f"on {ip} (hostnames: {', '.join(hostnames) or 'none'}, org: {org}). "
                            f"This port is commonly associated with AI serving infrastructure "
                            f"or data stores in healthcare environments. Open access may indicate "
                            f"an exposed AI service, vector database, or administrative interface."
                        ),
                        severity="high",
                        tippss=["Protection", "Security"],
                        remediation=(
                            "Verify whether this service should be publicly accessible. "
                            "Apply firewall rules to restrict access to authorized networks only. "
                            "Require authentication on all AI serving endpoints. "
                            "Conduct service audit for exposed AI infrastructure."
                        ),
                        url=f"https://www.shodan.io/host/{ip}",
                        raw={"ip": ip, "port": port, "org": org}
                    )
                    findings.append(finding)

            # Flag CVEs if present
            if vulns:
                finding = self._make_finding(
                    source="Shodan Host Lookup",
                    query=f"Shodan CVE check: {ip}",
                    title=f"Known Vulnerabilities on {ip}: {len(vulns)} CVE(s)",
                    description=(
                        f"Shodan reports {len(vulns)} known CVE(s) on {ip}: "
                        f"{', '.join(list(vulns.keys())[:5])}{'...' if len(vulns) > 5 else ''}. "
                        f"Vulnerable services in healthcare AI environments may provide "
                        f"direct exploitation paths to AI infrastructure or data stores."
                    ),
                    severity="critical",
                    tippss=["Protection", "Safety", "Security"],
                    remediation="Immediately patch identified CVEs. Conduct full vulnerability assessment.",
                    url=f"https://www.shodan.io/host/{ip}",
                    raw={"ip": ip, "vulns": list(vulns.keys())}
                )
                findings.append(finding)

        except Exception as e:
            self._log(f"Host lookup error for {ip}: {e}", "error")

        return findings

    def _execute_queries(self) -> List[Dict[str, Any]]:
        """Execute Shodan search queries from the library."""
        findings = []
        for q in self.query_library[:10]:  # Cap at 10 queries per run
            query_str = q.get("query", "").replace("{domain}", self.domain).replace("{target}", self.target)
            if not query_str:
                continue

            self._log(f"Shodan query: {query_str[:60]}...")
            try:
                resp = requests.get(
                    self.SHODAN_SEARCH_URL,
                    params={"query": query_str, "key": self.api_key},
                    timeout=15
                )
                if resp.status_code != 200:
                    continue

                data = resp.json()
                total = data.get("total", 0)
                matches = data.get("matches", [])

                if total > 0:
                    for match in matches[:3]:
                        finding = self._make_finding(
                            source="Shodan Search",
                            query=query_str,
                            title=q.get("title", "Shodan Result"),
                            description=(
                                f"{q.get('description', '')} "
                                f"Shodan returned {total} total result(s). "
                                f"IP: {match.get('ip_str', 'unknown')}, "
                                f"Port: {match.get('port', 'unknown')}, "
                                f"Org: {match.get('org', 'unknown')}"
                            ),
                            severity=q.get("severity", "medium"),
                            tippss=q.get("tippss", ["Security"]),
                            remediation=q.get("remediation", "Review and restrict external access."),
                            url=f"https://www.shodan.io/host/{match.get('ip_str', '')}",
                            raw={"ip": match.get("ip_str"), "port": match.get("port"), "total": total}
                        )
                        findings.append(finding)

            except Exception as e:
                self._log(f"Shodan query error: {e}", "error")

            self._throttle()

        return findings

    def _library_findings(self) -> List[Dict[str, Any]]:
        """Return query library as informational findings when no API key configured."""
        findings = []
        for q in self.query_library:
            query_str = q.get("query", "").replace("{domain}", self.domain).replace("{target}", self.target)
            finding = self._make_finding(
                source="Shodan Query Library (DRY-RUN — configure SHODAN_API_KEY to execute)",
                query=query_str,
                title=f"[DRY-RUN] {q.get('title', 'Shodan Query')}",
                description=f"{q.get('description', '')}\n\nConfigure SHODAN_API_KEY to execute automatically.",
                severity=q.get("severity", "info"),
                tippss=q.get("tippss", ["Security"]),
                remediation=q.get("remediation", ""),
            )
            findings.append(finding)
        return findings

    def _builtin_queries(self) -> List[Dict]:
        """Built-in Shodan query library for healthcare AI/IoT."""
        return [
            {
                "title": "Exposed Ollama LLM Server",
                "query": "port:11434 product:ollama",
                "description": "Ollama is a popular local LLM server. Port 11434 open publicly indicates an exposed LLM instance that may be running healthcare AI models without authentication.",
                "severity": "critical",
                "tippss": ["Identity", "Protection", "Security"],
                "remediation": "Immediately bind Ollama to localhost only. Do not expose port 11434 publicly. Require authentication for any AI model serving endpoint."
            },
            {
                "title": "Exposed Gradio AI Interface",
                "query": "port:7860 title:Gradio",
                "description": "Gradio is widely used to deploy AI demos. Port 7860 open publicly with Gradio title indicates an exposed AI interface that may be running healthcare-context models.",
                "severity": "high",
                "tippss": ["Identity", "Protection", "Security"],
                "remediation": "Restrict Gradio interfaces to internal networks. Implement authentication before deployment. Remove healthcare data from demo environments."
            },
            {
                "title": "Exposed Streamlit AI Application",
                "query": "port:8501 title:Streamlit",
                "description": "Streamlit is commonly used for healthcare AI dashboards and tools. Exposed instances may provide unauthenticated access to clinical AI applications.",
                "severity": "high",
                "tippss": ["Identity", "Protection", "Security"],
                "remediation": "Restrict Streamlit applications to internal access. Implement Streamlit authentication or place behind reverse proxy with auth."
            },
            {
                "title": "Exposed Elasticsearch Cluster (Healthcare Context)",
                "query": 'port:9200 product:elasticsearch "{target}"',
                "description": "Elasticsearch is commonly used as a vector database or data store for healthcare AI RAG systems. Unauthenticated Elasticsearch exposes all indexed data.",
                "severity": "critical",
                "tippss": ["Privacy", "Protection", "Security"],
                "remediation": "Enable Elasticsearch security (X-Pack). Restrict to internal networks. Audit indexed data for PHI. Implement TLS and authentication."
            },
            {
                "title": "Exposed Qdrant Vector Database",
                "query": "port:6333 product:qdrant",
                "description": "Qdrant is a vector database commonly used in healthcare AI RAG systems to store embeddings of clinical documents. Exposed instances may allow extraction of embedded healthcare data.",
                "severity": "critical",
                "tippss": ["Privacy", "Protection", "Security"],
                "remediation": "Restrict Qdrant to internal networks. Enable Qdrant API key authentication. Audit stored vectors for PHI embedding."
            },
            {
                "title": "Exposed Medical Device Web Interface",
                "query": 'ssl.cert.subject.cn:"{domain}" http.title:"patient monitor" OR "infusion" OR "imaging" OR "DICOM"',
                "description": "SSL certificates and web interfaces associated with the target domain may reveal exposed medical device management interfaces accessible from the internet.",
                "severity": "critical",
                "tippss": ["Protection", "Safety", "Security"],
                "remediation": "Immediately restrict medical device interfaces to internal networks. Implement network segmentation for all medical devices. Disable unnecessary remote access."
            },
            {
                "title": "Exposed vLLM or LM Studio API",
                "query": "port:8000 http.title:vllm OR port:1234 http.title:lmstudio",
                "description": "vLLM and LM Studio are AI model serving platforms. Open API ports without authentication allow unrestricted model querying and potential data extraction.",
                "severity": "high",
                "tippss": ["Identity", "Protection", "Security"],
                "remediation": "Require API key authentication on all model serving endpoints. Restrict to internal networks. Implement request logging and monitoring."
            },
            {
                "title": "Open Remote Desktop on Healthcare Infrastructure",
                "query": 'port:3389 org:"{target}" country:US',
                "description": "RDP exposed on healthcare organization infrastructure represents a common ransomware and lateral movement entry point. AI-connected systems with RDP exposure are high-value targets.",
                "severity": "high",
                "tippss": ["Protection", "Security"],
                "remediation": "Disable RDP where not required. Place RDP behind VPN. Enable NLA. Implement MFA for remote access."
            },
        ]
