"""
IEEE CyberSalukis HealthGuard OSINT
Module: ivre_recon.py — IVRE Open-Source Network Recon Integration

IVRE (Instrument de veille sur les réseaux extérieurs) is a fully open-source
network reconnaissance framework that can be self-hosted. It provides
internet-wide scan data querying capabilities without dependence on
proprietary services like Shodan or Censys.

IVRE GitHub: https://github.com/ivre/ivre
IVRE Web API: https://ivre.rocks
License: GPL v3 — fully open source, DPG-aligned

This module supports two modes:
1. IVRE Web API (ivre.rocks) — public, no auth required for basic queries
2. Self-hosted IVRE instance — for organizations running their own IVRE
"""

import requests
import yaml
from pathlib import Path
from typing import List, Dict, Any
from .base import BaseModule


class IVRERecon(BaseModule):
    """
    IVRE-based open-source network reconnaissance module.

    IVRE is the DPG-aligned alternative to Shodan/Censys:
    - Fully open source (GPL v3)
    - Self-hostable — no vendor dependency
    - Integrates Masscan, Nmap, Zeek, and other open-source scan data
    - No rate limit concerns for self-hosted deployments

    This module queries the IVRE web API or a self-hosted IVRE instance
    to identify exposed healthcare AI infrastructure.
    """

    MODULE_NAME = "ivre-recon"
    MODULE_LABEL = "IVRE Open-Source Network Recon"

    # Public IVRE web interface (no auth required for basic queries)
    IVRE_WEB_URL = "https://ivre.rocks/cgi-bin/flow.py"
    IVRE_VIEW_URL = "https://ivre.rocks/cgi-bin/view.py"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Support self-hosted IVRE instance via config
        self.ivre_url = self.config.get("ivre", {}).get(
            "web_url", self.IVRE_VIEW_URL
        )
        self.use_local = self.config.get("ivre", {}).get("use_local_cli", False)
        self.query_library = self._load_query_library()

    def _load_query_library(self) -> List[Dict]:
        path = Path("queries/ivre/healthcare_scans.yaml")
        if path.exists():
            try:
                with open(path) as f:
                    data = yaml.safe_load(f) or {}
                return data.get("queries", [])
            except Exception as e:
                self._log(f"Could not load IVRE query library: {e}", "warn")
        return self._builtin_queries()

    def run(self) -> List[Dict[str, Any]]:
        """Execute IVRE reconnaissance."""
        findings = []

        if self.use_local:
            findings.extend(self._local_cli_recon())
        else:
            findings.extend(self._web_api_recon())

        # Always include the IVRE setup guide as an informational finding
        # since self-hosted IVRE is the recommended DPG-aligned deployment
        findings.extend(self._ivre_capability_findings())

        return findings

    def _web_api_recon(self) -> List[Dict[str, Any]]:
        """Query IVRE web API for target-relevant data."""
        findings = []

        if self.domain:
            findings.extend(self._query_domain_hosts())

        for q in self.query_library[:6]:
            findings.extend(self._execute_web_query(q))
            self._throttle()

        return findings

    def _query_domain_hosts(self) -> List[Dict[str, Any]]:
        """Query IVRE for hosts associated with the target domain."""
        findings = []
        self._log(f"IVRE domain query: {self.domain}")

        try:
            params = {
                "q": f"hostnames:{self.domain}",
                "limit": 10,
                "format": "json"
            }
            resp = requests.get(self.ivre_url, params=params, timeout=15)

            if resp.status_code == 200:
                try:
                    hosts = resp.json()
                    if isinstance(hosts, list):
                        for host in hosts[:5]:
                            ip = host.get("addr", "unknown")
                            ports = host.get("ports", [])
                            ai_ports = [
                                p for p in ports
                                if p.get("port") in [
                                    11434, 7860, 8501, 8888, 9200,
                                    6333, 6379, 27017, 5000, 8000, 3000
                                ]
                            ]
                            if ai_ports:
                                port_list = [str(p.get("port")) for p in ai_ports]
                                finding = self._make_finding(
                                    source="IVRE Web API (Open Source)",
                                    query=f"IVRE hostnames:{self.domain}",
                                    title=f"AI-Related Ports on {ip}: {', '.join(port_list)}",
                                    description=(
                                        f"IVRE network scan data shows AI-relevant open ports "
                                        f"({', '.join(port_list)}) on host {ip} associated with "
                                        f"{self.domain}. These ports are commonly used by LLM "
                                        f"servers, AI dashboards, and data stores in healthcare "
                                        f"AI deployments."
                                    ),
                                    severity="high",
                                    tippss=["Protection", "Security"],
                                    remediation=(
                                        "Audit all open AI-related ports. Restrict to internal "
                                        "networks or require authentication. Review running services."
                                    ),
                                    url=f"https://ivre.rocks/#!view/nmap/host/{ip}",
                                    raw={"ip": ip, "ports": port_list}
                                )
                                findings.append(finding)
                except Exception:
                    pass  # IVRE public API response format may vary

        except Exception as e:
            self._log(f"IVRE web API error: {e}", "warn")

        return findings

    def _execute_web_query(self, q: Dict) -> List[Dict[str, Any]]:
        """Execute a single IVRE web query."""
        findings = []
        query_str = q.get("query", "").replace("{domain}", self.domain).replace("{target}", self.target)
        if not query_str:
            return findings

        self._log(f"IVRE query: {query_str[:60]}...")
        try:
            resp = requests.get(
                self.ivre_url,
                params={"q": query_str, "limit": 5, "format": "json"},
                timeout=15
            )
            if resp.status_code == 200:
                try:
                    results = resp.json()
                    if isinstance(results, list) and results:
                        finding = self._make_finding(
                            source="IVRE Web API (Open Source)",
                            query=query_str,
                            title=q.get("title", "IVRE Scan Result"),
                            description=(
                                f"{q.get('description', '')} "
                                f"IVRE returned {len(results)} result(s)."
                            ),
                            severity=q.get("severity", "medium"),
                            tippss=q.get("tippss", ["Security"]),
                            remediation=q.get("remediation", "Review and restrict external access."),
                            url=f"https://ivre.rocks/#!view/nmap",
                            raw={"count": len(results), "query": query_str}
                        )
                        findings.append(finding)
                except Exception:
                    pass
        except Exception as e:
            self._log(f"IVRE query error: {e}", "warn")

        return findings

    def _local_cli_recon(self) -> List[Dict[str, Any]]:
        """
        Execute IVRE via local CLI (ivre db2view / ivre view).
        Only runs when use_local_cli: true in config and IVRE is installed.
        """
        findings = []
        try:
            import subprocess
            # Test IVRE is available
            result = subprocess.run(
                ["ivre", "--version"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                self._log("IVRE CLI not found — falling back to web API", "warn")
                return self._web_api_recon()

            self._log("IVRE local CLI available — executing queries")

            for q in self.query_library[:5]:
                filter_arg = q.get("cli_filter", "")
                if not filter_arg:
                    continue

                cmd = ["ivre", "view", "--json", filter_arg]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

                if res.returncode == 0 and res.stdout.strip():
                    import json
                    try:
                        lines = [json.loads(l) for l in res.stdout.strip().split("\n") if l.strip()]
                        if lines:
                            finding = self._make_finding(
                                source="IVRE Local CLI (Self-Hosted, Open Source)",
                                query=f"ivre view {filter_arg}",
                                title=q.get("title", "IVRE CLI Result"),
                                description=(
                                    f"{q.get('description', '')} "
                                    f"IVRE local scan database returned {len(lines)} result(s)."
                                ),
                                severity=q.get("severity", "medium"),
                                tippss=q.get("tippss", ["Security"]),
                                remediation=q.get("remediation", ""),
                                raw={"count": len(lines)}
                            )
                            findings.append(finding)
                    except Exception:
                        pass

        except FileNotFoundError:
            self._log("IVRE not installed — see docs/IVRE_SETUP.md", "warn")
            findings.extend(self._ivre_not_installed_finding())
        except Exception as e:
            self._log(f"IVRE CLI error: {e}", "error")

        return findings

    def _ivre_not_installed_finding(self) -> List[Dict[str, Any]]:
        """Return setup guidance when IVRE is not installed."""
        return [self._make_finding(
            source="IVRE Setup Check",
            query="ivre --version",
            title="IVRE Not Installed — Self-Hosted Setup Recommended",
            description=(
                "IVRE (Instrument de veille sur les réseaux extérieurs) is a fully "
                "open-source network reconnaissance framework that provides Shodan-like "
                "capabilities without proprietary dependencies. Installing IVRE enables "
                "self-hosted internet-wide scan data queries for healthcare AI infrastructure "
                "discovery with no API rate limits or vendor lock-in.\n\n"
                "Install: pip install ivre\n"
                "Documentation: https://ivre.rocks\n"
                "GitHub: https://github.com/ivre/ivre\n\n"
                "For HealthGuard OSINT, set ivre.use_local_cli: true in config.yaml "
                "after installation."
            ),
            severity="info",
            tippss=["Security"],
            remediation=(
                "Install IVRE: pip install ivre\n"
                "Initialize database: ivre ipinfo --init\n"
                "Import scan data: ivre scan2db\n"
                "See docs/IVRE_SETUP.md for full setup guide."
            ),
        )]

    def _ivre_capability_findings(self) -> List[Dict[str, Any]]:
        """
        Document IVRE capabilities as informational findings,
        particularly for organizations considering self-hosted deployment.
        """
        return [self._make_finding(
            source="IVRE Capability Assessment",
            query="IVRE open-source recon capabilities",
            title="IVRE Self-Hosted Deployment Available — DPG-Aligned Reconnaissance",
            description=(
                "IEEE CyberSalukis HealthGuard OSINT integrates IVRE, a fully open-source "
                "network reconnaissance framework (GPL v3), as the DPG-aligned alternative "
                "to proprietary services. IVRE capabilities relevant to healthcare AI security:\n\n"
                "• Passive network traffic analysis via Zeek integration\n"
                "• Active scanning data via Nmap and Masscan integration\n"
                "• Self-hostable — no vendor dependency or API rate limits\n"
                "• MongoDB or PostgreSQL backend — full data control\n"
                "• REST API and web interface for programmatic access\n"
                "• Docker deployment available for rapid setup\n\n"
                "For resource-constrained health systems, IVRE provides Shodan-equivalent "
                "capabilities with zero licensing cost and full data sovereignty."
            ),
            severity="info",
            tippss=["Trust", "Security"],
            remediation=(
                "Consider deploying IVRE for continuous internal network scanning. "
                "Integrate with existing Nmap/Masscan scanning workflows. "
                "See https://github.com/ivre/ivre for deployment documentation."
            ),
        )]

    def _builtin_queries(self) -> List[Dict]:
        """Built-in IVRE query library."""
        return [
            {
                "title": "IVRE: Exposed LLM Serving Ports",
                "query": "ports.port:11434 or ports.port:7860 or ports.port:8501",
                "cli_filter": "--port 11434,7860,8501",
                "description": "IVRE scan data showing Ollama (11434), Gradio (7860), and Streamlit (8501) ports open. Primary LLM serving and AI demo interface ports.",
                "severity": "critical",
                "tippss": ["Identity", "Protection", "Security"],
                "remediation": "Restrict LLM serving ports to internal network. Require authentication."
            },
            {
                "title": "IVRE: Exposed Database Ports (Healthcare AI)",
                "query": "ports.port:9200 or ports.port:6333 or ports.port:27017 or ports.port:6379",
                "cli_filter": "--port 9200,6333,27017,6379",
                "description": "Elasticsearch (9200), Qdrant (6333), MongoDB (27017), Redis (6379) ports open. Common healthcare AI data stores.",
                "severity": "critical",
                "tippss": ["Privacy", "Protection", "Security"],
                "remediation": "Enable authentication on all database instances. Restrict to internal networks."
            },
            {
                "title": "IVRE: Jupyter Notebook Exposure",
                "query": "ports.port:8888 ports.state:open",
                "cli_filter": "--port 8888",
                "description": "Jupyter notebook server port open. Healthcare AI development environments with patient data or API keys.",
                "severity": "critical",
                "tippss": ["Identity", "Privacy", "Protection", "Security"],
                "remediation": "Enable Jupyter authentication. Restrict to localhost. Audit for PHI."
            },
            {
                "title": "IVRE: Medical Protocol Ports Exposed",
                "query": "ports.port:104 or ports.port:2575 or ports.port:11112",
                "cli_filter": "--port 104,2575,11112",
                "description": "DICOM (104, 11112) and HL7 MLLP (2575) healthcare protocol ports open publicly. AI-connected clinical data interfaces.",
                "severity": "critical",
                "tippss": ["Privacy", "Protection", "Safety", "Security"],
                "remediation": "Restrict medical protocol ports to internal clinical network immediately."
            },
            {
                "title": "IVRE: AI Infrastructure Ports",
                "query": "ports.port:5000 or ports.port:8000 or ports.port:3000",
                "cli_filter": "--port 5000,8000,3000",
                "description": "Common AI API serving ports (Flask, vLLM, BentoML, Grafana). May expose healthcare AI model APIs.",
                "severity": "high",
                "tippss": ["Identity", "Protection", "Security"],
                "remediation": "Audit services on these ports. Restrict AI APIs to authenticated access."
            },
        ]
