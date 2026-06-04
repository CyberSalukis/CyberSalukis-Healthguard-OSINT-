"""
Base reconnaissance module for IEEE CyberSalukis HealthGuard OSINT
All modules inherit from this base class.
"""

import time
import datetime
from abc import ABC, abstractmethod
from typing import List, Dict, Any
from rich.console import Console

console = Console()


class BaseModule(ABC):
    """
    Base class for all HealthGuard OSINT reconnaissance modules.

    Each finding returned by run() must conform to the standard finding schema:
    {
        "id":           str  — unique finding identifier
        "module":       str  — module name
        "source":       str  — data source (e.g. "Google", "Shodan", "GitHub")
        "query":        str  — the query that produced this finding
        "url":          str  — URL of the discovered resource (if applicable)
        "title":        str  — short descriptive title
        "description":  str  — full description of the finding
        "severity":     str  — "critical" | "high" | "medium" | "low" | "info"
        "tippss":       list — TIPPSS categories (Trust/Identity/Privacy/Protection/Safety/Security)
        "remediation":  str  — recommended remediation action
        "timestamp":    str  — ISO 8601 discovery timestamp
        "raw":          dict — raw data from source (optional)
    }
    """

    MODULE_NAME = "base"
    MODULE_LABEL = "Base Module"

    SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"]
    TIPPSS_CATEGORIES = ["Trust", "Identity", "Privacy", "Protection", "Safety", "Security"]

    def __init__(self, target: str = None, domain: str = None,
                 config: dict = None, verbose: bool = False):
        self.target = target or ""
        self.domain = domain or ""
        self.config = config or {}
        self.verbose = verbose
        self._findings: List[Dict[str, Any]] = []
        self._finding_counter = 0

    @abstractmethod
    def run(self) -> List[Dict[str, Any]]:
        """Execute the module and return a list of findings."""
        pass

    def _make_finding(self,
                      source: str,
                      query: str,
                      title: str,
                      description: str,
                      severity: str = "medium",
                      tippss: list = None,
                      remediation: str = "",
                      url: str = "",
                      raw: dict = None) -> Dict[str, Any]:
        """Create a standardized finding dict."""
        self._finding_counter += 1
        return {
            "id":          f"{self.MODULE_NAME}-{self._finding_counter:04d}",
            "module":      self.MODULE_NAME,
            "source":      source,
            "query":       query,
            "url":         url,
            "title":       title,
            "description": description,
            "severity":    severity if severity in self.SEVERITY_LEVELS else "info",
            "tippss":      tippss or [],
            "remediation": remediation,
            "timestamp":   datetime.datetime.utcnow().isoformat() + "Z",
            "raw":         raw or {}
        }

    def _throttle(self):
        """Respect configured delay between requests."""
        delay = self.config.get("rate_limits", {}).get("delay_between_requests", 2.0)
        time.sleep(delay)

    def _log(self, message: str, level: str = "info"):
        """Log a message if verbose mode is on."""
        if self.verbose:
            colors = {"info": "dim", "warn": "yellow", "error": "red", "success": "green"}
            style = colors.get(level, "dim")
            console.print(f"  [{style}][{self.MODULE_NAME}] {message}[/{style}]")
