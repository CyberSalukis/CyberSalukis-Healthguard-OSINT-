"""
IEEE CyberSalukis HealthGuard OSINT
Module: github_intel.py — GitHub Intelligence

Discovers healthcare AI attack surface through GitHub:
exposed API keys, AI configuration files, internal architecture
documentation, and repositories revealing system design.
"""

import yaml
import requests
from pathlib import Path
from typing import List, Dict, Any
from .base import BaseModule


class GitHubIntel(BaseModule):
    """
    GitHub OSINT reconnaissance module.
    Uses GitHub Search API (authenticated via token) to find repositories,
    files, and code associated with the target organization.
    """

    MODULE_NAME = "github-intel"
    MODULE_LABEL = "GitHub Intelligence"

    GITHUB_SEARCH_URL = "https://api.github.com/search"

    # File patterns that commonly contain secrets or sensitive AI config
    SENSITIVE_FILE_PATTERNS = [
        ".env", "config.yaml", "config.json", "settings.py",
        "docker-compose.yml", ".env.local", "secrets.yaml",
        "application.yml", "application.properties",
    ]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.token = self.config.get("api_keys", {}).get("github_token", "")
        self.max_repos = self.config.get("scope", {}).get("max_github_repos", 20)
        self.headers = {}
        if self.token:
            self.headers["Authorization"] = f"token {self.token}"
        self.headers["Accept"] = "application/vnd.github.v3+json"

    def run(self) -> List[Dict[str, Any]]:
        """Execute GitHub intelligence gathering."""
        findings = []

        if not self.token:
            self._log("No GitHub token configured — running with unauthenticated API (lower rate limit)", "warn")

        findings.extend(self._search_api_key_exposure())
        findings.extend(self._search_ai_config_files())
        findings.extend(self._search_healthcare_ai_repos())
        findings.extend(self._search_sensitive_file_patterns())

        return findings

    def _github_search(self, endpoint: str, query: str, search_type: str = "repositories") -> List[Dict]:
        """Execute a GitHub search API query."""
        url = f"{self.GITHUB_SEARCH_URL}/{endpoint}"
        params = {"q": query, "per_page": min(self.max_repos, 30), "sort": "indexed"}
        try:
            resp = requests.get(url, headers=self.headers, params=params, timeout=15)
            if resp.status_code == 403:
                self._log("GitHub rate limit hit — pausing", "warn")
                import time; time.sleep(60)
                return []
            resp.raise_for_status()
            return resp.json().get("items", [])
        except Exception as e:
            self._log(f"GitHub search error: {e}", "error")
            return []

    def _search_api_key_exposure(self) -> List[Dict[str, Any]]:
        """Search for exposed LLM API keys in GitHub code."""
        findings = []
        key_patterns = [
            ("OPENAI_API_KEY",    "OpenAI API Key Exposure",    "critical"),
            ("ANTHROPIC_API_KEY", "Anthropic API Key Exposure",  "critical"),
            ("AZURE_OPENAI_KEY",  "Azure OpenAI Key Exposure",   "critical"),
            ("sk-proj-",          "OpenAI Project Key Pattern",  "critical"),
            ("GOOGLE_AI_KEY",     "Google AI API Key Exposure",  "critical"),
            ("HUGGINGFACE_TOKEN", "HuggingFace Token Exposure",  "high"),
        ]

        org_qualifier = f'org:{self.target.replace(" ", "")}' if self.target else ""
        domain_qualifier = f'"{self.domain}"' if self.domain else f'"{self.target}"'

        for pattern, title, severity in key_patterns:
            query = f"{pattern} {domain_qualifier or org_qualifier}"
            self._log(f"Searching GitHub code: {query[:60]}...")
            results = self._github_search("code", query)

            for item in results[:5]:  # Cap at 5 per pattern to avoid noise
                finding = self._make_finding(
                    source="GitHub Code Search",
                    query=query,
                    title=title,
                    description=(
                        f"A GitHub code search for '{pattern}' associated with "
                        f"{self.target or self.domain} returned results. "
                        f"File: {item.get('name', 'unknown')} in repository "
                        f"{item.get('repository', {}).get('full_name', 'unknown')}. "
                        f"Exposed LLM API keys enable unauthorized model access, "
                        f"billing abuse, and potential access to fine-tuned models "
                        f"trained on healthcare data."
                    ),
                    severity=severity,
                    tippss=["Identity", "Security"],
                    remediation=(
                        "Immediately rotate the exposed API key. Remove from repository history "
                        "using git-filter-repo. Enable GitHub secret scanning. Implement "
                        "pre-commit hooks (detect-secrets, gitleaks). Audit key usage logs "
                        "for unauthorized access."
                    ),
                    url=item.get("html_url", ""),
                    raw={"name": item.get("name"), "repo": item.get("repository", {}).get("full_name")}
                )
                findings.append(finding)

            self._throttle()

        return findings

    def _search_ai_config_files(self) -> List[Dict[str, Any]]:
        """Search for AI configuration files in target-associated repositories."""
        findings = []
        config_searches = [
            ('filename:.env "openai" OR "anthropic" OR "llm"', "AI Config in .env File"),
            ('filename:config.yaml "model" "api_key" OR "endpoint"', "AI Config YAML with Credentials"),
            ('filename:docker-compose.yml "openai" OR "llm" OR "ollama"', "AI Service in Docker Compose"),
            ('"system_prompt" OR "system prompt" "healthcare" OR "clinical" OR "patient"', "System Prompt in Code"),
        ]

        org_qualifier = f'org:{self.target.replace(" ", "")}' if self.target else f'"{self.target or self.domain}"'

        for search_suffix, title in config_searches:
            query = f"{org_qualifier} {search_suffix}"
            self._log(f"Config file search: {title}")
            results = self._github_search("code", query)

            for item in results[:3]:
                finding = self._make_finding(
                    source="GitHub Code Search",
                    query=query,
                    title=title,
                    description=(
                        f"GitHub search found '{title}' associated with {self.target or self.domain}. "
                        f"Repository: {item.get('repository', {}).get('full_name', 'unknown')}. "
                        f"AI configuration files in public repositories may expose API keys, "
                        f"endpoint URLs, system prompts, model names, and data source connections "
                        f"that enable targeted attacks against the healthcare AI deployment."
                    ),
                    severity="high",
                    tippss=["Identity", "Privacy", "Security"],
                    remediation=(
                        "Remove sensitive configuration files from public repositories. "
                        "Add sensitive file patterns to .gitignore. "
                        "Rotate any credentials found in configuration files. "
                        "Use environment variables or secrets management for API credentials."
                    ),
                    url=item.get("html_url", ""),
                    raw={"name": item.get("name"), "repo": item.get("repository", {}).get("full_name")}
                )
                findings.append(finding)

            self._throttle()

        return findings

    def _search_healthcare_ai_repos(self) -> List[Dict[str, Any]]:
        """Search for repositories revealing healthcare AI architecture."""
        findings = []
        repo_searches = [
            (f'"{self.target or self.domain}" healthcare AI LLM', "Healthcare AI Repository"),
            (f'"{self.target or self.domain}" EHR OR "Epic" OR "Cerner" AI', "EHR-AI Integration Repository"),
            (f'"{self.target or self.domain}" HIPAA AI OR "machine learning"', "HIPAA-Context AI Repository"),
        ]

        for query, title in repo_searches:
            self._log(f"Repo search: {query[:60]}...")
            results = self._github_search("repositories", query)

            for item in results[:3]:
                desc = item.get("description", "No description")
                finding = self._make_finding(
                    source="GitHub Repository Search",
                    query=query,
                    title=f"{title}: {item.get('full_name', 'unknown')}",
                    description=(
                        f"GitHub repository associated with {self.target or self.domain} "
                        f"contains healthcare AI content. "
                        f"Repository: {item.get('full_name', 'unknown')}. "
                        f"Description: {desc}. "
                        f"Stars: {item.get('stargazers_count', 0)}, "
                        f"Public: {not item.get('private', False)}. "
                        f"Public repositories reveal AI system architecture, integration "
                        f"patterns, and potentially sensitive implementation details."
                    ),
                    severity="medium",
                    tippss=["Trust", "Security"],
                    remediation=(
                        "Audit public repositories for sensitive content. "
                        "Consider restricting repositories containing healthcare AI implementation details. "
                        "Remove any PHI, credentials, or internal system references."
                    ),
                    url=item.get("html_url", ""),
                    raw={"name": item.get("full_name"), "description": desc, "stars": item.get("stargazers_count")}
                )
                findings.append(finding)

            self._throttle()

        return findings

    def _search_sensitive_file_patterns(self) -> List[Dict[str, Any]]:
        """Search for sensitive file patterns in target-associated repositories."""
        findings = []
        org_qualifier = f'org:{self.target.replace(" ", "")}' if self.target else f'"{self.target or self.domain}"'

        sensitive_searches = [
            (f'{org_qualifier} filename:*.pem OR filename:*.key "healthcare" OR "AI"', "Private Key in Healthcare AI Repo", "critical"),
            (f'{org_qualifier} "patient_data" OR "phi" OR "ehr_data" filename:*.csv OR filename:*.json', "Healthcare Data in Repository", "critical"),
            (f'{org_qualifier} "training_data" "clinical" OR "patient" OR "medical"', "Clinical AI Training Data Reference", "high"),
        ]

        for query, title, severity in sensitive_searches:
            self._log(f"Sensitive file search: {title}")
            results = self._github_search("code", query)

            for item in results[:3]:
                finding = self._make_finding(
                    source="GitHub Code Search",
                    query=query,
                    title=title,
                    description=(
                        f"Sensitive file pattern search for '{title}' returned results "
                        f"associated with {self.target or self.domain}. "
                        f"File: {item.get('name', 'unknown')} in "
                        f"{item.get('repository', {}).get('full_name', 'unknown')}."
                    ),
                    severity=severity,
                    tippss=["Privacy", "Protection", "Security"],
                    remediation=(
                        "Immediately review and remove sensitive files from repositories. "
                        "Rotate any exposed credentials. Audit repository for HIPAA compliance. "
                        "Implement automated secret and sensitive data scanning in CI/CD pipeline."
                    ),
                    url=item.get("html_url", ""),
                    raw={"name": item.get("name"), "repo": item.get("repository", {}).get("full_name")}
                )
                findings.append(finding)

            self._throttle()

        return findings
