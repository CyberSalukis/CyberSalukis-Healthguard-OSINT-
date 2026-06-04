"""
Configuration loader for IEEE CyberSalukis HealthGuard OSINT
"""

import yaml
import os
from pathlib import Path


DEFAULT_CONFIG = {
    "api_keys": {
        "shodan": "",
        "google_cse_api_key": "",
        "google_cse_cx": "",
        "github_token": "",
        "censys_api_id": "",
        "censys_api_secret": "",
    },
    "rate_limits": {
        "google_requests_per_day": 100,
        "shodan_requests_per_second": 1,
        "github_requests_per_hour": 60,
        "delay_between_requests": 2.0,
    },
    "scope": {
        "max_results_per_query": 10,
        "max_github_repos": 20,
        "passive_only": True,
    },
    "output": {
        "include_raw_urls": True,
        "severity_threshold": "low",
    }
}


def load_config(config_path: str = "config/config.yaml") -> dict:
    """
    Load configuration from YAML file.
    Falls back to defaults if file not found.
    Environment variables override file values for API keys.
    """
    cfg = DEFAULT_CONFIG.copy()

    path = Path(config_path)
    if path.exists():
        with open(path) as f:
            file_cfg = yaml.safe_load(f) or {}
        cfg = _deep_merge(cfg, file_cfg)

    # Environment variable overrides (preferred for CI/CD)
    env_keys = {
        "SHODAN_API_KEY":        ("api_keys", "shodan"),
        "GOOGLE_CSE_API_KEY":    ("api_keys", "google_cse_api_key"),
        "GOOGLE_CSE_CX":         ("api_keys", "google_cse_cx"),
        "GITHUB_TOKEN":          ("api_keys", "github_token"),
        "CENSYS_API_ID":         ("api_keys", "censys_api_id"),
        "CENSYS_API_SECRET":     ("api_keys", "censys_api_secret"),
    }
    for env_var, (section, key) in env_keys.items():
        val = os.environ.get(env_var)
        if val:
            cfg[section][key] = val

    return cfg


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base."""
    result = base.copy()
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result
