# IEEE CyberSalukis HealthGuard OSINT

**An Open-Source Digital Public Good (DPG) — Automated OSINT Reconnaissance Framework for Healthcare AI Security**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-green.svg)](https://python.org)
[![DPG](https://img.shields.io/badge/Digital%20Public%20Good-DPG-purple.svg)](https://digitalpublicgoods.net)
[![IEEE SA Cybersecurity Hackathon 2026](https://img.shields.io/badge/IEEE%20SA-Cybersecurity%20Hackathon%202026-orange.svg)](https://ieee.org)

---

## Overview

**IEEE CyberSalukis HealthGuard OSINT** is the first open-source OSINT framework purpose-built for identifying, mapping, and reducing the AI attack surface of healthcare organizations. It is designed as a **Digital Public Good (DPG)** — free, open, and accessible to all health systems globally, including resource-constrained community hospitals, rural health systems, and public health agencies.

Healthcare organizations are deploying AI models, LLMs, agentic AI systems, and AI-connected IoT devices at an unprecedented pace. Most lack a structured, automated process for understanding what parts of those systems are externally discoverable, exposed, or vulnerable through open-source intelligence. This framework closes that gap.

> **HealthGuard OSINT replicates what a threat actor does during reconnaissance — so defenders can find and fix exposure before adversaries exploit it.**

---

## Features

| Module | Description |
|--------|-------------|
| `dork-scan` | Execute healthcare AI-specific dorks across **4 search engines**: Google CSE, Bing, Brave (independent index), and Mojeek (independent index) |
| `llm-recon` | LLM vulnerability surface discovery: prompt injection, API key leakage, model fingerprinting |
| `github-intel` | GitHub dork execution targeting AI config files, credentials, internal documentation |
| `shodan-scan` | Shodan queries for exposed medical IoT devices and AI infrastructure |
| `censys-scan` | Censys certificate and host intelligence for healthcare AI infrastructure discovery |
| `ivre-recon` | IVRE open-source (GPL v3) network recon — self-hostable, no vendor dependency |
| `leakix-scan` | LeakIX confirmed data leak and exposed service detection (content-verified, not just ports) |
| `vendor-intel` | Supply chain and vendor relationship intelligence gathering |
| `social-recon` | Personnel disclosure and social engineering surface analysis |
| `report` | Generate structured TIPPSS-mapped attack surface assessment reports |

---

## TIPPSS Framework Alignment

All findings are mapped to the **TIPPSS** security framework:

- **T**rust — AI system trustworthiness signals and governance indicators
- **I**dentity — Authentication surface, API key exposure, credential leakage
- **P**rivacy — PHI exposure, data leakage, PII in public repositories
- **P**rotection — Misconfigured endpoints, unpatched AI infrastructure, exposed admin interfaces
- **S**afety — Clinical AI integrity signals, hallucination risk indicators, IoT device exposure
- **S**ecurity — Attack surface breadth, vendor dependencies, social engineering vectors

---

## Quick Start

### Prerequisites

- Python 3.10 or higher
- pip
- API keys (free tiers sufficient): Shodan, Google Custom Search, GitHub, Censys (optional)

### Installation

```bash
git clone https://github.com/CyberSalukis/CyberSalukis-Healthguard-OSINT-.git
cd CyberSalukis-Healthguard-OSINT-
pip install -r requirements.txt
cp config/config.example.yaml config/config.yaml
# Edit config/config.yaml with your API keys
```

### Docker (Recommended for quick deployment)

```bash
docker build -t healthguard-osint .
docker run -v $(pwd)/config:/app/config -v $(pwd)/reports:/app/reports healthguard-osint --help
```

### Basic Usage

```bash
# Run a full assessment against a target organization
python healthguard.py --target "Memorial Hospital" --domain memorialhospital.org --all-modules

# Run individual modules
python healthguard.py --target "General Health System" --domain ghs.org --module dork-scan
python healthguard.py --target "General Health System" --domain ghs.org --module llm-recon
python healthguard.py --target "General Health System" --domain ghs.org --module github-intel

# Generate report from existing findings
python healthguard.py --report --input output/findings.json --format both

# Optional: allow low-impact HTTP endpoint checks when explicitly authorized
python healthguard.py --target "General Health System" --domain ghs.org --module llm-recon --enable-http-probes
```

---

## Output

HealthGuard OSINT produces:

- **JSON findings file** — machine-readable, SIEM-compatible structured output
- **Plain-text assessment report** — human-readable, TIPPSS-mapped, severity-rated
- **Executive summary** — non-technical summary for clinical leadership and compliance officers

### Sample Report Structure

```
IEEE CyberSalukis HealthGuard OSINT — Attack Surface Assessment
Target: [Organization Name]
Assessment Date: [Date]
Modules Run: [List]

EXECUTIVE SUMMARY
─────────────────
Critical Findings: X
High Findings:     X
Medium Findings:   X
Low Findings:      X

TIPPSS MAPPING
──────────────
[T] TRUST       — X findings
[I] IDENTITY    — X findings
[P] PRIVACY     — X findings
[P] PROTECTION  — X findings
[S] SAFETY      — X findings
[S] SECURITY    — X findings

DETAILED FINDINGS
─────────────────
[Finding entries with source, severity, TIPPSS category, and remediation recommendation]
```

---

## Repository Structure

```
CyberSalukis-Healthguard-OSINT-/
├── healthguard.py              # Main CLI entry point
├── requirements.txt            # Python dependencies
├── Dockerfile                  # Container deployment
├── LICENSE
├── .gitignore
├── config/
│   └── config.example.yaml     # Configuration template; copy to config.yaml locally
├── src/
│   ├── config/
│   │   └── loader.py           # Config management
│   ├── modules/                # Reconnaissance modules
│   │   ├── base.py
│   │   ├── dork_scan.py
│   │   ├── llm_recon.py
│   │   ├── github_intel.py
│   │   ├── shodan_scan.py
│   │   ├── censys_scan.py
│   │   ├── ivre_recon.py
│   │   ├── leakix_scan.py
│   │   ├── vendor_intel.py
│   │   └── social_recon.py
│   ├── utils/
│   │   ├── normalizer.py       # Results normalization and deduplication
│   │   └── tippss_mapper.py    # TIPPSS category mapping
│   └── reports/
│       └── report_generator.py # Report generation
├── queries/
│   ├── dorks/
│   │   ├── healthcare_ai.yaml
│   │   ├── llm_endpoints.yaml
│   │   └── phi_exposure.yaml
│   ├── shodan/
│   │   ├── ai_infrastructure.yaml
│   │   └── medical_iot.yaml
│   ├── censys/
│   │   └── health_networks.yaml
│   ├── ivre/
│   │   └── healthcare_scans.yaml
│   └── leakix/
│       └── healthcare_leaks.yaml
├── docs/
│   ├── GETTING_STARTED.md
│   ├── METHODOLOGY.md
│   ├── TIPPSS_MAPPING.md
│   ├── RESPONSIBLE_USE.md
│   └── CONTRIBUTING.md
└── output_samples/
    ├── sample_report.txt
    └── sample_report.json
```

---

## Responsible Use

**This framework is designed exclusively for authorized defensive security assessments.**

- Use only against infrastructure you own or have explicit written authorization to assess
- Passive OSINT is the default mode; optional low-impact HTTP endpoint checks require explicit authorization and `--enable-http-probes`
- No exploitation, payload delivery, credential guessing, or unauthorized access
- Review your jurisdiction's computer access laws before use
- See [RESPONSIBLE_USE.md](docs/RESPONSIBLE_USE.md) for full policy

**Misuse of this framework against systems without authorization is illegal and unethical. The IEEE CyberSalukis team and contributors bear no responsibility for unauthorized use.**

---

## Contributing

This is a community-maintained Digital Public Good. Contributions are welcome and encouraged, particularly:

- New healthcare AI dork entries in the YAML query libraries
- Additional Shodan/Censys query sets for emerging AI infrastructure
- Translations of documentation for international health system teams
- Bug fixes and module improvements

See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for guidelines.

---

## Team

**IEEE CyberSalukis** — IEEE SA Cybersecurity Hackathon 2026

---

## License

MIT License — see [LICENSE](LICENSE) for details.

This project is submitted as a **Digital Public Good (DPG)** under the DPG Standard, ensuring it is open-source, uses open standards, and is designed for broad public benefit.
