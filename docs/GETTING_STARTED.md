# Getting Started Guide
## IEEE CyberSalukis HealthGuard OSINT
### Open-Source Digital Public Good (DPG) | Healthcare AI Attack Surface Reconnaissance

---

> **Before you begin:** Read [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md).
> This framework is for authorized defensive security assessments only.
> Use it against infrastructure you own or have explicit written permission to assess.

---

## Table of Contents

1. [What Is HealthGuard OSINT?](#1-what-is-healthguard-osint)
2. [Who Is This For?](#2-who-is-this-for)
3. [How It Works — Plain Language Overview](#3-how-it-works--plain-language-overview)
4. [System Requirements](#4-system-requirements)
5. [Installation](#5-installation)
   - [Option A: Python (Recommended)](#option-a-python-recommended)
   - [Option B: Docker (Zero dependency)](#option-b-docker-zero-dependency)
   - [Option C: Environment Variables](#option-c-environment-variables-cicd-friendly)
6. [API Key Setup](#6-api-key-setup)
   - [Free Tier Summary](#free-tier-summary)
   - [Google Custom Search](#google-custom-search-engine-cse)
   - [Bing Web Search](#bing-web-search-api)
   - [Brave Search](#brave-search-api)
   - [Mojeek Search](#mojeek-search-api)
   - [Shodan](#shodan)
   - [GitHub](#github)
   - [Censys](#censys)
   - [LeakIX](#leakix)
   - [Running Without API Keys](#running-without-api-keys-dry-run-mode)
7. [Your First Assessment — Step by Step](#7-your-first-assessment--step-by-step)
8. [All Modules Explained](#8-all-modules-explained)
   - [dork-scan](#dork-scan--multi-engine-search-dork-scanner)
   - [llm-recon](#llm-recon--llm-vulnerability-surface-recon)
   - [github-intel](#github-intel--github-intelligence)
   - [shodan-scan](#shodan-scan--shodan-iot--infrastructure-scanner)
   - [censys-scan](#censys-scan--censys-infrastructure-scanner)
   - [ivre-recon](#ivre-recon--ivre-open-source-network-recon)
   - [leakix-scan](#leakix-scan--leakix-data-leak-scanner)
   - [vendor-intel](#vendor-intel--vendor-supply-chain-intelligence)
   - [social-recon](#social-recon--social-engineering-surface-analyzer)
9. [Configuration Reference](#9-configuration-reference)
10. [Understanding Your Report](#10-understanding-your-report)
    - [Severity Levels](#severity-levels)
    - [TIPPSS Framework](#tippss-framework)
    - [Report Sections](#report-sections)
    - [JSON Output for SIEM](#json-output-for-siem-integration)
11. [The Query Library](#11-the-query-library)
12. [Common Workflows](#12-common-workflows)
13. [Troubleshooting](#13-troubleshooting)
14. [Next Steps](#14-next-steps)

---

## 1. What Is HealthGuard OSINT?

**IEEE CyberSalukis HealthGuard OSINT** is a free, open-source Python framework that automatically searches publicly available information to identify security risks in healthcare organizations' AI systems — before adversaries find them first.

It is a **Digital Public Good (DPG)**: free to use, free to modify, free to distribute. No licensing fees. No vendor lock-in. Designed to be accessible to any health system in the world, including those with limited security budgets.

The framework uses **Open Source Intelligence (OSINT)** — the same techniques cybercriminals use during the reconnaissance phase of an attack — to map what information about a healthcare organization's AI infrastructure is visible from the public internet. It then produces reports written in plain language for both technical security teams and non-technical stakeholders like compliance officers, privacy officers, and clinical leadership.

### What it finds

- AI model APIs and endpoints exposed to the open internet without authentication
- API keys and credentials accidentally posted in public code repositories
- Patient data files accessible in cloud storage without passwords
- Development servers (Jupyter notebooks, AI demo interfaces) open to the internet
- AI vendor relationships visible in public records that enable supply chain attacks
- Clinical staff disclosing AI tool usage on public professional networks
- Medical IoT devices with internet-accessible management interfaces
- Historical exposure in web archives and certificate transparency logs

### What it does NOT do

- It does not hack, exploit, or access any system without authorization
- It does not perform active network scanning by default. Optional low-impact HTTP endpoint checks require explicit authorization and `--enable-http-probes`.
- It does not access any data behind a login or authentication wall
- It does not store, transmit, or retain any patient data

---

## 2. Who Is This For?

| Role | How to Use This Guide |
|------|-----------------------|
| **Healthcare Security Analyst** | Read everything. You will run assessments and interpret findings. |
| **IT Security Generalist** | Read Sections 3–10. Focus on Installation, API Setup, and Running Modules. |
| **CISO / Security Manager** | Read Sections 1–3 and Section 10 (Understanding Your Report). |
| **Compliance / Privacy Officer** | Read Sections 1–3 and Section 10. Focus on HIPAA implications in reports. |
| **Security Researcher / CTF** | Read Sections 5–12. You know what you're doing — go fast. |
| **Community Contributor** | Read [CONTRIBUTING.md](CONTRIBUTING.md) after completing this guide. |

---

## 3. How It Works — Plain Language Overview

Think of HealthGuard OSINT as a cybercriminal's reconnaissance toolkit — repurposed for defense.

Before launching an attack on a healthcare organization, a sophisticated adversary would spend days or weeks collecting publicly available information: searching Google for exposed configuration files, checking GitHub for accidentally committed API keys, querying Shodan for internet-facing AI servers, and scanning LinkedIn to understand which clinical staff are using which AI tools.

HealthGuard OSINT automates that exact process and runs it against your own infrastructure — so your security team finds the exposure first.

```
┌─────────────────────────────────────────────────────────┐
│                                                         │
│   You provide:  Organization name + domain              │
│                                                         │
│   Framework queries:                                    │
│   • Google, Bing, Brave, Mojeek (search dorks)         │
│   • GitHub (code and credential search)                 │
│   • Shodan, Censys, IVRE, LeakIX (infrastructure)      │
│   • Vendor databases (supply chain)                     │
│   • LinkedIn via Google (personnel disclosure)          │
│                                                         │
│   Output:                                               │
│   • Plain-language report for leadership                │
│   • Technical report for security team                  │
│   • JSON findings for SIEM integration                  │
│   • Prioritized remediation checklist                   │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

Default mode is **passive OSINT** — search/API-based collection against information already publicly available on the internet. Optional low-impact HTTP endpoint checks can be enabled only when authorized with `--enable-http-probes`.

---

## 4. System Requirements

### Minimum Requirements

| Component | Requirement |
|-----------|-------------|
| Operating System | Windows 10+, macOS 11+, Linux (Ubuntu 20.04+) |
| Python | 3.10 or higher |
| Memory | 512 MB RAM |
| Disk Space | 100 MB |
| Internet | Required for all live queries |
| Python pip | Included with Python 3.10+ |

### Check Your Python Version

```bash
python --version
# or
python3 --version
```

You should see `Python 3.10.x` or higher. If not, download from https://python.org/downloads/

### Optional: Docker

Docker is not required but simplifies deployment on servers or in CI/CD pipelines. Download from https://docker.com if you want to use the Docker installation option.

---

## 5. Installation

### Option A: Python (Recommended)

This is the standard installation method for desktop use and direct assessment work.

**Step 1 — Clone the repository**

```bash
git clone https://github.com/CyberSalukis/CyberSalukis-Healthguard-OSINT-.git
cd CyberSalukis-Healthguard-OSINT-
```

> Don't have git? Download the ZIP from the GitHub repository page and extract it.

**Step 2 — Install Python dependencies**

```bash
pip install -r requirements.txt
```

If you get a permissions error on Linux/macOS, try:

```bash
pip install --user -r requirements.txt
```

> This installs: requests, rich, click, PyYAML, pandas, Jinja2, shodan, PyGithub, and other dependencies. All are open source and freely available.

**Step 3 — Set up your configuration**

```bash
cp config/config.example.yaml config/config.yaml
```

Then open `config/config.yaml` in any text editor and add your API keys. See [Section 6](#6-api-key-setup) for where to get each key.

**Step 4 — Verify the installation**

```bash
python healthguard.py --help
```

You should see the HealthGuard OSINT banner and a list of available options. If you see this, the installation is complete.

---

### Option B: Docker (Zero dependency)

Use Docker if you want to run HealthGuard OSINT on a server, in a CI/CD pipeline, or without installing Python on your local machine.

**Step 1 — Clone and build**

```bash
git clone https://github.com/CyberSalukis/CyberSalukis-Healthguard-OSINT-.git
cd CyberSalukis-Healthguard-OSINT-

docker build -t healthguard-osint .
```

**Step 2 — Set up configuration**

```bash
cp config/config.example.yaml config/config.yaml
# Edit config/config.yaml with your API keys
```

**Step 3 — Run an assessment**

```bash
docker run \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/output:/app/output \
  healthguard-osint \
  --target "Memorial Hospital" \
  --domain memorialhospital.org \
  --all-modules \
  --format both
```

Output files are saved to `./output/` on your local machine.

**Verify Docker install:**

```bash
docker run healthguard-osint --help
```

---

### Option C: Environment Variables (CI/CD-friendly)

Use environment variables instead of a config file for automated pipelines or when you cannot store files on the system.

```bash
# Linux / macOS
export SHODAN_API_KEY="your_shodan_key"
export GOOGLE_CSE_API_KEY="your_google_key"
export GOOGLE_CSE_CX="your_search_engine_id"
export BING_API_KEY="your_bing_key"
export BRAVE_API_KEY="your_brave_key"
export MOJEEK_API_KEY="your_mojeek_key"
export GITHUB_TOKEN="your_github_token"
export CENSYS_API_ID="your_censys_id"
export CENSYS_API_SECRET="your_censys_secret"

python healthguard.py --target "Your Org" --domain yourdomain.org --all-modules
```

```powershell
# Windows PowerShell
$env:SHODAN_API_KEY="your_shodan_key"
$env:GOOGLE_CSE_API_KEY="your_google_key"
$env:GOOGLE_CSE_CX="your_search_engine_id"
$env:BING_API_KEY="your_bing_key"
$env:BRAVE_API_KEY="your_brave_key"
$env:MOJEEK_API_KEY="your_mojeek_key"
$env:GITHUB_TOKEN="your_github_token"

python healthguard.py --target "Your Org" --domain yourdomain.org --all-modules
```

Environment variables take priority over config file values.

---

## 6. API Key Setup

HealthGuard OSINT operates on **free-tier APIs only** for all baseline functionality. You do not need to pay for anything to run a complete assessment. Paid tiers increase query limits for larger or more frequent assessments.

### Free Tier Summary

| Service | What It Does | Free Tier | Key Required | Sign Up |
|---------|-------------|-----------|--------------|---------|
| Google CSE | Web dork execution | 100 queries/day | Yes | https://programmablesearchengine.google.com |
| Bing Web Search | Independent index dorks | 1,000/month | Yes (Azure) | https://azure.microsoft.com |
| Brave Search | Independent index dorks | 2,000/month | Yes | https://brave.com/search/api/ |
| Mojeek Search | Independent index dorks | Free | Yes | https://www.mojeek.com/services/search/web-search-api/ |
| Shodan | IoT & infrastructure scan | Basic | Yes | https://account.shodan.io/register |
| GitHub | Code & credential search | 60 req/hr | Optional | https://github.com/settings/tokens |
| Censys | Certificate & host intel | 250/month | Yes | https://search.censys.io/register |
| LeakIX | Confirmed data leaks | ~50/day | Yes | https://leakix.net |
| IVRE | Open-source net recon | Unlimited (self-hosted) | No | https://ivre.rocks |

> **Minimum recommended setup:** Get at least one search engine key (Google or Brave), GitHub token, and Shodan key. This gives you meaningful coverage across all major finding categories.

---

### Google Custom Search Engine (CSE)

Google CSE lets HealthGuard OSINT execute dork queries programmatically.

**Step 1 — Create a Custom Search Engine**
1. Go to https://programmablesearchengine.google.com
2. Click **Add** or **New search engine**
3. In "Sites to search" enter `www.google.com` (we override this with dork queries)
4. Name it (e.g., "HealthGuard OSINT")
5. Click **Create**
6. Copy the **Search engine ID** (looks like `abc123:xyz456`)

**Step 2 — Get an API Key**
1. Go to https://console.developers.google.com
2. Create a project (or use an existing one)
3. Enable the **Custom Search API**
4. Go to Credentials → **Create Credentials** → API Key
5. Copy the API key

**Step 3 — Add to config.yaml**
```yaml
api_keys:
  google_cse_api_key: "YOUR_API_KEY_HERE"
  google_cse_cx: "YOUR_SEARCH_ENGINE_ID_HERE"
```

**Free tier:** 100 queries/day. Sufficient for targeted single-organization assessments.

---

### Bing Web Search API

Bing maintains an independent search index from Google. It is particularly strong at surfacing Microsoft Azure and SharePoint-hosted healthcare AI documentation.

**Step 1 — Create an Azure account**
1. Go to https://azure.microsoft.com/free (free account available)
2. Sign in or create an account

**Step 2 — Create a Bing Search resource**
1. In the Azure portal, search for **Bing Search v7**
2. Click **Create**
3. Select the **F1 (Free)** tier — 1,000 transactions/month
4. Complete creation and go to the resource
5. Click **Keys and Endpoint**
6. Copy **KEY 1**

**Step 3 — Add to config.yaml**
```yaml
api_keys:
  bing_api_key: "YOUR_BING_KEY_HERE"
```

**Free tier:** 1,000 queries/month. No credit card required on F1 tier.

---

### Brave Search API

Brave Search is built on a fully independent crawler — the only major search engine that does not use Google or Bing data. This provides genuine index diversity and is the strongest DPG-aligned search integration in the framework.

**Step 1 — Sign up**
1. Go to https://brave.com/search/api/
2. Click **Get Started** under the Free plan
3. Create an account

**Step 2 — Get your API key**
1. In the dashboard, go to **API Keys**
2. Click **Create API Key**
3. Copy the key

**Step 3 — Add to config.yaml**
```yaml
api_keys:
  brave_api_key: "YOUR_BRAVE_KEY_HERE"
```

**Free tier:** 2,000 queries/month. The most generous free tier among the four search engines.

---

### Mojeek Search API

Mojeek is a privacy-focused search engine with its own crawler built in the UK. No Google, no Bing, no Microsoft infrastructure underneath it. Unique results that complement the other three engines.

**Step 1 — Sign up**
1. Go to https://www.mojeek.com/services/search/web-search-api/
2. Click **Apply for API access**
3. Complete the registration form

**Step 2 — Get your API key**
1. Confirm your email
2. API key will be provided in your account dashboard

**Step 3 — Add to config.yaml**
```yaml
api_keys:
  mojeek_api_key: "YOUR_MOJEEK_KEY_HERE"
```

**Free tier:** Available at no cost for non-commercial and security research use.

---

### Shodan

Shodan is the primary internet infrastructure search engine. It continuously scans the internet and indexes what services are running on every public IP address. HealthGuard OSINT uses Shodan to find exposed AI servers, medical IoT devices, and misconfigured healthcare infrastructure.

**Step 1 — Create account**
1. Go to https://account.shodan.io/register
2. Create a free account

**Step 2 — Get your API key**
1. Log in and click on your username
2. Your API key is shown on your account page
3. Copy it

**Step 3 — Add to config.yaml**
```yaml
api_keys:
  shodan: "YOUR_SHODAN_KEY_HERE"
```

**Free tier:** Supports targeted host lookups and basic search queries. Sufficient for domain-specific healthcare AI assessments.

> **Note:** Shodan is a proprietary commercial service. The framework uses it as a data source via its public API. The framework code itself remains fully open source.

---

### GitHub

GitHub token enables HealthGuard OSINT to search public code repositories for exposed API keys, AI configuration files, and healthcare AI architecture disclosures associated with the target organization.

**Step 1 — Create a token**
1. Go to https://github.com/settings/tokens
2. Click **Generate new token (classic)**
3. Name it (e.g., "HealthGuard OSINT")
4. Select scopes: **public_repo** (read access to public repositories only)
5. Click **Generate token**
6. Copy the token immediately (it will not be shown again)

**Step 2 — Add to config.yaml**
```yaml
api_keys:
  github_token: "YOUR_GITHUB_TOKEN_HERE"
```

**Without a token:** GitHub Search API allows 10 unauthenticated requests/minute. This is sufficient for small assessments but may hit rate limits on comprehensive scans.

---

### Censys

Censys provides internet-wide host scanning data and certificate transparency intelligence. It is particularly strong for discovering subdomains and services via SSL certificate history.

**Step 1 — Create account**
1. Go to https://search.censys.io/register
2. Create a free community account

**Step 2 — Get API credentials**
1. Go to https://search.censys.io/account
2. Copy your **API ID** and **API Secret**

**Step 3 — Add to config.yaml**
```yaml
api_keys:
  censys_api_id: "YOUR_CENSYS_ID_HERE"
  censys_api_secret: "YOUR_CENSYS_SECRET_HERE"
```

**Free tier:** 250 queries/month on the community plan.

---

### LeakIX

LeakIX indexes confirmed data exposures — not just open ports, but verified accessible content. It is particularly valuable for healthcare AI assessments because it confirms actual data leakage rather than theoretical exposure.

**Step 1 — Create account**
1. Go to https://leakix.net
2. Click **Register** and create a free account

**Step 2 — Get your API key**
1. Go to your profile settings
2. Copy your API key

**Step 3 — Add to config.yaml**
```yaml
api_keys:
  leakix_api_key: "YOUR_LEAKIX_KEY_HERE"
```

**Free tier:** Approximately 50 queries/day. Sufficient for targeted domain assessments.

---

### Running Without API Keys (DRY-RUN Mode)

You can run HealthGuard OSINT with no API keys at all. In DRY-RUN mode, each module returns its complete query library as documented findings — giving you every query you would need to execute manually, pre-formatted with severity ratings, TIPPSS mappings, and remediation guidance.

```bash
# No API keys configured — runs in DRY-RUN mode automatically
python healthguard.py --target "Your Org" --domain yourdomain.org --all-modules
```

DRY-RUN output is still a complete, useful deliverable: a documented assessment plan with all queries listed, ready for manual execution or as the basis for a scope-of-work document.

---

## 7. Your First Assessment — Step by Step

This section walks through a complete assessment from start to first report.

### Before You Begin

Confirm you have:
- [ ] Completed installation (Section 5)
- [ ] At least one API key configured (Section 6) — or plan to run in DRY-RUN mode
- [ ] Written authorization to assess the target (your own org, or signed scope of work)
- [ ] Read [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md)

### Step 1 — Open a terminal

```bash
# Navigate to the HealthGuard OSINT directory
cd CyberSalukis-Healthguard-OSINT-
```

### Step 2 — Confirm everything is working

```bash
python healthguard.py --help
```

You should see the banner and options list. If you see an error, go to [Section 13 — Troubleshooting](#13-troubleshooting).

### Step 3 — Run a single module first

Before running all modules, start with one to confirm your API keys work and understand the output format.

```bash
python healthguard.py \
  --target "Your Organization Name" \
  --domain yourdomain.org \
  --module dork-scan \
  --verbose
```

Replace `"Your Organization Name"` and `yourdomain.org` with your target.

The `--verbose` flag shows you exactly what queries are being executed in real time.

### Step 4 — Review the output

Output files are saved to `./output/`. The naming format is:

```
output/
└── yourorganization_20260602_143022_findings.json
└── yourorganization_20260602_143022_report.txt
```

Open the `.txt` report first. It is written in plain language. Check that it looks correct and that the target is right.

### Step 5 — Run the full assessment

Once you have confirmed the single-module run works:

```bash
python healthguard.py \
  --target "Your Organization Name" \
  --domain yourdomain.org \
  --all-modules \
  --format both \
  --verbose
```

`--format both` produces both the plain-text report and the JSON file.

A full assessment typically takes 5–20 minutes depending on how many API keys are configured and your network speed.

### Step 6 — Review your report

Open `output/*_report.txt` in any text editor. The report is organized into sections:

1. Plain Language Executive Summary — for leadership and compliance
2. Risk Dashboard — severity counts and TIPPSS mapping
3. Critical Findings — immediate action required
4. High Priority Findings — this week
5. Medium Findings — this month
6. Low / Informational Findings
7. Remediation Timeline Checklist
8. Compliance and Regulatory Implications

For a full explanation of the report structure, see [Section 10](#10-understanding-your-report).

### Step 7 — Repeat regularly

An OSINT attack surface is not static. New employees post on LinkedIn. New repositories get committed. New services get deployed. Run HealthGuard OSINT on a regular schedule — quarterly at minimum, monthly for high-risk environments.

---

## 8. All Modules Explained

HealthGuard OSINT has nine reconnaissance modules. Each can be run individually or all together with `--all-modules`.

---

### `dork-scan` — Multi-Engine Search Dork Scanner

**What it does:** Executes a library of healthcare AI-specific search queries (dorks) across four independent search engines simultaneously: Google, Bing, Brave, and Mojeek. Each engine maintains a different index, so running all four maximizes coverage.

**What it finds:**
- Exposed LLM API endpoints indexed by search engines
- AI configuration files (YAML, JSON, .env) in public web directories
- Patient data files in public cloud storage (S3, Azure Blob)
- AI demo interfaces (Gradio, Streamlit) accessible publicly
- Jupyter notebook servers without authentication
- System prompts and AI behavioral instructions in page source
- GitHub repositories with AI architecture details

**When to use it:** Always. This is the broadest-coverage module and should always be included in any assessment.

**API keys required:** At least one of: Google CSE, Bing, Brave, or Mojeek.

**Example:**
```bash
python healthguard.py -t "Memorial Hospital" -d memorialhospital.org -m dork-scan --verbose
```

**DRY-RUN output:** Returns all 24+ dork queries pre-formatted for manual Google/Bing execution.

---

### `llm-recon` — LLM Vulnerability Surface Recon

**What it does:** Documents the LLM-specific vulnerability surface for healthcare AI deployments using search/API OSINT. Optional low-impact HTTP endpoint checks can be enabled only when explicitly authorized.

**What it finds:**
- OpenAI-compatible API endpoints returning HTTP 200 without authentication
- Ollama, vLLM, LM Studio, and LocalAI servers accessible publicly
- LangChain and LlamaIndex RAG application endpoints
- Clinical AI chatbot interfaces vulnerable to prompt injection
- AI governance gaps (absence of public policy documentation)
- Agentic AI capability disclosures in public content

**When to use it:** Whenever the target is known to use AI chat tools, clinical decision support AI, or LLM-powered applications.

**API keys required:** None for local baseline findings. Google CSE or another search API improves documentation searches. Optional HTTP endpoint checks require authorization, not an API key.

**Example:**
```bash
python healthguard.py -t "Health System" -d hs.org -m llm-recon

# Authorized HTTP endpoint checks only
python healthguard.py -t "Health System" -d hs.org -m llm-recon --enable-http-probes
```

> **Note:** Optional HTTP endpoint checks only inspect response codes and headers. They do not send prompts, payloads, exploit strings, credential guesses, or authentication attempts. Use only when authorized.

---

### `github-intel` — GitHub Intelligence

**What it does:** Searches GitHub's public code search index for repositories, files, and code associated with the target organization that contain AI credentials, configuration details, or healthcare architecture information.

**What it finds:**
- OpenAI, Anthropic, Azure OpenAI, Google AI, and HuggingFace API keys
- `.env` files with AI service credentials committed to public repos
- Docker Compose files revealing AI service configurations
- System prompt content committed in source code
- Repositories containing healthcare AI integration code
- Private key files accidentally committed with AI/healthcare context
- Patient data references in public repository code

**When to use it:** Always. Credential exposure in GitHub is one of the leading causes of healthcare AI breaches.

**API keys required:** GitHub token (optional but recommended for higher rate limits).

**Example:**
```bash
python healthguard.py -t "Regional Medical" -d regionalmedical.org -m github-intel
```

---

### `shodan-scan` — Shodan IoT & Infrastructure Scanner

**What it does:** Queries Shodan's internet-wide port scan database for the target's IP space, identifying exposed AI serving infrastructure, medical IoT devices, and services with known vulnerabilities.

**What it finds:**
- Ollama LLM servers on port 11434 open publicly
- Gradio AI interfaces on port 7860
- Streamlit AI applications on port 8501
- Jupyter notebook servers on port 8888
- Elasticsearch, Qdrant, MongoDB, Redis (AI data stores)
- DICOM medical imaging protocol ports exposed
- HL7 MLLP clinical data interface ports exposed
- Known CVEs on healthcare AI infrastructure
- RDP exposed on healthcare organization IP ranges

**When to use it:** For any assessment where you have a domain to resolve to IPs, or want to identify internet-facing AI infrastructure.

**API keys required:** Shodan API key.

**Example:**
```bash
python healthguard.py -t "City Hospital" -d cityhospital.org -m shodan-scan
```

---

### `censys-scan` — Censys Infrastructure Scanner

**What it does:** Queries Censys's internet scan data with a focus on TLS certificate transparency — finding subdomains and services that may not appear in standard DNS lookups.

**What it finds:**
- AI-related subdomains via certificate transparency (llm., api., inference., ai.)
- Expired or self-signed TLS certificates on healthcare AI services
- Open Elasticsearch, Redis, MongoDB via Censys host data
- Grafana monitoring dashboards exposed publicly
- MLflow model registries accessible without authentication
- MinIO object storage with healthcare AI content

**When to use it:** Particularly valuable for discovering hidden subdomains that host AI services not visible through standard reconnaissance.

**API keys required:** Censys API ID and Secret.

**Example:**
```bash
python healthguard.py -t "Health Network" -d healthnetwork.org -m censys-scan
```

---

### `ivre-recon` — IVRE Open-Source Network Recon

**What it does:** Integrates with IVRE, a fully open-source (GPL v3) network reconnaissance framework. IVRE is the DPG-aligned alternative to proprietary services — self-hostable with no vendor dependency or API rate limits.

**What it finds (via IVRE web API or local CLI):**
- AI serving ports open on target IP ranges
- Healthcare protocol ports (DICOM, HL7) visible externally
- Database and vector store ports accessible from internet
- Network infrastructure topology for AI environments

**Two operating modes:**
1. **Web API mode (default):** Queries the public IVRE web API at ivre.rocks — no installation needed
2. **Local CLI mode:** Uses a self-hosted IVRE installation for unlimited queries with full data control

**When to use it:** Always include for the DPG narrative. Consider self-hosted IVRE for organizations seeking zero proprietary dependencies.

**API keys required:** None. IVRE is fully open source.

**Example:**
```bash
python healthguard.py -t "Public Health Agency" -d pha.gov -m ivre-recon
```

**Self-hosted IVRE setup:**
```bash
pip install ivre
ivre ipinfo --init
# Set ivre.use_local_cli: true in config.yaml
```

---

### `leakix-scan` — LeakIX Data Leak Scanner

**What it does:** Queries LeakIX's database of confirmed data exposures. Unlike Shodan or Censys which report open ports, LeakIX verifies actual data accessibility — meaning findings from LeakIX represent confirmed exposures, not theoretical risks.

**What it finds:**
- Confirmed open Elasticsearch clusters with accessible data
- Verified open MongoDB databases
- Exposed `.env` files with credentials confirmed accessible
- Git repository configuration files exposed
- Open Jupyter notebook servers confirmed accessible
- Public S3 buckets with accessible content
- Open Redis caches

**When to use it:** Always. LeakIX confirmed findings are the highest-confidence results in any assessment — they have been verified, not just inferred from open ports.

**API keys required:** LeakIX API key (free tier available).

**Example:**
```bash
python healthguard.py -t "Medical Center" -d medcenter.org -m leakix-scan
```

---

### `vendor-intel` — Vendor Supply Chain Intelligence

**What it does:** Maps publicly visible AI vendor relationships for the target organization and assesses supply chain risk. Searches public sources for evidence of relationships with 19 major healthcare AI vendors.

**What it finds:**
- Evidence of specific AI vendor relationships (Epic AI, Nuance/DAX, Azure OpenAI, etc.)
- Procurement records revealing vendor contracts
- Press releases disclosing AI tool deployments
- Supply chain risk indicators for third-party model dependencies
- Missing HIPAA Business Associate Agreement signals
- Open-source AI model provenance risks

**When to use it:** For any comprehensive assessment and any organization concerned about vendor risk management or HIPAA BAA compliance.

**API keys required:** Google CSE for automated search; runs in documented-query mode without it.

**Example:**
```bash
python healthguard.py -t "Regional Health" -d regionalhealth.org -m vendor-intel
```

---

### `social-recon` — Social Engineering Surface Analyzer

**What it does:** Identifies personnel-level disclosures of AI tools and technical details on public platforms, mapping the social engineering attack surface for the target organization.

**What it finds:**
- Clinical staff disclosing AI tool usage on LinkedIn
- Job postings revealing AI technology stack (specific platforms, vendors, versions)
- Conference presentations disclosing AI architecture details
- Academic publications revealing clinical AI system design
- Social engineering risk indicators specific to AI-themed phishing

**When to use it:** For any organization conducting security awareness training, red team planning, or social engineering risk assessment of their AI-enabled clinical workforce.

**API keys required:** Google CSE for automated search; runs in documented-query mode without it.

**Example:**
```bash
python healthguard.py -t "Children's Hospital" -d childrenshospital.org -m social-recon
```

---

## 9. Configuration Reference

The configuration file is at `config/config.yaml`. A template is provided at `config/config.example.yaml`.

### Full Configuration Reference

```yaml
api_keys:
  shodan: ""                  # Shodan API key
  google_cse_api_key: ""      # Google Custom Search API key
  google_cse_cx: ""           # Google Custom Search Engine ID
  bing_api_key: ""            # Bing Web Search API key (Azure)
  brave_api_key: ""           # Brave Search API key
  mojeek_api_key: ""          # Mojeek Search API key
  github_token: ""            # GitHub Personal Access Token
  censys_api_id: ""           # Censys API ID
  censys_api_secret: ""       # Censys API Secret
  leakix_api_key: ""          # LeakIX API key

rate_limits:
  google_requests_per_day: 100      # Google CSE daily limit
  shodan_requests_per_second: 1     # Shodan rate limit
  github_requests_per_hour: 30      # GitHub rate limit
  delay_between_requests: 2.0       # Seconds between requests (be respectful)

scope:
  max_results_per_query: 10         # Results per search query
  max_github_repos: 20              # Max GitHub repos to analyze
  passive_only: true                # true = no direct HTTP endpoint checks

output:
  include_raw_urls: true            # Include source URLs in findings
  severity_threshold: "info"        # Minimum severity to report

ivre:
  web_url: "https://ivre.rocks/cgi-bin/view.py"  # IVRE web API URL
  use_local_cli: false              # true if IVRE installed locally
```

### Key Configuration Tips

**Increase delay for large assessments:** If you are running multiple assessments per day or scanning large organizations, increase `delay_between_requests` to 3.0 or 4.0 to stay well within rate limits.

**passive_only mode:** Set `passive_only: true` to disable all HTTP probing. The framework will only execute search engine and API queries, with no direct contact with the target's infrastructure. Recommended for initial scoping assessments.

**severity_threshold:** Set to `"high"` to only report high and critical findings. Useful for executive summary reports where you only want the most important issues.

---

## 10. Understanding Your Report

### Severity Levels

Every finding is assigned a severity level. Here is what each level means and how quickly it should be addressed:

| Severity | What It Means | Response Time |
|----------|---------------|---------------|
| **CRITICAL** | Active, immediate threat. An adversary can exploit this today. Breach notification obligations may already apply. | Within 24 hours |
| **HIGH** | Significant vulnerability. Exploitation is likely if not addressed. Risk escalates over time. | Within 7 days |
| **MEDIUM** | Meaningful security gap. Exploitation is possible. Should be prioritized. | Within 30 days |
| **LOW** | Informational risk indicator. Low direct threat but contributes to attack surface. | Within 90 days |
| **INFO** | No direct risk. Documented for awareness and future assessment baseline. | As resources permit |

---

### TIPPSS Framework

All findings are mapped to the TIPPSS healthcare AI security framework. Each letter represents one dimension of trustworthy AI deployment in health environments:

| Letter | Category | Healthcare AI Question It Answers |
|--------|----------|----------------------------------|
| **T** | Trust | Are ERMC's AI systems governed, transparent, and trustworthy? |
| **I** | Identity | Are AI systems protected by proper authentication and access controls? |
| **P** | Privacy | Is patient data protected from unauthorized AI access? |
| **P** | Protection | Are technical security controls in place to defend AI systems? |
| **S** | Safety | Could a compromised AI system harm patients? |
| **S** | Security | How wide is the overall AI attack surface? |

When a finding is tagged with multiple TIPPSS categories, it means the exposure affects multiple dimensions simultaneously. A finding tagged `[I][P][S]` means it affects authentication, patient privacy, and patient safety at the same time — generally the highest-priority findings.

---

### Report Sections

The plain-text report is organized into sections designed for different audiences:

**Section 1 — Plain Language Executive Summary**
Written for non-technical readers: CISO, CMO, compliance officers, clinical leadership. No jargon. Uses plain-language boxes to describe critical findings and their real-world impact.

**Section 2 — Risk Dashboard**
Severity counts, TIPPSS mapping table, findings by module. Designed for security managers and board-level reporting.

**Section 3 — Critical Findings (Immediate Action)**
Each critical finding presented in full: what was found, technical detail, business impact, regulatory implications, who should act, numbered remediation steps, and response deadline.

**Sections 4–6 — High / Medium / Low Findings**
Table format for efficiency. Each finding has a one-line plain-language description, TIPPSS tags, and an action directive.

**Section 7 — Remediation Timeline Checklist**
A complete checkbox list organized by deadline: Immediate, This Week, This Month, Within 90 Days. Designed to be handed directly to a project manager or CISO as a remediation tracking document.

**Section 8 — Compliance and Regulatory Implications**
HIPAA breach notification analysis, NIST AI RMF gaps, FDA SaMD considerations. Designed for the compliance officer and legal counsel.

**Section 9 — Assessment Methodology Note**
Brief explanation of how the assessment was conducted, for transparency with all stakeholders.

---

### JSON Output for SIEM Integration

The JSON report (`*_report.json`) is structured for direct ingestion into SIEM platforms (Splunk, Microsoft Sentinel, IBM QRadar, etc.) and downstream security tooling.

Key fields for SIEM integration:

```json
{
  "siem_fields": {
    "alert_title": "...",
    "alert_severity": "critical",
    "alert_count": 24,
    "critical_count": 4,
    "hipaa_review_required": true,
    "tags": ["healthcare-ai", "osint", "phi-exposure", ...],
    "mitre_atlas": ["AML.T0000", "AML.T0007", ...]
  }
}
```

Each finding includes:
- `plain_language_summary` — non-technical one-sentence description
- `business_impact` — array of business consequences
- `regulatory_implications` — array of applicable regulations
- `remediation_steps` — ordered array of specific actions
- `response_deadline` — machine-readable deadline category
- `hipaa_review_required` — boolean for compliance workflow routing

---

## 11. The Query Library

The `queries/` directory contains community-maintained YAML files that define every search query the framework executes. These are plain text files you can read, edit, and extend without touching any Python code.

```
queries/
├── dorks/
│   ├── healthcare_ai.yaml      # 15+ healthcare AI Google/Bing/Brave/Mojeek dorks
│   ├── llm_endpoints.yaml      # 10 LLM endpoint and vulnerability dorks
│   └── phi_exposure.yaml       # 8 PHI exposure discovery dorks
├── shodan/
│   ├── medical_iot.yaml        # 12 medical IoT and AI infrastructure queries
│   └── ai_infrastructure.yaml  # 10 AI serving infrastructure queries
├── censys/
│   └── health_networks.yaml    # 8 Censys healthcare network queries
├── ivre/
│   └── healthcare_scans.yaml   # 6 IVRE network scan queries
├── leakix/
│   └── healthcare_leaks.yaml   # 8 LeakIX plugin-based leak queries
├── github/
│   ├── ai_configs.yaml         # AI configuration file searches
│   └── credentials.yaml        # Credential exposure searches
└── social/
    └── personnel.yaml          # Personnel disclosure queries
```

### Adding Your Own Queries

Every YAML file follows the same structure:

```yaml
dorks:
  - title: "Your Finding Title"
    query: 'your search query with {domain} and {target} placeholders'
    description: >
      What this query finds and why it matters for healthcare AI security.
    severity: high          # critical | high | medium | low | info
    tippss: [Identity, Security]
    remediation: >
      Specific steps to remediate this finding if confirmed.
```

After adding queries, they are automatically picked up the next time the module runs — no code changes needed.

To contribute queries back to the community, see [CONTRIBUTING.md](CONTRIBUTING.md).

---

## 12. Common Workflows

### Workflow 1: Quick Exposure Check (15 minutes)

For a fast initial assessment with minimal setup:

```bash
# Only dork-scan and github-intel — no Shodan required
python healthguard.py \
  -t "Your Organization" \
  -d yourdomain.org \
  -m dork-scan

python healthguard.py \
  -t "Your Organization" \
  -d yourdomain.org \
  -m github-intel
```

### Workflow 2: Full Comprehensive Assessment (1–2 hours)

The standard complete assessment:

```bash
python healthguard.py \
  --target "Your Organization" \
  --domain yourdomain.org \
  --all-modules \
  --format both \
  --output reports/$(date +%Y%m%d)
```

### Workflow 3: Executive Report Only

If you already have findings from a previous run and want a fresh report:

```bash
python healthguard.py \
  --report \
  --input output/yourorg_20260602_findings.json \
  --format txt
```

### Workflow 4: Compliance-Focused Assessment

Focused on PHI exposure and HIPAA risk:

```bash
# Run only the modules most relevant to HIPAA compliance
python healthguard.py -t "Your Org" -d yourdomain.org -m dork-scan
python healthguard.py -t "Your Org" -d yourdomain.org -m leakix-scan
python healthguard.py -t "Your Org" -d yourdomain.org -m github-intel
python healthguard.py -t "Your Org" -d yourdomain.org -m vendor-intel
```

### Workflow 5: Continuous Monitoring (Scheduled)

Set up a cron job for monthly reassessment:

```bash
# Add to crontab: runs on the 1st of every month at 6am
0 6 1 * * cd /path/to/healthguard && python healthguard.py \
  -t "Your Org" -d yourdomain.org --all-modules --format both \
  --output /path/to/reports/$(date +%Y%m) --quiet
```

---

## 13. Troubleshooting

### Installation Issues

**`pip install` fails with permission error**
```bash
# Try with --user flag
pip install --user -r requirements.txt

# Or use a virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows
pip install -r requirements.txt
```

**`python healthguard.py` gives `ModuleNotFoundError`**
```bash
# Make sure you are in the right directory
ls healthguard.py   # Should show the file

# Make sure dependencies are installed
pip install -r requirements.txt

# If using venv, make sure it is activated
source venv/bin/activate
```

**Python version error**
```bash
# Check your Python version
python --version     # May be Python 2 on older systems
python3 --version    # Use python3 explicitly

python3 healthguard.py --help
```

---

### API Key Issues

**Google CSE returns 0 results**
- Verify your Search Engine ID (cx) is correct — it looks like `abc123:xyz456`
- Check the API key is enabled for Custom Search API in Google Cloud Console
- Free tier limit (100/day) may be exhausted — wait until midnight Pacific time

**Bing returns 403 Forbidden**
- Verify the API key is from the Bing Search v7 resource, not another Azure service
- Check the Azure subscription is active
- Make sure you copied KEY 1 or KEY 2 from Keys and Endpoint, not the endpoint URL

**Shodan returns `Invalid API key`**
- Copy the key again from https://account.shodan.io — make sure there are no trailing spaces
- Free tier keys have some query restrictions — check Shodan documentation

**GitHub rate limit hit**
- Add a GitHub token to increase limit from 10 to 30 requests/minute
- Increase `delay_between_requests` in config.yaml to 3.0 or higher
- GitHub rate limits reset every hour

---

### Assessment Issues

**Assessment runs but finds nothing**
- Verify your target name and domain are correct
- Run with `--verbose` to see exactly what queries are executing
- Try running in DRY-RUN mode (remove API keys) to confirm the query library is loading
- Check output directory for any partial findings files

**Rate limit errors during long assessments**
```yaml
# In config/config.yaml, increase the delay:
rate_limits:
  delay_between_requests: 3.0
```

**Report shows `[DRY-RUN]` in all finding titles**
- This means no API keys are configured for that module
- Check config/config.yaml has your keys filled in (not the placeholder text)
- Verify environment variables are set if using Option C installation

**Docker volume mounting issues on Windows**
```powershell
# Use Windows-style paths
docker run -v C:\path\to\config:/app/config -v C:\path\to\output:/app/output healthguard-osint --help
```

---

### Getting Help

If you encounter an issue not covered here:

1. Run with `--verbose` flag and include the full output when reporting
2. Check the GitHub Issues page for known issues
3. Open a new GitHub Issue with your Python version, OS, and the full error message
4. See [CONTRIBUTING.md](CONTRIBUTING.md) for community support channels

---

## 14. Next Steps

After completing your first assessment:

**Deepen your understanding:**
- [METHODOLOGY.md](METHODOLOGY.md) — Full assessment methodology and reconnaissance phases
- [TIPPSS_MAPPING.md](TIPPSS_MAPPING.md) — Complete TIPPSS framework with finding-to-category tables
- [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md) — Legal considerations and responsible disclosure guidance

**Extend the framework:**
- [CONTRIBUTING.md](CONTRIBUTING.md) — Add queries to the community library, submit bug fixes
- Edit `queries/*.yaml` directly to add organization-specific dorks
- Build a new module by inheriting `BaseModule` in `src/modules/`

**Operationalize your findings:**
- Share the plain-text report with your CISO and compliance team
- Feed the JSON report into your SIEM for tracking
- Use the remediation checklist as input to your vulnerability management program
- Schedule monthly reassessments to track remediation progress

**Community:**
- Star the repository to stay updated on new modules and query library additions
- Share anonymized case studies to help other health systems understand their risk
- Translate the documentation to expand access for international health systems

---

*IEEE CyberSalukis HealthGuard OSINT — Open-Source Digital Public Good*
*IEEE SA Cybersecurity Hackathon 2026*
*https://github.com/CyberSalukis/CyberSalukis-Healthguard-OSINT-*
*License: MIT | DPG Standard Compliant*
