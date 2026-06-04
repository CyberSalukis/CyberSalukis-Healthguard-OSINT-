# Assessment Methodology
## IEEE CyberSalukis HealthGuard OSINT

---

## Overview

IEEE CyberSalukis HealthGuard OSINT applies a structured, repeatable OSINT-based methodology to identify the externally visible AI attack surface of healthcare organizations. The methodology replicates adversarial reconnaissance techniques — the same process a threat actor uses before launching an attack — enabling defenders to find and remediate exposure proactively.

---

## Reconnaissance Phases

### Phase 1 — Target Scoping

Define the assessment target:
- Organization name (for search-based queries)
- Primary domain (for site-specific queries and optional authorized HTTP endpoint checks)
- Subsidiary domains (optional)
- Assessment scope (which modules to run)

### Phase 2 — Passive OSINT Collection

Execute reconnaissance modules against the target:

| Module | Data Sources | Primary Targets |
|--------|-------------|-----------------|
| `dork-scan` | Google CSE, Bing, Brave, Mojeek | Exposed endpoints, PHI, configs, cloud storage |
| `llm-recon` | Search/API OSINT; optional authorized HTTP endpoint checks | LLM APIs, prompt injection surface, governance gaps |
| `github-intel` | GitHub Search API | API keys, config files, architecture repos |
| `shodan-scan` | Shodan API | Medical IoT, AI serving ports, vulnerable services |
| `censys-scan` | Censys certificates and hosts | Healthcare AI infrastructure, exposed services |
| `ivre-recon` | IVRE web/API or local CLI | Open-source network intelligence and service exposure |
| `leakix-scan` | LeakIX API | Confirmed leaks and exposed services |
| `vendor-intel` | Search APIs, public records | AI vendor relationships, supply chain |
| `social-recon` | Public professional profiles, search APIs, job boards | Personnel disclosure, social engineering surface |

### Phase 3 — Normalization & Deduplication

All findings are:
1. Normalized to a standard schema
2. Deduplicated by module + title + URL hash
3. Severity-ranked (Critical → Info)
4. TIPPSS-categorized

### Phase 4 — Report Generation

Findings are assembled into:
- An executive summary with overall risk rating
- TIPPSS-mapped category breakdown
- Prioritized remediation recommendations
- Full detailed findings with source, query, and remediation for each

### Phase 5 — Remediation Validation (Manual)

After organizational remediation:
- Re-run relevant modules to verify findings are resolved
- Update risk register with remediation status
- Document residual risk for accepted findings

---

## OSINT Intelligence Sources

### Tier 1 — Search Engine Intelligence
- Google Custom Search API with healthcare AI-specific dork syntax
- Bing (manual), DuckDuckGo (manual) for cross-validation
- Wayback Machine for historical exposure

### Tier 2 — Code Repository Intelligence
- GitHub Search API for code, repositories, and file patterns
- GitLab public repositories (manual)
- npm/PyPI package metadata (manual)

### Tier 3 — Infrastructure Intelligence
- Shodan for internet-wide port/service scanning data
- Censys for certificate and network intelligence
- FOFA (manual) for regional infrastructure discovery

### Tier 4 — Professional Network Intelligence
- LinkedIn public profiles via Google dorks
- Conference presentation archives (HIMSS, RSNA, AHA)
- Academic publication databases (PubMed, arXiv)

### Tier 5 — Procurement & Regulatory Intelligence
- Public procurement databases
- FDA 510(k) and De Novo AI device clearances
- CMS innovation model documentation
- Press releases and news archives

---

## Healthcare AI Attack Surface Categories

### 1. LLM API Exposure
Externally accessible LLM API endpoints without authentication allow:
- Unauthorized model access and inference
- Prompt injection and jailbreaking
- Data extraction through context window manipulation
- Billing abuse and quota exhaustion

### 2. Configuration and Credential Exposure
API keys, connection strings, and AI system configurations in public repositories or accessible directories enable:
- Unauthorized model access
- Cloud infrastructure pivot
- Fine-tuned model access including clinically-trained models

### 3. Protected Health Information (PHI) Exposure
Patient data, clinical records, or AI training datasets in public-facing systems create:
- Direct HIPAA breach exposure
- Breach notification obligations
- Regulatory penalty risk
- Patient harm through re-identification

### 4. Medical IoT Attack Surface
AI-connected medical devices with internet-accessible interfaces enable:
- Manipulation of clinical monitoring data
- False sensor readings causing inappropriate interventions
- Ransomware delivery via device management interfaces
- Patient safety incidents

### 5. Supply Chain Attack Vectors
Publicly visible vendor relationships enable:
- Targeted vendor impersonation attacks
- Exploitation of known vendor-specific vulnerabilities
- Monitoring for vendor breach disclosures
- Third-party AI model supply chain compromise

### 6. Social Engineering Surface
Personnel disclosures of AI tools and technical details on public platforms create:
- Targeted phishing using known AI tool context
- Pretexting via vendor impersonation
- Technical intelligence for AI-specific attacks

---

## TIPPSS Threat Mapping

Each finding is mapped to one or more TIPPSS categories, enabling healthcare security teams to prioritize remediation by framework objective rather than only by technical severity.

See [TIPPSS_MAPPING.md](TIPPSS_MAPPING.md) for full mapping tables and control recommendations.

---

## Limitations

This methodology has known limitations:

1. **Coverage is passive by default** — Active vulnerability scanning and exploitation are out of scope. Optional authorized HTTP endpoint checks are limited to response codes and headers. Findings represent externally visible exposure, not confirmed exploitability.
2. **API rate limits** — Free-tier APIs constrain query volume. High-rate assessments require paid API tiers.
3. **Dynamic content** — Cloud-hosted AI services change rapidly. Findings represent a point-in-time snapshot.
4. **False positives** — Dork results require human review to confirm relevance. Not all results represent confirmed exposure.
5. **Dark web and closed communities** — This framework does not assess adversarial interest in dark web forums, closed Telegram channels, or private threat intelligence sources.

---

## References

- NIST AI Risk Management Framework (AI RMF 1.0)
- OWASP Top 10 for Large Language Model Applications
- HIPAA Security Rule (45 CFR Part 164)
- HHS Office for Civil Rights — AI and Healthcare Guidance
- MITRE ATLAS — Adversarial Threat Landscape for AI Systems
- Digital Public Goods Standard v1.1.3
