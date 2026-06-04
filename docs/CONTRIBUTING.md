# Contributing to IEEE CyberSalukis HealthGuard OSINT

Thank you for helping maintain and expand this Digital Public Good.

---

## How to Contribute

### Adding New Dorks or Queries

The easiest contribution — no Python required:

1. Navigate to the relevant YAML file in `queries/`
2. Add a new entry following the existing schema:

```yaml
- title: "Descriptive Finding Title"
  query: 'your search query with {domain} and {target} placeholders'
  description: >
    What this query finds and why it matters in healthcare AI context.
  severity: critical  # critical | high | medium | low | info
  tippss: [Trust, Identity, Privacy, Protection, Safety, Security]
  remediation: >
    Concrete remediation steps for the security team.
```

3. Test your query manually in Google, Shodan, or GitHub
4. Submit a pull request with evidence it returns relevant results

### Adding a New Module

1. Create `src/modules/your_module.py`
2. Inherit from `BaseModule`
3. Implement `run()` returning a list of standardized findings
4. Register in `healthguard.py` MODULE_MAP
5. Add documentation to `docs/`
6. Submit pull request

### Improving Documentation

- Translations of `docs/` for international health systems are especially welcomed
- Case studies demonstrating real-world use (anonymized) are valuable additions

---

## Query Library YAML Schema

```yaml
# File header (required)
# IEEE CyberSalukis HealthGuard OSINT
# [Library Name]
# Tested: [Month Year]
# AUTHORIZED USE ONLY

dorks:  # or 'queries:' for non-Google sources

  - title: string              # Short descriptive title (required)
    query: string              # The search query (required)
                               # Use {domain} for target domain placeholder
                               # Use {target} for target org name placeholder
    description: string        # What it finds and why it matters (required)
    severity: string           # critical|high|medium|low|info (required)
    tippss: list               # One or more TIPPSS categories (required)
    remediation: string        # Concrete remediation steps (required)
```

---

## Code Standards

- Python 3.10+ compatible
- Follow existing module structure (inherit BaseModule)
- All findings must use `_make_finding()` for schema compliance
- Passive OSINT by default; no exploitation code, payload delivery, credential guessing, or unauthorized access accepted
- Include docstring on all classes and public methods

---

## Reporting Issues

Open a GitHub issue for:
- Broken queries (search engine algorithm changes)
- False positive patterns
- New healthcare AI attack surface categories
- Module bugs or errors

---

## Digital Public Good Commitment

All contributions must:
- Be compatible with the MIT License
- Advance healthcare security without enabling harm
- Be usable without proprietary dependencies
- Include documentation in English
