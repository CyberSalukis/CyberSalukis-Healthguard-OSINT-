"""
IEEE CyberSalukis HealthGuard OSINT
Utility: tippss_mapper.py — TIPPSS Framework Category Mapping

Maps OSINT findings to the TIPPSS framework:
Trust, Identity, Privacy, Protection, Safety, Security
"""

TIPPSS_DEFINITIONS = {
    "Trust": (
        "Signals related to AI system trustworthiness, governance, vendor relationships, "
        "policy documentation, and organizational AI risk posture."
    ),
    "Identity": (
        "Authentication surface, API key exposure, credential leakage, "
        "access control weaknesses, and identity verification gaps in AI systems."
    ),
    "Privacy": (
        "Protected health information (PHI) exposure, data leakage, PII in public "
        "repositories, training data disclosure, and patient data governance gaps."
    ),
    "Protection": (
        "Misconfigured AI endpoints, unpatched infrastructure, exposed administrative "
        "interfaces, missing encryption, and security control deficiencies."
    ),
    "Safety": (
        "Clinical AI integrity signals, AI hallucination risk indicators, IoT medical "
        "device exposure, and threats to patient safety through AI compromise."
    ),
    "Security": (
        "Attack surface breadth, supply chain vulnerabilities, social engineering vectors, "
        "adversarial AI exposure, and cyber threat indicators across the AI ecosystem."
    ),
}

TIPPSS_REMEDIATIONS = {
    "Trust": [
        "Develop and publish AI governance policy and acceptable use framework.",
        "Conduct AI vendor security assessments and ensure HIPAA BAAs.",
        "Implement AI risk management aligned with NIST AI RMF.",
        "Establish AI change management and deployment review processes.",
    ],
    "Identity": [
        "Rotate all exposed API keys immediately.",
        "Implement MFA for all AI system administrative access.",
        "Deploy secrets management (HashiCorp Vault, AWS Secrets Manager).",
        "Enable GitHub secret scanning and pre-commit hooks.",
        "Conduct API key audit and inventory.",
    ],
    "Privacy": [
        "Remove PHI from all public-facing systems and repositories.",
        "Implement data minimization in AI prompts and queries.",
        "Conduct HIPAA risk assessment for AI data flows.",
        "Deploy DLP controls on AI interfaces handling PHI.",
        "Audit AI training data for de-identification compliance.",
    ],
    "Protection": [
        "Restrict AI API endpoints to internal networks or authenticated access.",
        "Implement WAF rules for AI interface protection.",
        "Conduct vulnerability assessment on AI infrastructure.",
        "Apply network segmentation for AI systems.",
        "Implement prompt injection and input validation defenses.",
    ],
    "Safety": [
        "Implement AI output validation before clinical use.",
        "Establish human-in-the-loop requirements for clinical AI decisions.",
        "Deploy AI monitoring for hallucination and anomalous output detection.",
        "Conduct adversarial testing of clinical AI systems.",
        "Restrict medical IoT device interfaces to internal networks.",
    ],
    "Security": [
        "Conduct regular OSINT-based attack surface assessments.",
        "Implement vendor security monitoring program.",
        "Deploy security awareness training focused on AI social engineering.",
        "Establish AI incident response procedures.",
        "Monitor dark web and breach disclosure feeds for AI-related exposures.",
    ],
}


def get_tippss_summary(findings: list) -> dict:
    """Generate TIPPSS category summary from findings."""
    summary = {}
    for cat, definition in TIPPSS_DEFINITIONS.items():
        cat_findings = [f for f in findings if cat in f.get("tippss", [])]
        summary[cat] = {
            "definition": definition,
            "finding_count": len(cat_findings),
            "findings": cat_findings,
            "remediations": TIPPSS_REMEDIATIONS.get(cat, []),
        }
    return summary
