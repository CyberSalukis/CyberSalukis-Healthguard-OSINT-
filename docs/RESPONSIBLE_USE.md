# Responsible Use Policy
## IEEE CyberSalukis HealthGuard OSINT

---

## Purpose

IEEE CyberSalukis HealthGuard OSINT is designed exclusively for **authorized defensive security assessments** by healthcare organizations seeking to identify and reduce their AI attack surface.

This framework is a **Digital Public Good (DPG)** — it is freely available to support global healthcare security. With that openness comes responsibility.

---

## Authorized Use

You are authorized to use this framework when:

1. **You own the target infrastructure** — You are assessing your own organization's AI attack surface.
2. **You have explicit written authorization** — You are a security professional with a signed scope of work, penetration testing agreement, or equivalent written authorization from the infrastructure owner.
3. **You are conducting academic research** — You are researching healthcare AI security with appropriate IRB/ethics approval and no unauthorized system access.

---

## Prohibited Use

The following uses are **strictly prohibited**:

- Executing queries against healthcare organizations you do not own or have written authorization to assess
- Using OSINT findings to facilitate unauthorized access, data theft, or harm to any healthcare system
- Conducting active exploitation using findings from this framework
- Targeting patient data or PHI for any unauthorized purpose
- Any use that violates applicable computer access laws (CFAA, Computer Misuse Act, GDPR, HIPAA, etc.)

---

## Legal Considerations

OSINT is generally passive and legal when accessing publicly available information. However:

- **Automated querying** of search engines may violate terms of service
- **Accessing exposed systems** even without credentials may constitute unauthorized access under CFAA and equivalent laws
- **PHI discovered incidentally** must be handled in compliance with HIPAA
- Laws vary by jurisdiction — consult legal counsel before conducting assessments in unfamiliar legal environments

---

## Passive-First OSINT Principles

This framework is designed to run in **passive OSINT mode by default**:

- We query public search engines and APIs for openly available information
- Direct HTTP endpoint checks are disabled by default and require explicit authorization plus `--enable-http-probes`
- Optional HTTP endpoint checks inspect response codes and public headers only — never prompts, payloads, exploit strings, credential guesses, or authentication attempts
- We do not send malicious payloads, inject code, or attempt authentication bypass
- We do not access data that requires credentials we do not possess

---

## Responsible Disclosure

If you discover a security vulnerability in a healthcare organization through use of this framework:

1. **Do not access** the exposed data or system beyond what is needed to confirm the finding
2. **Document** the finding and evidence of exposure
3. **Contact** the organization's security team through their responsible disclosure or bug bounty program
4. **Allow reasonable time** (typically 90 days) for remediation before any public disclosure
5. **Follow** the CERT/CC Coordinated Vulnerability Disclosure guidelines

---

## Healthcare-Specific Considerations

Healthcare security assessment carries unique obligations:

- PHI discovered must be handled in compliance with HIPAA minimum necessary standards
- Patient safety concerns (exposed medical devices, clinical AI systems) may warrant expedited disclosure
- Consider coordination with HHS/OCR for significant findings affecting patient safety
- Respect the operational continuity needs of clinical environments during assessment

---

## Contact

To report misuse of this framework or for questions about responsible use:

**IEEE CyberSalukis Team**
IEEE SA Cybersecurity Hackathon 2026

---

*This framework is released under the MIT License as a Digital Public Good. The IEEE CyberSalukis team and contributors bear no responsibility for unauthorized or harmful use of this software.*
