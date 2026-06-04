# TIPPSS Framework Mapping
## IEEE CyberSalukis HealthGuard OSINT

---

## What is TIPPSS?

TIPPSS is a healthcare-specific security framework addressing six dimensions of trustworthy, secure AI deployment in health environments:

| Letter | Category | Definition |
|--------|----------|------------|
| **T** | Trust | AI system trustworthiness, governance, vendor relationships, policy |
| **I** | Identity | Authentication, authorization, credential management, access control |
| **P** | Privacy | PHI protection, data minimization, patient data governance |
| **P** | Protection | Technical security controls, endpoint security, misconfiguration |
| **S** | Safety | Patient safety, clinical AI integrity, IoT device security |
| **S** | Security | Broad cyber threat posture, attack surface, incident response |

---

## TIPPSS → Finding Type Mapping

### [T] TRUST

**What HealthGuard OSINT looks for:**
- Absence of public AI governance policy documentation
- AI vendor relationships visible in public sources
- Conference presentations disclosing AI architecture
- Academic publications revealing system design
- Press releases disclosing specific AI tools in use

**Key remediations:**
- Publish AI acceptable use policy and governance framework
- Align AI governance with NIST AI RMF
- Conduct vendor security assessments and ensure HIPAA BAAs
- Implement AI change management processes
- Review all public communications for AI architecture disclosure

---

### [I] IDENTITY

**What HealthGuard OSINT looks for:**
- LLM API keys (OpenAI, Anthropic, Azure, Google) in GitHub repositories
- Exposed AI API endpoints without authentication
- Configuration files containing credentials in public directories
- Unauthenticated AI demo interfaces (Gradio, Streamlit, OpenWebUI)
- Jupyter notebook servers without authentication

**Key remediations:**
- Rotate all exposed API keys immediately
- Implement API key management (rotation, scope limitation, monitoring)
- Deploy secrets management (HashiCorp Vault, AWS Secrets Manager)
- Enable GitHub secret scanning and push protection
- Require authentication on all AI-facing interfaces

---

### [P] PRIVACY

**What HealthGuard OSINT looks for:**
- PHI in public-facing documents (PDF, CSV, XLSX)
- Exposed healthcare AI training datasets
- AI output logs containing patient query data
- Exposed FHIR API endpoints
- Vector databases with clinical document embeddings

**Key remediations:**
- Remove PHI from all public-facing systems immediately
- Implement DLP controls on AI interfaces handling PHI
- Conduct HIPAA risk assessment for all AI data flows
- Ensure data minimization in AI prompts and queries
- Assess HIPAA BAA coverage for all AI vendor relationships

---

### [P] PROTECTION

**What HealthGuard OSINT looks for:**
- LLM serving endpoints exposed without authentication
- Medical IoT management interfaces accessible from internet
- Misconfigured cloud storage (S3, Azure Blob) with healthcare content
- Known CVEs on healthcare AI infrastructure (via Shodan)
- Vector databases and AI data stores without access controls

**Key remediations:**
- Restrict all AI infrastructure to internal networks or authenticated access
- Implement WAF rules for AI interface protection
- Apply network segmentation for medical devices and AI systems
- Conduct regular vulnerability assessment of AI infrastructure
- Implement cloud security posture management (CSPM)

---

### [S] SAFETY

**What HealthGuard OSINT looks for:**
- Clinical AI chatbot interfaces with direct patient data access
- Prompt injection surface in clinical decision support tools
- Exposed system prompts for clinical AI assistants
- AI-connected medical IoT devices accessible from internet
- Agentic AI with clinical workflow access disclosed publicly

**Key remediations:**
- Implement prompt injection defenses on all clinical AI interfaces
- Deploy human-in-the-loop validation for high-risk clinical AI outputs
- Restrict medical IoT device interfaces to internal clinical networks
- Conduct adversarial testing of clinical AI systems
- Implement AI output monitoring and anomaly detection

---

### [S] SECURITY

**What HealthGuard OSINT looks for:**
- Overall AI attack surface breadth (module aggregate)
- Supply chain vulnerability exposure
- Social engineering surface (personnel AI tool disclosures)
- Job postings revealing technology stack
- Dark pattern indicators of adversarial interest

**Key remediations:**
- Conduct regular OSINT-based attack surface assessments (use this tool)
- Implement vendor security monitoring program
- Deploy AI-focused security awareness training
- Establish AI incident response playbooks
- Monitor threat intelligence feeds for healthcare AI targeting

---

## Finding → TIPPSS Quick Reference

| Finding Type | T | I | P | P | S | S |
|-------------|---|---|---|---|---|---|
| LLM API key exposed | | ✓ | | | | ✓ |
| PHI in public document | | | ✓ | ✓ | | ✓ |
| Exposed AI endpoint | | ✓ | | ✓ | | ✓ |
| Medical IoT exposed | | | | ✓ | ✓ | ✓ |
| Vendor relationship visible | ✓ | | | | | ✓ |
| System prompt disclosed | ✓ | ✓ | | | ✓ | ✓ |
| Clinical AI chatbot | ✓ | ✓ | | | ✓ | ✓ |
| Personnel disclosure | ✓ | ✓ | | | | ✓ |
| Training data exposed | | | ✓ | ✓ | | ✓ |
| Vector DB exposed | | | ✓ | ✓ | | ✓ |
| No governance policy | ✓ | | | | | ✓ |
| CVE on AI infrastructure | | | | ✓ | ✓ | ✓ |
