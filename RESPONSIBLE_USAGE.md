# Responsible Usage Guidelines

> **MCP Verify is a defensive security tool designed for auditing and validating MCP servers.**
> This document outlines ethical usage and our commitment to responsible security practices.

---

## Our Mission

MCP Verify exists to **improve the security of the MCP ecosystem** by enabling developers and security teams to:

- Validate their own MCP servers before deployment
- Identify vulnerabilities in development/staging environments
- Ensure compliance with security best practices
- Build more secure AI infrastructure

**We do not condone or support offensive security operations against systems without authorization.**

---

## Authorized Use Cases ✅

MCP Verify is designed for:

### 1. Self-Auditing
- Scanning **your own** MCP servers
- Pre-deployment security validation
- Continuous integration security checks
- Internal security assessments

### 2. Authorized Security Testing
- Penetration testing **with written authorization**
- Bug bounty programs (where permitted)
- Security research **with explicit consent**
- Red team exercises on owned infrastructure

### 3. Development & Learning
- Learning MCP protocol security
- Testing in local/development environments
- Security training and education
- Capture The Flag (CTF) competitions

### 4. Compliance & Governance
- Meeting security compliance requirements (SOC 2, ISO 27001)
- Pre-certification audits
- Third-party security assessments (with authorization)
- Supply chain security validation

---

## Prohibited Use Cases ❌

**DO NOT use MCP Verify for:**

### 1. Unauthorized Scanning
- Scanning systems **you do not own or control**
- Scanning without **explicit written permission**
- "Testing" production systems of other organizations
- Curiosity-driven scanning of random targets

### 2. Malicious Activities
- Exploiting discovered vulnerabilities
- Disrupting services (DoS/DDoS)
- Data exfiltration or theft
- Any illegal activity under applicable law

### 3. Mass Scanning
- Indiscriminate scanning of IP ranges
- Automated discovery and scanning of public servers
- Building vulnerability databases without consent
- Weaponizing findings for extortion or blackmail

---

## Legal & Ethical Framework

### You Are Responsible

Using MCP Verify **does not grant permission** to scan any system. Authorization must be:

1. **Explicit** - Clear written consent from the system owner
2. **Documented** - Scope, duration, and methods agreed upon
3. **Limited** - Only scan what is authorized
4. **Reversible** - Ability to stop if requested

### Know Your Jurisdiction

Different countries have different laws regarding security testing:

- **United States**: Computer Fraud and Abuse Act (CFAA)
- **European Union**: Network and Information Security Directive
- **United Kingdom**: Computer Misuse Act 1990
- **Others**: Consult local laws before testing

**Ignorance is not a defense.**

### Responsible Disclosure

If you discover vulnerabilities:

1. **Do not exploit** - Stop testing immediately
2. **Do not publish** - Avoid public disclosure before patching
3. **Notify privately** - Contact the vendor/owner directly
4. **Give time** - Allow reasonable time for remediation (typically 90 days)
5. **Coordinate** - Work with the vendor on disclosure timeline

Resources:
- [CERT Coordination Center](https://www.kb.cert.org/vuls/)
- [HackerOne Disclosure Guidelines](https://www.hackerone.com/disclosure-guidelines)
- [ISO/IEC 29147](https://www.iso.org/standard/72311.html) (Vulnerability Disclosure)

---

## AGPL-3.0 License ≠ Permission to Scan

**Important:** The AGPL-3.0 license grants permission to **use, modify, and distribute the software**.

It does **NOT** grant permission to:
- Scan systems you don't own
- Bypass security controls
- Ignore applicable laws

**Using MCP Verify against unauthorized targets is YOUR responsibility and YOUR legal liability.**

---

## Red Flags 🚩

If you find yourself asking any of these questions, **STOP**:

- "Can I scan this to see what happens?"
- "Is it illegal if I don't exploit the vulnerabilities?"
- "What if I just do a quick scan?"
- "Will anyone know if I scan them?"

**If you need permission, you don't have it.**

---

## Our Commitment

As the maintainers of MCP Verify, we commit to:

### 1. Defensive Design
- Focus on **validation** and **compliance**, not exploitation
- Avoid features that automate exploitation
- Provide clear documentation on ethical usage
- Position the tool as a **defender's tool**

### 2. Transparency
- Open-source codebase (100% auditable)
- Clear documentation of all functionality
- No hidden features or telemetry
- Community-driven development

### 3. Education
- Provide responsible security guidance
- Share best practices for MCP security
- Educate on legal and ethical frameworks
- Support security research done responsibly

### 4. Accountability
- Respond to legitimate abuse reports
- Coordinate with security community
- Update documentation based on feedback
- Maintain ethical standards in all communications

---

## Case Studies: What NOT to Do

### ❌ Bad Example 1: Curiosity Scanning
**Scenario:** Developer finds a public MCP server URL and "just wants to see if it's secure."

**Why This is Wrong:**
- No authorization
- Not your system
- Potential CFAA violation

**Correct Approach:**
- Contact the owner
- Request permission in writing
- Define scope and methods
- Document authorization

---

### ❌ Bad Example 2: Bug Bounty Overreach
**Scenario:** Company has bug bounty program. Researcher scans production API without reading scope.

**Why This is Wrong:**
- Bug bounty programs have **explicit scope**
- Scanning out-of-scope systems = unauthorized access
- Can result in legal action, not reward

**Correct Approach:**
- Read bug bounty scope carefully
- Only test **in-scope** systems
- Follow **all** program rules
- Report findings through official channels

---

### ❌ Bad Example 3: "Public Research"
**Scenario:** Security researcher scans 10,000 random MCP servers to "measure ecosystem security."

**Why This is Wrong:**
- Mass scanning without consent
- Potentially illegal in many jurisdictions
- Ethical violation (no opt-in)
- Could cause service disruption

**Correct Approach:**
- Survey methodology with opt-in
- Contact targets for permission
- Use test/honeypot infrastructure
- Publish aggregated data only (no identifiable info)

---

## ✅ Good Example: Responsible Researcher

**Scenario:** Security researcher discovers critical vulnerability in popular MCP server software.

**What They Did Right:**
1. Tested on **own infrastructure** first
2. Verified finding was real and exploitable
3. Contacted vendor **privately** via security@vendor.com
4. Provided detailed write-up and PoC
5. Gave vendor **90 days** to patch
6. Coordinated disclosure timeline
7. Published responsibly after patch release

**Result:**
- Vendor fixed vulnerability
- Users protected
- Researcher credited
- Ecosystem improved

**This is what we want to enable.**

---

## Developer Responsibilities

If you are **building on top of MCP Verify** (e.g., integrating into CI/CD, commercial products):

### You Must:
- Ensure users cannot scan unauthorized targets
- Provide your own authorization mechanisms
- Clearly document acceptable use
- Handle findings responsibly
- Comply with all applicable laws

### You Must Not:
- Remove or obscure responsible usage documentation
- Promote offensive security use cases
- Enable anonymous or unauthorized scanning
- Sell findings without authorization

---

## Responsible Use of Security Proxy (Runtime Protection)

The **Security Gateway v1.0** proxy provides powerful real-time threat detection capabilities. With this power comes additional responsibility.

### Understanding the Proxy's Capabilities

The Security Gateway operates in 3 layers:

1. **Layer 1 (Fast Rules)**: Pattern-based detection (<10ms) - Extremely accurate, minimal false positives
2. **Layer 2 (Suspicious Rules)**: Heuristic analysis (<50ms) - May generate false positives requiring review
3. **Layer 3 (LLM Rules)**: AI-powered semantic analysis (500-2000ms) - Experimental, requires careful interpretation

### Ethical Considerations

#### 1. Production Deployment Requires Authorization

**DO NOT** deploy the Security Proxy in front of someone else's MCP server without their knowledge:

```bash
# ❌ WRONG: Intercepting traffic to unauthorized server
node dist/mcp-verify.js proxy \
  --target "https://someone-elses-mcp-server.com" \
  --port 3000
```

**Why This is Wrong:**
- Constitutes unauthorized interception of communications
- May violate wiretapping laws (e.g., ECPA in the US)
- Violates privacy expectations
- Could expose sensitive data to your audit logs

**✅ Correct Approach:**
- Only proxy **your own** MCP servers
- Get **written authorization** before proxying third-party servers
- Disclose proxy usage to all connected clients
- Document authorization in audit trail

#### 2. Audit Logs Contain Sensitive Data

Audit logs (`--audit-log`) record **all blocked requests**, including:
- Tool names and parameters
- Potentially sensitive data that triggered detection
- Client IP addresses and identifiers
- Attack patterns and payloads

**You Must:**
- Treat audit logs as **confidential security data**
- Store logs with appropriate access controls (chmod 600 recommended)
- Implement log retention policies (delete after 90 days unless required)
- Comply with data protection laws (GDPR, CCPA)
- **Never** share raw audit logs publicly (even for bug reports)

**Example: Secure Audit Log Configuration**
```bash
# Create secure logs directory
mkdir -p ./logs
chmod 700 ./logs

# Start proxy with audit logging
node dist/mcp-verify.js proxy \
  --target "node my-server.js" \
  --audit-log ./logs/security-audit.jsonl

# Verify permissions
ls -la ./logs/security-audit.jsonl
# Expected: -rw------- (owner read/write only)
```

#### 3. LLM Layer Privacy Implications

When you enable Layer 3 (`--enable-llm-layer`), request data is sent to external LLM APIs:

**Privacy Risks:**
- Request parameters are sent to third-party LLM providers (Anthropic, OpenAI, Gemini)
- LLM providers may log requests for quality/safety (check their privacy policies)
- Sensitive data in tool calls could be exposed to external services

**Mitigation:**
- **Default: Layer 3 is DISABLED** (opt-in only)
- Use Layer 3 only in **development/testing** environments
- For production: Use Layers 1+2 only (zero external data sharing)
- If Layer 3 is required: Use self-hosted Ollama provider
- Redact sensitive data before analysis

**Example: Privacy-Safe Configuration**
```bash
# Production (no external LLM calls)
node dist/mcp-verify.js proxy \
  --target "node production-server.js" \
  --no-llm-layer

# Development with self-hosted LLM
export OLLAMA_API_URL=http://localhost:11434
node dist/mcp-verify.js proxy \
  --target "node dev-server.js" \
  --enable-llm-layer
```

#### 4. False Positives and Due Process

**Layer 2 and Layer 3 can produce false positives**. You must:

- **Review blocked requests manually** before taking action against users
- **Provide appeal process** for clients claiming false positives
- **Document decision rationale** when permanently blocking clients (Strike 3)
- **Avoid automated bans** based solely on Layer 2/3 findings

**Example: False Positive Scenario**
```json
// Layer 2 blocks legitimate GraphQL query
{
  "blocked": true,
  "layer": 2,
  "findings": [{
    "severity": "medium",
    "message": "Suspicious pattern: nested object manipulation",
    "pattern": "{ user { profile { settings } } }"
  }]
}

// Action Required: Manual review confirms this is valid GraphQL, not an attack
// Solution: Whitelist client or adjust Layer 2 thresholds
```

#### 5. Panic Stop System and Fairness

The 3-strike Panic Stop system is designed to prevent DoS, but can impact legitimate users:

**Fairness Requirements:**
- **Monitor strike counts** regularly (`jq 'select(.strikes > 0)' audit.jsonl`)
- **Investigate root causes** of rate limit errors (429) before Strike 3
- **Provide warning notifications** to clients after Strike 1 and Strike 2
- **Implement manual override** for trusted clients
- **Restart proxy** to reset panic state if false positive strikes occurred

**Example: Monitoring Strike Counts**
```bash
# Check clients approaching Strike 3
jq -s 'group_by(.clientId) | map({client: .[0].clientId, maxStrikes: ([.[].strikes] | max)}) | .[] | select(.maxStrikes >= 2)' ./logs/security-audit.jsonl

# Output:
# {"client": "192.168.1.100", "maxStrikes": 2}
# → Action Required: Investigate before this client hits permanent ban
```

#### 6. Disclosure to End Users

If you deploy the Security Proxy in a multi-user environment:

**You Must Disclose:**
- That traffic is being monitored for security purposes
- What data is logged (requests, client IDs, timestamps)
- How long logs are retained
- Whether Layer 3 (external LLM analysis) is enabled
- How users can appeal false positive blocks

**Example Disclosure Notice:**
```
Security Notice: This MCP server is protected by mcp-verify Security Gateway.

- All requests are analyzed for security threats in real-time
- Malicious requests will be blocked and logged
- Client IP addresses and request patterns are recorded for security audit
- Repeated violations may result in temporary or permanent access restrictions
- No request data is sent to external services (LLM analysis is disabled)
- Audit logs are retained for 90 days and stored securely
- To appeal a block, contact: security@your-domain.com
```

#### 7. Compliance with Monitoring Laws

**Legal Requirements Vary by Jurisdiction:**

- **United States**: Generally permitted for own systems, must notify in multi-party scenarios
- **European Union**: GDPR Article 6 requires lawful basis (legitimate interest or consent)
- **California**: CCPA requires disclosure of data collection practices
- **Others**: Consult local laws on network monitoring and data retention

**When in Doubt:**
- Consult legal counsel before deployment
- Implement clear privacy policies
- Obtain consent where required
- Minimize data collection to security-essential only

---

### Security Proxy: Dos and Don'ts

| ✅ DO | ❌ DON'T |
|-------|----------|
| Proxy only your own MCP servers | Proxy third-party servers without authorization |
| Store audit logs securely (chmod 600) | Share raw audit logs publicly |
| Use Layers 1+2 for production | Enable Layer 3 (LLM) without understanding privacy implications |
| Review Layer 2/3 blocks manually | Automatically ban users based on suspicious patterns |
| Disclose monitoring to end users | Hide the fact that traffic is being analyzed |
| Provide appeal process for blocks | Implement permanent bans without investigation |
| Monitor strike counts proactively | Wait until Strike 3 to investigate 429 errors |
| Use self-hosted Ollama for LLM analysis | Send sensitive data to external LLM APIs |
| Implement log retention policies | Store audit logs indefinitely |
| Restart proxy to reset false positive strikes | Leave innocent clients permanently banned |

---

### Example: Responsible Production Deployment

```bash
# 1. Secure configuration
mkdir -p ./logs
chmod 700 ./logs

# 2. Start proxy with privacy-safe settings
node dist/mcp-verify.js proxy \
  --target "node production-server.js" \
  --port 3000 \
  --rate-limit 100 \
  --audit-log ./logs/security-audit.jsonl \
  --no-llm-layer

# 3. Implement log rotation (delete logs after 90 days)
find ./logs -name "*.jsonl" -mtime +90 -delete

# 4. Monitor for false positive strikes
jq -s 'group_by(.clientId) | map({client: .[0].clientId, strikes: ([.[].strikes] | max)}) | .[] | select(.strikes >= 1)' ./logs/security-audit.jsonl

# 5. Provide disclosure notice to clients
echo "Security Monitoring Enabled" > ./SECURITY_NOTICE.txt

# 6. Establish appeal process
# Create email alias: security-appeals@your-domain.com
```

---

### Reporting Security Proxy Issues

If you discover:
- False positive patterns in Layer 1 (should NEVER happen)
- Systematic Layer 2 false positives for legitimate use cases
- Privacy concerns with audit log data
- Client-aware isolation bypass vulnerabilities

**Report to:** hello.finksystems@gmail.com with subject "Security Proxy Issue"

**Include:**
- Anonymized request patterns (remove sensitive data)
- Layer that triggered the block
- Expected vs. actual behavior
- Steps to reproduce

**Do NOT include:**
- Full audit logs (may contain sensitive data)
- Client IP addresses or identifiers
- Production secrets or credentials

---

## Final Word

Security tools are powerful.
With power comes responsibility.

**MCP Verify is a tool for builders, not breakers.**

If you're securing your infrastructure, welcome.
If you're protecting your users, welcome.
If you're learning security responsibly, welcome.

If you're looking to exploit others, **this is not for you.**

---

**Questions?**
- Read our [Security Policy](SECURITY.md)
- Check our [GitHub Discussions](https://github.com/FinkTech/mcp-verify/discussions)
- Contact us: hello.finksystems@gmail.com

**Stay ethical. Stay legal. Stay defensive.**

---

**License:** AGPL-3.0 (see [LICENSE](LICENSE))
**Last Updated:** 2026-03-01
**Maintained by:** Ariel Fink (@FinkTech)
