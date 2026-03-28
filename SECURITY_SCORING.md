# 🛡️ Technical Vulnerability Scoring System

**Last Updated**: 2026-02-12
**Target Audience**: Security Engineers, DevOps
**Purpose**: Understand how mcp-verify calculates vulnerability scores

---

## 🎯 Overview

mcp-verify calculates a **Technical Vulnerability Score (0-100)** based on static analysis of MCP server capabilities. The score measures the **technical attack surface** - patterns that correlate with common vulnerabilities.

> ⚠️ **Important Disclaimer**
>
> This score measures **technical vulnerability indicators**, NOT overall security posture.
> - A score of 100 means "no known vulnerability patterns detected"
> - It does **NOT** mean "perfectly secure" or "production-ready"
> - It does **NOT** analyze business logic, authentication correctness, or runtime behavior
> - For production deployments, a professional security audit is recommended

---

## 📊 Score Calculation Algorithm (Unified Engine)

Every server starts with **100 points** (maximum security). mcp-verify v1.0 uses a **Unified Scoring Engine** that combines multiple sources of truth.

### 1. Static Penalty (Theoretical Risk)

Deductions based on declarative schema analysis (60 rules).

| Severity | Penalty | Examples |
|----------|---------|----------|
| **CRITICAL** | -40 | Command execution, SQL injection, SSRF |
| **HIGH** | -25 | File system modification, credential exposure |
| **MEDIUM** | -15 | Network requests, weak crypto, no maxLength |
| **LOW** | -5 | Missing mimeType, no pattern |

### 2. Fuzzer Penalty (Confirmed Vulnerabilities)

Vulnerabilities actually triggered during fuzzing have a **1.75x multiplier** because they represent a real exploit, not just a risk.

| Fuzzer Severity | High Confidence (1.0) | Med Confidence (0.75) | Low Confidence (0.5) |
|-----------------|-----------------------|-----------------------|----------------------|
| **CRITICAL**    | -70 points            | -52.5 points          | -35 points           |
| **HIGH**        | -43.75 points         | -32.8 points          | -21.8 points         |
| **MEDIUM**      | -26.25 points         | -19.6 points          | -13.1 points         |

### 3. Final Score Formula

```
Final Score = 100 - StaticPenalties - (FuzzerPenalties × 1.75 × ConfidenceWeight) - LLMPenalties
Minimum = 0
Maximum = 100
```

---

## 🎨 Risk Levels

| Score Range | Risk Level | Color | Meaning | Action Required |
|-------------|-----------|-------|---------|-----------------|
| **90-100** | ✅ **EXCELLENT** | 🟢 Green | Production-ready, minimal risk | ✅ Safe to deploy |
| **70-89** | ⚠️ **GOOD** | 🟡 Yellow | Some risks detected, review recommended | ⚠️ Review findings, fix high-severity issues |
| **50-69** | 🟠 **FAIR** | 🟠 Orange | Multiple risks, caution advised | 🔍 Thorough review required before production |
| **<50** | 🔴 **POOR** | 🔴 Red | Critical issues detected | ❌ **DO NOT USE** in production |

---

## 🚩 Detection Rule Blocks (60 Rules Total)

The scanner evaluates 60 rules organized into specialized security blocks:

### 1. Block OWASP: Industry Standard Risks (13 rules)
- **SEC-001 to SEC-013**: Auth Bypass, Command Injection, SQL Injection, SSRF, XXE, Insecure Deserialization, Path Traversal, Data Leakage, Sensitive Exposure, Rate Limiting, ReDoS, Weak Cryptography, and Prompt Injection.

### 2. Block MCP: Protocol-Specific Risks (8 rules)
- **SEC-014 to SEC-021**: Exposed Endpoints, Missing Authentication, Insecure URI Schemes, Excessive Permissions, Secrets in Descriptions, Missing Input Constraints, Dangerous Tool Chaining, Unencrypted Credentials.

### 3. Block A: OWASP LLM Top 10 (9 rules)
- **SEC-022 to SEC-030**: Insecure Output Handling, Excessive Agency, Prompt Injection via Tools, Supply Chain Tool Dependencies, Sensitive Data in Tool Responses, Training Data Poisoning, Model DoS via Tools, Insecure Plugin Design, Excessive Data Disclosure.

### 4. Block B: Multi-Agent & Agentic Attacks (11 rules)
- **SEC-031 to SEC-041**: Agent Identity Spoofing, Tool Result Tampering, Recursive Agent Loop, Multi-Agent Privilege Escalation, Agent State Poisoning, Distributed Agent DDoS, Cross-Agent Prompt Injection, Agent Reputation Hijacking, Tool Chaining Path Traversal, Agent Swarm Coordination, Agent Memory Injection.

### 5. Block C: Operational & Enterprise Compliance (9 rules)
- **SEC-042 to SEC-050**: Missing Audit Logging, Insecure Session Management, Schema Versioning Absent, Insufficient Error Granularity, Missing CORS Validation, Insecure Default Configuration, Missing Capability Negotiation, Timing Side-Channel in Auth, Insufficient Output Entropy.

### 6. Block D: AI Weaponization & Supply Chain (10 rules)
- **SEC-051 to SEC-060**: Weaponized MCP Fuzzer, Autonomous MCP Backdoor, Malicious Config File, API Endpoint Hijacking, Jailbreak-as-a-Service, Phishing via MCP, Data Exfiltration via Steganography, Self-Replicating MCP, Unvalidated Tool Authorization, Missing Transaction Semantics.

---

## 🚩 Individual Rule Details (OWASP Block)

Below are details for the 13 OWASP-aligned rules from the main block:

---

### Rule SEC-013: Prompt Injection

**Pattern**: `prompt`, `task`, `instruction`, `message` without limits

**Severity**: MEDIUM (-10) / LOW (-5)

**Example**:
```json
{
  "name": "ask_ai",
  "description": "Ask anything to the AI",
  "inputSchema": {
    "properties": {
      "user_prompt": { "type": "string" }  // ❌ No maxLength or pattern
    }
  }
}
```

**Mitigation**: Implement `maxLength`, use strict `pattern` regex, sanitize prompt arguments.

---

### Rule SEC-007: Path Traversal

**Pattern**: `../`, `..\`, file path manipulation

**Severity**: CRITICAL (-30)

**Example**:
```json
{
  "name": "read_file",
  "description": "Read any file from disk",
  "inputSchema": {
    "properties": {
      "path": { "type": "string" }  // ❌ No validation
    }
  }
}
```

**Mitigation**: Validate paths, use whitelist, prevent directory traversal.

---

### Rule SEC-002: Command Injection

**Pattern**: `exec`, `shell`, `bash`, `cmd`, `system`, `eval`

**Severity**: CRITICAL (-30)

**Example**:
```json
{
  "name": "run_command",
  "description": "Execute system command",
  "inputSchema": {
    "properties": {
      "command": { "type": "string" }  // ❌ Arbitrary execution
    }
  }
}
```

**Mitigation**: Disable shell commands or use strict whitelists.

---

### Rule SEC-004: SSRF (Server-Side Request Forgery)

**Pattern**: `fetch`, `curl`, `request`, `http`, URLs in parameters

**Severity**: CRITICAL (-30)

**Example**:
```json
{
  "name": "fetch_url",
  "description": "Fetch content from URL",
  "inputSchema": {
    "properties": {
      "url": { "type": "string" }  // ❌ No URL validation
    }
  }
}
```

**Mitigation**: Whitelist allowed domains, block private IPs.

---

### Rule SEC-008: Data Leakage

**Pattern**: `api_key`, `token`, `password`, `secret` in descriptions

**Severity**: HIGH (-15)

**Example**:
```json
{
  "name": "fetch_data",
  "description": "Fetch data using API key: sk-abc123"  // ❌ Exposed secret
}
```

**Mitigation**: Never hardcode secrets in tool descriptions.

---

### Rule SEC-005: XXE Injection

**Pattern**: XML parsing without disabling external entities

**Severity**: HIGH (-15)

**Example**:
```json
{
  "name": "parse_xml",
  "description": "Parse XML document"  // ❌ No XXE protection mentioned
}
```

**Mitigation**: Disable XML external entities when parsing.

---

### Rule SEC-006: Insecure Deserialization

**Pattern**: `pickle`, `marshal`, `eval`, unsafe object parsing

**Severity**: HIGH (-15)

**Example**:
```json
{
  "name": "load_object",
  "description": "Load Python pickle object"  // ❌ RCE risk
}
```

**Mitigation**: Use JSON instead of pickle, validate input.

---

### Rule SEC-003: SQL Injection

**Pattern**: `sql`, `query`, `database`, dynamic SQL

**Severity**: CRITICAL (-30)

**Example**:
```json
{
  "name": "execute_query",
  "description": "Execute SQL query",
  "inputSchema": {
    "properties": {
      "query": { "type": "string" }  // ❌ Raw SQL
    }
  }
}
```

**Mitigation**: Use parameterized queries, ORM, or read-only access.

---

### Rule SEC-011: ReDoS (Regular Expression DoS)

**Pattern**: Complex regex patterns without timeout

**Severity**: MEDIUM (-10)

**Example**:
```json
{
  "name": "validate_input",
  "description": "Validate with regex: (a+)+"  // ❌ Exponential backtracking
}
```

**Mitigation**: Simplify regex, add timeout, use safe patterns.

---

### Rule SEC-001: Authentication Bypass

**Pattern**: Weak password requirements, missing auth

**Severity**: HIGH (-15)

**Example**:
```json
{
  "name": "login",
  "inputSchema": {
    "properties": {
      "password": {
        "type": "string",
        "minLength": 4  // ❌ Too short
      }
    }
  }
}
```

**Mitigation**: Enforce strong passwords (min 8 chars), use MFA.

---

### Rule SEC-009: Sensitive Data Exposure

**Pattern**: API keys, PII, credentials in parameters/descriptions

**Severity**: HIGH (-15)

**Example**:
```json
{
  "name": "backup",
  "inputSchema": {
    "properties": {
      "api_key": { "type": "string" }  // ❌ Credential in parameter
    }
  }
}
```

**Mitigation**: Use environment variables for secrets.

---

### Rule SEC-010: Rate Limiting

**Pattern**: Missing rate limits for expensive operations

**Severity**: MEDIUM (-10)

**Example**:
```json
{
  "name": "generate_report",
  "description": "Generate PDF report"  // ❌ No rate limit mentioned
}
```

**Mitigation**: Implement rate limiting, quota systems.

---

### Rule SEC-012: Weak Cryptography

**Pattern**: `md5`, `sha1`, weak crypto algorithms

**Severity**: MEDIUM (-10)

**Example**:
```json
{
  "name": "hash_password",
  "description": "Hash password using MD5"  // ❌ Weak algorithm
}
```

**Mitigation**: Use bcrypt, Argon2, or scrypt for passwords.

---

## 📈 Scoring Examples

### Example 1: Read-Only Server (Score: 100)

```json
{
  "tools": [
    {
      "name": "get_weather",
      "description": "Get current weather for a city",
      "inputSchema": {
        "properties": {
          "city": { "type": "string" }
        }
      }
    }
  ]
}
```

**Analysis**:
- ✅ No dangerous patterns detected
- ✅ Read-only operation
- ✅ Simple input validation

**Score**: 100 (EXCELLENT)

---

### Example 2: File Reader with Risks (Score: 70)

```json
{
  "tools": [
    {
      "name": "read_file",
      "description": "Read file contents",
      "inputSchema": {
        "properties": {
          "path": { "type": "string" }  // ❌ No path validation
        }
      }
    }
  ]
}
```

**Analysis**:
- ❌ **SEC-007**: Path traversal risk (-30)
- ⚠️ File system access without restrictions

**Score**: 70 (GOOD - Review required)

---

### Example 3: Command Executor (Score: 30)

```json
{
  "tools": [
    {
      "name": "execute_bash",
      "description": "Execute bash commands. API key: sk-abc123",
      "inputSchema": {
        "properties": {
          "command": { "type": "string" }
        }
      }
    }
  ]
}
```

**Analysis**:
- ❌ **SEC-002**: Command injection (-30)
- ❌ **SEC-008**: Exposed secret in description (-15)
- ❌ **SEC-009**: Credential exposure (-15)

**Score**: 40 → Capped at 30 (POOR - DO NOT USE)

---

## 🎯 Acceptable Risk Levels by Environment

### Production Environments

| Environment Type | Minimum Score | Recommendation |
|------------------|---------------|----------------|
| **Public-Facing APIs** | 90+ | Only deploy servers with EXCELLENT rating |
| **Internal Tools** | 80+ | Good-Excellent rating, review all findings |
| **Development/Staging** | 70+ | Fair rating acceptable, but fix before production |
| **Local Development** | 50+ | Any rating, but understand risks |

### Use Case Matrix

| Use Case | Acceptable Score | Rationale |
|----------|------------------|-----------|
| **Third-Party MCP Server** | 90+ | You don't control the code, require high confidence |
| **Your Own Server (Public)** | 85+ | You control it, but exposed to internet |
| **Internal Server (Private Network)** | 75+ | Lower risk due to network isolation |
| **Prototype/POC** | 60+ | Testing only, not production |

---

## 🛡️ Score Interpretation Guide

### Score 90-100 (EXCELLENT)

**Meaning**: Server follows security best practices. Minimal attack surface detected.

**What to do**:
- ✅ Safe for production deployment
- ✅ Proceed with deployment
- ⚠️ Still review LLM semantic findings (if enabled)

**Example Servers**:
- Weather API (read-only)
- Documentation search
- Read-only database queries

---

### Score 70-89 (GOOD)

**Meaning**: Some security concerns detected. Likely safe but requires review.

**What to do**:
- ⚠️ Review all findings before deployment
- ⚠️ Fix HIGH-severity issues
- ⚠️ Document accepted risks
- ✅ Deploy after review

**Example Servers**:
- File readers with path validation
- Write operations with whitelisting
- Network requests with domain restrictions

---

### Score 50-69 (FAIR)

**Meaning**: Multiple security issues detected. Use with caution.

**What to do**:
- 🔍 Thorough security review required
- 🔍 Fix all CRITICAL issues
- 🔍 Consider alternative servers
- ⚠️ Only deploy to isolated environments

**Example Servers**:
- File writers without proper validation
- Database tools with dynamic queries
- Network tools without SSRF protection

---

### Score <50 (POOR)

**Meaning**: Critical security vulnerabilities detected. Likely unsafe.

**What to do**:
- ❌ **DO NOT DEPLOY** to production
- ❌ Fix critical issues immediately
- ❌ Consider complete redesign
- ✅ Use only for testing/learning

**Example Servers**:
- Arbitrary command executors
- Unprotected SQL query tools
- File system access without restrictions

---

## 🔍 Additional Factors (Beyond Score)

The security score is one metric. Also consider:

### 1. **Source Trust**
- Who developed the server?
- Is it open source?
- Has it been audited?

### 2. **Network Exposure**
- Is it internet-facing?
- Behind VPN/firewall?
- Local-only?

### 3. **Data Sensitivity**
- What data does it access?
- PII, financial, health records?
- Public data only?

### 4. **Usage Context**
- Production vs. development
- Number of users
- Criticality to business

---

## 📋 Security Checklist

Before deploying an MCP server:

- [ ] Security score ≥ 90 (or documented exceptions)
- [ ] All CRITICAL findings resolved
- [ ] All HIGH findings reviewed and mitigated
- [ ] LLM semantic analysis passed (if enabled)
- [ ] Manual code review completed
- [ ] Penetration testing performed (if high-value)
- [ ] Incident response plan documented
- [ ] Monitoring/alerting configured

---

## 🚨 False Positives

Static analysis can produce false positives:

### Common False Positives

1. **SQL Tool for DBAs**
   - Intentionally allows SQL queries
   - Mitigation: Document in `.mcpignore`, restrict access

2. **System Admin Tool**
   - Legitimately needs command execution
   - Mitigation: Strong authentication, audit logs

3. **File Manager**
   - Needs file system access
   - Mitigation: Path whitelisting, sandboxing

### Handling False Positives

Use `.mcpverifyignore` to suppress known false positives:

```
# .mcpverifyignore
[rule:SEC-003:database_admin]   # SQL tool for DBAs
[rule:SEC-002:system_admin]     # Legit system tool
```

---

## 📊 Trend Analysis

Track security scores over time:

```bash
# Save baseline
mcp-verify validate <target> --save-baseline v1.0.0.json

# Compare against baseline
mcp-verify validate <target> --compare-baseline v1.0.0.json
```

**Goal**: Security score should never decrease between releases.

---

## 🔗 Related Documentation

- [Security Model](./SECURITY.md) - Overall security approach
- [Examples](./guides/EXAMPLES.md) - Validation commands
- [CI/CD Integration](./guides/CI_CD.md) - Automated security checks

---

## ❓ FAQ

**Q: What's a "good enough" score for production?**
A: **90+** for public-facing, **80+** for internal tools.

**Q: Score is 100 but I found a vulnerability. Why?**
A: Static analysis has limitations. Report false negatives as GitHub issues.

**Q: Can I customize scoring rules?**
A: Not yet. This feature is planned for a future release.

**Q: How does LLM analysis affect the score?**
A: LLM findings are added as additional security issues, lowering the score if concerns are found.

**Q: Should I trust a third-party server with score 100?**
A: Score 100 means "no known patterns detected". Always review code manually for critical systems.

---

## ⚠️ Disclaimer

The security score is a **risk indicator**, not a guarantee. mcp-verify:

- ✅ Detects common vulnerability patterns
- ✅ Provides risk assessment
- ❌ Does NOT guarantee runtime security
- ❌ Does NOT replace manual audits
- ❌ Does NOT test implementation quality

**Use mcp-verify as one layer in defense-in-depth, not as the only security measure.**

