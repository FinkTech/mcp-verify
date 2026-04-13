# 🏢 Professional MCP Server Validation Guide

**Last Updated**: 2026-02-04
**Target Audience**: Enterprise DevSecOps, Production Environments
**Time to Complete**: 20 minutes

---

## ⚠️ Important Disclaimer

**mcp-verify is a development tool that helps catch common vulnerabilities early.** It is **NOT**:

- ❌ A replacement for professional security audits
- ❌ A certification or guarantee of security
- ❌ A comprehensive penetration testing tool
- ❌ Able to detect all types of vulnerabilities

**What mcp-verify CAN do**:

- ✅ Detect common OWASP vulnerabilities (SQL injection, command injection, etc.)
- ✅ Validate MCP protocol compliance
- ✅ Check documentation quality
- ✅ Track security trends over time

**What mcp-verify CANNOT detect**:

- ❌ Business logic flaws
- ❌ Race conditions
- ❌ Complex authentication/authorization bugs
- ❌ Advanced cryptographic issues
- ❌ Zero-day vulnerabilities

**A high security score (90+) does NOT mean your server is production-ready.** Always conduct professional security audits before deploying to production.

---

## 🎯 What You'll Learn

This guide shows how to use mcp-verify to validate a **real production MCP server**, including:

- ✅ Pre-deployment security checks
- ✅ Baseline establishment for regression detection
- ✅ CI/CD integration patterns
- ✅ Report interpretation
- ✅ Understanding limitations

**Example Use Case**: Auditing a third-party GitHub MCP server before deploying to your enterprise Claude Desktop installation.

---

## 📋 Prerequisites

- Node.js >= 18.0.0
- mcp-verify installed (see [README.md](../README.md))
- The MCP server you want to validate
- (Optional) Anthropic API key for semantic analysis

---

## 🚀 Step 1: Initial Quick Validation

### Goal: Fast sanity check (< 1 minute)

First, let's validate the server with minimal options to ensure it responds correctly:

```bash
# Clone and build mcp-verify
git clone https://github.com/FinkTech/mcp-verify.git
cd mcp-verify
npm install
npm run build

# Quick validation
mcp-verify validate "npx -y @modelcontextprotocol/server-github"
```

### Expected Output

```
✓ Testing handshake
✓ Discovering capabilities
✓ Validating schema
✓ Running security audit (61 rules)
✓ Generating report

Validation Report:
──────────────────────────────────────────────────
Server: github-mcp-server
Protocol: 2024-11-05
Status: ✓ Valid

Tools: 18 (18 valid)
Resources: 0
Prompts: 0

Security Score: 75/100 (GOOD)
Quality Score: 88/100
──────────────────────────────────────────────────
JSON: ./reportes/json/mcp-report-2026-02-04.json
HTML: ./reportes/html/mcp-report-2026-02-04.html
```

### Interpretation

| Metric                   | Value        | Meaning                                                       |
| ------------------------ | ------------ | ------------------------------------------------------------- |
| **Status: Valid**        | ✓            | Server responds to MCP protocol (does NOT guarantee security) |
| **Security: 75**         | 🟡 Good      | **May have issues**, requires deeper analysis                 |
| **Quality: 88**          | 🟢 Excellent | Well-documented tools                                         |
| **Protocol: 2024-11-05** | ✓            | Latest MCP specification                                      |

**⚠️ Important**: A "Valid" status only means the server **responds correctly to the MCP protocol**. It does **NOT** mean the server is secure or production-ready.

---

## 🔒 Step 2: Deep Security Analysis

### Goal: Identify common vulnerabilities (OWASP-aligned)

```bash
mcp-verify validate "npx -y @modelcontextprotocol/server-github" \
  --security \
  --verbose \
  --html \
  --format sarif \
  --output ./github-mcp-audit
```

### Example Security Findings

```json
{
  "security": {
    "score": 75,
    "totalFindings": 4,
    "bySeverity": {
      "critical": 0,
      "high": 2,
      "medium": 2,
      "low": 0
    },
    "findings": [
      {
        "ruleCode": "SEC-003",
        "severity": "high",
        "message": "Potential SSRF vulnerability in create_or_update_file tool",
        "component": "create_or_update_file",
        "description": "Tool accepts user-provided URLs without validation",
        "remediation": "Validate and whitelist allowed GitHub API endpoints",
        "cwe": "CWE-918"
      },
      {
        "ruleCode": "SEC-010",
        "severity": "high",
        "message": "GitHub token pattern detected in tool descriptions",
        "component": "list_commits",
        "description": "Tool description contains example with real token pattern",
        "remediation": "Use placeholder tokens in documentation (e.g., 'ghp_XXXX')",
        "cwe": "CWE-200"
      },
      {
        "ruleCode": "SEC-004",
        "severity": "medium",
        "message": "Potential data leakage: Debug logs may expose sensitive information",
        "component": "push_files",
        "description": "Console.log statements include full API responses",
        "remediation": "Remove debug logs or use structured logging with redaction"
      },
      {
        "ruleCode": "SEC-011",
        "severity": "medium",
        "message": "Missing rate limiting for GitHub API calls",
        "component": "global",
        "description": "No visible rate limiting wrapper around GitHub API",
        "remediation": "Implement exponential backoff and respect X-RateLimit headers"
      }
    ]
  }
}
```

### ⚠️ Understanding These Findings

**Critical Issues**: 0 (No immediate blockers detected by static analysis)
**High Issues**: 2 (Potential SSRF + Token exposure patterns)

**Important**: These are **potential** vulnerabilities based on static code analysis. They may be:

- ✅ True positives (real vulnerabilities)
- ❌ False positives (acceptable patterns in context)
- ⚠️ Incomplete (may miss complex vulnerabilities)

**Recommendation**: Manually review each finding and conduct deeper testing.

---

## 🧠 Step 3: LLM Semantic Analysis (Optional)

### Goal: Catch additional issues that static analysis might miss

```bash
# Option 1: Free (Ollama - requires local setup)
ollama pull llama3.2
mcp-verify validate "npx -y @modelcontextprotocol/server-github" \
  --llm ollama:llama3.2 \
  --security \
  --html

# Option 2: Paid (Anthropic - best quality, ~$0.0003/scan)
export ANTHROPIC_API_KEY="sk-ant-api03-..."
mcp-verify validate "npx -y @modelcontextprotocol/server-github" \
  --llm anthropic:claude-haiku-4-5-20251001 \
  --security \
  --html
```

### Example LLM Findings

```
LLM Semantic Analysis Results:
─────────────────────────────────────────

✓ Documentation Quality: 92/100
  - Clear descriptions for 17/18 tools
  - Missing: Example usage for 'create_pull_request'

⚠️ Naming Consistency: 78/100
  - Inconsistent verb tense: 'create_issue' vs 'list_commits'
  - Recommendation: Standardize to imperative mood

🔴 Potential Security Concerns (LLM-detected):
  - Tool 'search_code' allows regex without visible complexity limits
    → Risk: Potential ReDoS attacks via malicious regex patterns
    → Remediation: Implement regex timeout or use safe regex library

  - Tool 'fork_repository' lacks validation on target owner
    → Risk: Fork to attacker-controlled organization
    → Remediation: Whitelist allowed target organizations

🔍 Quality Issues:
  - Parameter 'branch' in 'create_or_update_file' has ambiguous description
  - 3 tools use 'repo' while 2 use 'repository' (inconsistent)
```

**⚠️ LLM Limitations**: LLM analysis provides suggestions based on code patterns but:

- May generate false positives
- Cannot execute code or test runtime behavior
- Depends on LLM model quality
- Should be manually verified

---

## 📊 Step 4: Generate Reports

### HTML Report (for human review)

```bash
mcp-verify validate "npx -y @modelcontextprotocol/server-github" \
  --security \
  --llm anthropic:claude-haiku-4-5-20251001 \
  --format html \
  --output ./audit-reports

# Open in browser
open ./audit-reports/html/mcp-report-*.html
```

### SARIF Report (for GitHub Security tab)

```bash
mcp-verify validate "npx -y @modelcontextprotocol/server-github" \
  --security \
  --format sarif \
  --output ./audit-reports
```

**Upload to GitHub**:

- Navigate to: Repository → Security → Code Scanning
- Upload: `audit-reports/sarif/mcp-report-*.sarif`
- View findings directly in GitHub UI

---

## 🎯 Step 5: Establish Baseline (Regression Detection)

### Goal: Track security trends over time

```bash
# Create v1.0.0 baseline
mcp-verify validate "npx -y @modelcontextprotocol/server-github" \
  --security \
  --save-baseline ./baselines/github-mcp-v1.0.0.json

# Store baseline in version control
git add baselines/github-mcp-v1.0.0.json
git commit -m "chore: save mcp-verify baseline for github-mcp v1.0.0"
git push
```

### Compare Future Versions

```bash
# Validate new version against baseline
mcp-verify validate "npx -y @modelcontextprotocol/server-github@1.1.0" \
  --security \
  --compare-baseline ./baselines/github-mcp-v1.0.0.json \
  --fail-on-degradation \
  --allowed-score-drop 5
```

**What this detects**: Regressions in security score, **not** all new vulnerabilities.

---

## 🛡️ Step 6: Suppressing False Positives

### Example: SSRF warning is acceptable in context

Create `.mcpverifyignore`:

```bash
# .mcpverifyignore - Document why findings are suppressed

# GitHub MCP server intentionally connects to GitHub API
# Acceptable because:
# 1. Only connects to github.com (manually verified in code)
# 2. Token has limited scopes (read-only, manually configured)
# 3. Rate limiting verified in GitHub SDK source code
SEC-003:create_or_update_file

# Debug logs needed for enterprise support
# Risk accepted: logs are only written to local files, not network
SEC-004:push_files

# Rate limiting delegated to GitHub SDK (verified in dependencies)
SEC-011
```

**Important**: Document **why** each suppression is safe. Review quarterly.

---

## 🏗️ Step 7: CI/CD Integration

### GitHub Actions Workflow

```yaml
# .github/workflows/mcp-validation.yml
name: MCP Server Security Checks

on:
  pull_request:
    branches: [main]
  schedule:
    - cron: "0 0 * * 0" # Weekly audit

jobs:
  validate-mcp-server:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v3

      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: "18"

      - name: Install mcp-verify
        run: |
          git clone https://github.com/FinkTech/mcp-verify.git
          cd mcp-verify
          npm install && npm run build

      - name: Run Security Checks
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          cd mcp-verify
          mcp-verify validate \
            "npx -y @modelcontextprotocol/server-github" \
            --security \
            --llm anthropic:claude-haiku-4-5-20251001 \
            --format sarif \
            --compare-baseline ../baselines/github-mcp-v1.0.0.json \
            --fail-on-degradation \
            --output ../reports

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: reports/sarif/mcp-report-*.sarif
          category: mcp-security
```

**What this provides**:

- ✅ Automated regression detection
- ✅ GitHub Security tab integration
- ❌ Does NOT replace manual security review

---

## 📈 Step 8: Production Deployment Decision

### Decision Matrix

| Metric          | Value  | Production Guidance | Status    |
| --------------- | ------ | ------------------- | --------- |
| Security Score  | 85/100 | ≥ 90 recommended    | ⚠️ REVIEW |
| Critical Issues | 0      | Must be 0           | ✅ PASS   |
| High Issues     | 2      | Should be 0         | ⚠️ REVIEW |
| Medium Issues   | 2      | ≤ 5 acceptable      | ✅ PASS   |
| Quality Score   | 90/100 | ≥ 80 recommended    | ✅ PASS   |

**⚠️ Important Decision Criteria**:

**DO NOT deploy to production based on mcp-verify score alone.** Additional required steps:

1. ✅ **Manual code review** of all high/critical findings
2. ✅ **Penetration testing** by security professionals
3. ✅ **Runtime testing** (mcp-verify is static analysis only)
4. ✅ **Threat modeling** for your specific use case
5. ✅ **Security audit** by qualified professionals

**mcp-verify helps you catch common issues early, but is not a substitute for professional security assessment.**

---

## 📚 Complete Command Reference

### Development (Quick Checks)

```bash
# Fast validation during development
mcp-verify validate "node server.js"
```

### Staging (Deeper Analysis)

```bash
# Full security + quality checks
mcp-verify validate "node server.js" \
  --security \
  --llm ollama:llama3.2 \
  --html
```

### Pre-Production (Comprehensive Audit)

```bash
# Maximum coverage (still not a replacement for professional audit)
mcp-verify validate "node server.js" \
  --security \
  --llm anthropic:claude-haiku-4-5-20251001 \
  --format html \
  --format sarif \
  --save-baseline ./baselines/production.json
```

### Production Monitoring (Regression Detection)

```bash
# Weekly regression checks
mcp-verify validate "node server.js" \
  --security \
  --compare-baseline ./baselines/production.json \
  --fail-on-degradation
```

---

## 🎯 Recommended Security Thresholds

### By Environment (Guidelines, NOT Guarantees)

| Environment | Min Score | Critical | High | Medium | Additional Required             |
| ----------- | --------- | -------- | ---- | ------ | ------------------------------- |
| Development | 50+       | Any      | Any  | Any    | Code review                     |
| Staging     | 70+       | 0        | ≤ 3  | ≤ 10   | Manual testing                  |
| Production  | 90+       | 0        | 0    | ≤ 2    | **Professional security audit** |

**Note**: These are **minimum** suggestions. A score of 90+ does **NOT** mean "production-ready". Always conduct professional security audits.

---

## ⚠️ What mcp-verify Does NOT Guarantee

Even with a perfect score (100/100), mcp-verify **cannot** detect:

1. **Business Logic Flaws**
   - Example: Incorrect permission checks in your application logic
   - Requires: Domain-specific manual review

2. **Race Conditions**
   - Example: Concurrent requests causing data corruption
   - Requires: Concurrency testing

3. **Authentication/Authorization Bugs**
   - Example: Missing access control on sensitive operations
   - Requires: Penetration testing

4. **Advanced Cryptographic Issues**
   - Example: Implementation flaws in encryption
   - Requires: Cryptography expert review

5. **Supply Chain Vulnerabilities**
   - Example: Malicious dependencies
   - Requires: Dependency scanning tools (npm audit, Snyk, etc.)

6. **Zero-Day Vulnerabilities**
   - Example: Unknown vulnerabilities in dependencies
   - Requires: Continuous monitoring

**mcp-verify is a helpful development tool, not a security certification.**

---

## 🆘 Common Issues

### Issue: High score but server still vulnerable

**Reality**: mcp-verify uses static analysis with limited scope. A high score means:

- ✅ No common OWASP patterns detected
- ❌ Does NOT mean "no vulnerabilities exist"

**Solution**: Always conduct manual security reviews and penetration testing.

### Issue: Low score but server is actually safe

**Reality**: False positives happen, especially with:

- Admin tools with intentional elevated permissions
- Test fixtures
- Legitimate use cases that pattern-match vulnerabilities

**Solution**: Use `.mcpverifyignore` with clear justifications.

---

## 📊 Real-World Usage

### What mcp-verify IS good for:

- ✅ Early detection of common vulnerabilities
- ✅ Regression detection in CI/CD
- ✅ Documentation quality checks
- ✅ Protocol compliance validation
- ✅ Trend tracking over time

### What mcp-verify is NOT good for:

- ❌ Final production security certification
- ❌ Replacing professional audits
- ❌ Detecting complex business logic flaws
- ❌ Runtime vulnerability testing

---

## 🎓 Next Steps

1. ✅ **Use mcp-verify** to catch common issues early
2. ✅ **Integrate into CI/CD** for regression detection
3. ✅ **Document suppressions** in `.mcpverifyignore`
4. ⚠️ **Do NOT rely solely on mcp-verify** for production decisions
5. ✅ **Conduct professional security audits** before production deployment

---

## 📚 Related Documentation

- [EXAMPLES.md](./EXAMPLES.md) - Copy-paste commands
- [CI_CD.md](./CI_CD.md) - CI/CD integration patterns
- [LLM_SETUP.md](./LLM_SETUP.md) - Configure AI analysis
- [SECURITY_SCORING.md](../SECURITY_SCORING.md) - How scoring works

---

## 💡 Pro Tips

### Tip 1: Combine with Other Tools

```bash
# mcp-verify + npm audit + manual review
npm audit --audit-level=high
mcp-verify validate "node server.js" --security
# Then: Manual code review + penetration testing
```

### Tip 2: Track Trends

```bash
# Monitor security score over time
SCORE=$(mcp-verify validate ... --json-stdout | jq '.security.score')
echo "$(date),${SCORE}" >> security-history.csv
```

### Tip 3: Automate Reporting

```bash
# Generate weekly summary for security team
mcp-verify validate "node server.js" \
  --security \
  --format html \
  --output ./weekly-reports/$(date +%Y-%m-%d)/
```

---

## 📧 Contact & Support

**Questions or Security Concerns?**

📧 Email: hello.finksystems@gmail.com
💼 LinkedIn: [Ariel Fink](https://linkedin.com/in/ariel-fink)
🐙 GitHub: [@FinkTech](https://github.com/FinkTech)
🐛 Issues: [mcp-verify Issues](https://github.com/FinkTech/mcp-verify/issues)

