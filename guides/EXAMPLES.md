# 📋 mcp-verify Examples - Copy & Paste Commands

**Last Updated**: 2026-02-03
**Target Audience**: All users (especially Persona 1 & 2)
**Time to Read**: 5 minutes

---

## 🎯 Quick Navigation

- [Basic Validation](#basic-validation)
- [Security Scanning](#security-scanning)
- [Quality Analysis](#quality-analysis)
- [LLM Semantic Analysis](#llm-semantic-analysis)
- [CI/CD Integration](#cicd-integration)
- [Report Formats](#report-formats)
- [Troubleshooting](#troubleshooting)
- [Advanced Usage](#advanced-usage)

---

## 🚀 Basic Validation

### Validate Local Server (STDIO)

```bash
# Node.js server
mcp-verify validate "node server.js"

# Python server
mcp-verify validate "python server.py"

# Deno server
mcp-verify validate "deno run --allow-net server.ts"
```

### Validate HTTP Server

```bash
# Local server
mcp-verify validate http://localhost:3000

# Remote server
mcp-verify validate https://api.example.com/mcp
```

### Validate with Custom Transport

```bash
# Explicitly specify STDIO
mcp-verify validate "node server.js" --transport stdio

# SSE (Server-Sent Events)
mcp-verify validate http://localhost:3000 --transport sse

# HTTP
mcp-verify validate http://localhost:3000 --transport http
```

---

## 🔒 Security Scanning

### Full Security Audit

```bash
# Basic security scan
mcp-verify validate "node server.js"

# Security scan with detailed output
mcp-verify validate \"node server.js\" --verbose
```

### Security with Baseline Comparison

```bash
# Create baseline
mcp-verify validate "node server.js" \
   \
  --save-baseline ./baselines/v1.0.0.json

# Compare against baseline
mcp-verify validate "node server.js" \
   \
  --compare-baseline ./baselines/v1.0.0.json

# Fail build on degradation
mcp-verify validate "node server.js" \
   \
  --compare-baseline ./baselines/v1.0.0.json \
  --fail-on-degradation
```

📚 **Detailed Guide**: [Regression Detection Guide](../REGRESSION-DETECTION.md)

### Generate SARIF for GitHub Security

```bash
mcp-verify validate "node server.js" \
   \
  --format sarif \
  --output ./reports
```

---

## 📊 Quality Analysis

### Basic Quality Check

```bash
# Quality analysis only
mcp-verify validate "node server.js"

# Quality with detailed report
mcp-verify validate \"node server.js\" --verbose
```

### Quality with Score Threshold

```bash
# Fail if quality score < 80
mcp-verify validate \"node server.js\" --min-score 80
```

---

## 🧠 LLM Semantic Analysis

### Using Ollama (Free, Local)

```bash
# Basic semantic analysis
mcp-verify validate "node server.js" --llm ollama:llama3.2

# With specific model
mcp-verify validate "node server.js" --llm ollama:codellama
mcp-verify validate "node server.js" --llm ollama:mistral
```

### Using Anthropic Claude

```bash
# Set API key first
export ANTHROPIC_API_KEY="sk-ant-api03-..."

# Haiku (fastest, cheapest)
mcp-verify validate "node server.js" --llm anthropic:claude-haiku-4-5-20251001

# Sonnet (balanced)
mcp-verify validate "node server.js" --llm anthropic:claude-sonnet-4-20250514

# Opus (most powerful)
mcp-verify validate "node server.js" --llm anthropic:claude-opus-4-5-20251101
```

### Using OpenAI

```bash
# Set API key first
export OPENAI_API_KEY="sk-..."

# GPT-4o-mini (recommended)
mcp-verify validate "node server.js" --llm openai:gpt-4o-mini

# GPT-4o
mcp-verify validate "node server.js" --llm openai:gpt-4o
```

### Combined Security + LLM Analysis

```bash
# Full analysis with Ollama
mcp-verify validate "node server.js" \
   \
  --llm ollama:llama3.2 \
  --output ./reports

# Full analysis with Anthropic
mcp-verify validate "node server.js" \
   \
  --llm anthropic:claude-haiku-4-5-20251001 \
  --format html
```

---

## 🔄 CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/mcp-validation.yml
name: MCP Server Validation

on: [push, pull_request]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: "18"

      - name: Install dependencies
        run: npm install

      - name: Clone mcp-verify
        run: |
          git clone https://github.com/FinkTech/mcp-verify.git
          cd mcp-verify
          npm install
          npm run build

      - name: Validate Server
        run: |
          cd mcp-verify
          node dist/mcp-verify.js validate \
            "node ../your-server.js" \
             \
            --format sarif \
            --output ../reports

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: reports/sarif/mcp-report-*.sarif
```

### GitLab CI

```yaml
# .gitlab-ci.yml
mcp_validation:
  stage: test
  image: node:18
  script:
    - git clone https://github.com/FinkTech/mcp-verify.git
    - cd mcp-verify
    - npm install
    - npm run build
    - node dist/mcp-verify.js validate \
      "node ../server.js" \
      \
      --format json
  artifacts:
    reports:
      coverage_report:
        coverage_format: cobertura
        path: reports/json/mcp-report-*.json
```

### CircleCI

```yaml
# .circleci/config.yml
version: 2.1
jobs:
  validate:
    docker:
      - image: cimg/node:18.0
    steps:
      - checkout
      - run:
          name: Install mcp-verify
          command: |
            git clone https://github.com/FinkTech/mcp-verify.git
            cd mcp-verify
            npm install
            npm run build
      - run:
          name: Validate Server
          command: |
            cd mcp-verify
            node dist/mcp-verify.js validate \
              "node ../server.js" \

```

### With LLM in CI/CD

```yaml
# GitHub Actions with Anthropic
- name: Validate with LLM
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
  run: |
    mcp-verify validate \
      "node server.js" \
       \
      --llm anthropic:claude-haiku-4-5-20251001 \
      --fail-on-critical
```

---

## 📄 Report Formats

### JSON Output

```bash
# Generate JSON report
mcp-verify validate "node server.js" \
  --format json \
  --output ./reports

# Output to stdout (for piping)
mcp-verify validate "node server.js" \
  --format json \
  --json-stdout
```

### HTML Report

```bash
# Generate HTML report (human-friendly)
mcp-verify validate "node server.js" \
  --format html \
  --output ./reports

# Open in browser after generation
mcp-verify validate "node server.js" \
  --format html \
  --output ./reports && \
  open ./reports/html/mcp-report-*.html
```

### SARIF for GitHub Security

```bash
# Generate SARIF (GitHub Code Scanning)
mcp-verify validate "node server.js" \
  --format sarif \
  --output ./reports
```

### Markdown Summary

```bash
# Generate Markdown report
mcp-verify validate "node server.js" \
  --format md \
  --output ./reports
```

### Multiple Formats

```bash
# Generate all formats
mcp-verify validate "node server.js" \
  --format json \
  --format html \
  --format sarif \
  --format md \
  --output ./reports
```

---

## 🔧 Troubleshooting

### Test Connection

```bash
# Diagnose connection issues
mcp-verify doctor "node server.js"

# Verbose diagnostics
mcp-verify doctor "node server.js" --verbose
```

### Test Server with Mock

```bash
# Start mock MCP server
mcp-verify mock --port 3000

# In another terminal, validate it
mcp-verify validate http://localhost:3000
```

### Interactive Playground

```bash
# Test tools interactively
mcp-verify play "node server.js"

# With specific transport
mcp-verify play "node server.js" --transport stdio
```

### Debug Mode

```bash
# Enable verbose logging
mcp-verify validate "node server.js" --verbose

# Quiet mode (only errors)
mcp-verify validate "node server.js" --quiet
```

---

## 🎛️ Advanced Usage

### Custom Output Directory

```bash
# Save reports to custom location
mcp-verify validate "node server.js" \
  --output /path/to/custom/reports
```

### Fuzzing (Active Security Testing)

Test your server against real-world attack payloads (Jailbreaks, Prompt Injections, SQLi).

```bash
# Enable full smart fuzzing on all tools during validation
mcp-verify validate "node server.js" --fuzz

# Deep fuzzing on a specific tool and parameter
mcp-verify fuzz "node server.js" --tool ask_ai --param user_input

# Use specific generators (e.g., only Prompt Injection)
mcp-verify fuzz "node server.js" --generators prompt
```

### Sandbox Mode

```bash
# Run in Deno sandbox (requires Deno installed)
mcp-verify validate "node server.js" --sandbox

# Note: Only works with Node.js/Deno servers
```

### Environment Variables

```bash
# Pass environment variables to server
mcp-verify validate "node server.js" \
  --env API_KEY=secret123 \
  --env DEBUG=true

# Multiple environment variables
mcp-verify validate "node server.js" \
  -e API_KEY=secret \
  -e DB_HOST=localhost \
  -e PORT=3000
```

### Language Selection

```bash
# Spanish output
mcp-verify validate "node server.js" --lang es

# English output (default)
mcp-verify validate "node server.js" --lang en
```

### Stress Testing

```bash
# Basic stress test
mcp-verify stress "node server.js"

# Custom users and duration
mcp-verify stress "node server.js" \
  --users 10 \
  --duration 30
```

### Dashboard Mode

```bash
# Launch web dashboard
mcp-verify dashboard "node server.js" --port 8080

# Open browser to: http://localhost:8080
```

## 🛡️ Security Gateway (Runtime Protection)

Deploy a real-time security proxy between AI agents and your MCP server. Protection Layer 1 (Fast Patterns) and Layer 2 (Suspicious Heuristics) are active.

### Basic Proxy Setup

```bash
# Start proxy with default guardrails (Layer 1+2 ACTIVE)
mcp-verify proxy --target "node my-server.js" --port 3000
```

### Testing the Proxy

In another terminal, you can test the protection by sending a manual JSON-RPC request:

```bash
curl -X POST http://localhost:3000/message \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_user","arguments":{"userId":"123"}}}'
```

### With Audit Logging & Monitoring

Enable the audit log to track every request, response, and block event.

```bash
# Start with logging enabled
mcp-verify proxy --target "node server.js" --port 3000 --log-file ./logs/security-audit.jsonl

# View blocked requests in real-time (using jq)
tail -f ./logs/security-audit.jsonl | jq 'select(.type == "block")'
```

### Production Best Practices

For production environments, ensure your logs are protected:

```bash
# Secure log directory
mkdir -p ./logs
chmod 700 ./logs

# Run proxy with restricted logging
mcp-verify proxy --target "node prod-server.js" --port 3000 --log-file ./logs/proxy.jsonl
```

### 🚀 Future Capabilities (Coming Soon)

The following advanced security features and CLI-based fine-tuning are planned for future updates:

```bash
# AI-powered semantic protection (Layer 3) - Planned
# mcp-verify proxy --target "node server.js" --llm-layer

# Fine-tune rate limiting via CLI - Planned (Currently defaults to 60 RPM)
# mcp-verify proxy --target "node server.js" --rate-limit 100

# Enable PII masking in proxy logs - Planned
# mcp-verify proxy --target "node server.js" --mask-pii
```

---

### Connecting Claude Desktop Through Proxy

Update your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "my-protected-server": {
      "command": "node",
      "args": ["/path/to/stdio-proxy-client.js", "http://localhost:3000"]
    }
  }
}
```

**Note**: You need a stdio-to-HTTP proxy client. See `tools/demo/stdio-proxy-client.js` for example.

### Monitoring Security Events

```bash
# Count blocked requests
jq -s 'map(select(.blocked == true)) | length' ./logs/security-audit.jsonl

# Group by rule ID
jq -s 'group_by(.findings[0].ruleCode) | map({rule: .[0].findings[0].ruleCode, count: length})' ./logs/security-audit.jsonl

# Find clients approaching Strike 3 (Panic Mode)
jq -s 'group_by(.clientId) | map({client: .[0].clientId, maxStrikes: ([.[].strikes] | max)}) | .[] | select(.maxStrikes >= 2)' ./logs/security-audit.jsonl

# Calculate cache hit ratio
jq -s '[.[] | select(.cacheHit != null)] | group_by(.cacheHit) | map({cached: .[0].cacheHit, count: length})' ./logs/security-audit.jsonl
```

### Testing Attack Detection

```bash
# Test SQL injection blocking (Layer 1)
curl -X POST http://localhost:3000 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "id":1,
    "method":"tools/call",
    "params":{
      "name":"query_users",
      "arguments":{"filter":"'"'"' OR 1=1--"}
    }
  }'

# Expected response:
# {
#   "error": {
#     "code": -32003,
#     "message": "Security Gateway blocked request",
#     "data": {
#       "blocked": true,
#       "layer": 1,
#       "findings": [{
#         "ruleCode": "SEC-003",
#         "severity": "critical",
#         "message": "SQL injection detected"
#       }]
#     }
#   }
# }
```

### With Custom Client ID

```bash
# Use custom client identifier (useful for tracking different apps)
curl -X POST http://localhost:3000 \
  -H "Content-Type: application/json" \
  -H "x-client-id: my-app-v1.0" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"test","arguments":{}}}'
```

### Proxy in Docker

```dockerfile
# Dockerfile
FROM node:18-alpine

WORKDIR /app
COPY . .

RUN npm install && npm run build

EXPOSE 3000

CMD ["node", "dist/mcp-verify.js", "proxy", \
     "--target", "node production-server.js", \
     "--port", "3000", \
     "--log-file", "/var/log/security-audit.jsonl"]
```

```bash
# Build and run
docker build -t mcp-verify-proxy .
docker run -p 3000:3000 -v $(pwd)/logs:/var/log mcp-verify-proxy
```

### CI/CD Integration with Proxy

```yaml
# .github/workflows/proxy-test.yml
name: Proxy Integration Test

on: [push]

jobs:
  test:
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
          cd mcp-verify && npm install && npm run build

      - name: Start Proxy
        run: |
          cd mcp-verify
          node dist/mcp-verify.js proxy \
            --target "node ../server.js" \
            --port 3000 \
            --log-file ../logs/audit.jsonl &
          sleep 5

      - name: Test Attack Blocking
        run: |
          # Test SQL injection is blocked
          response=$(curl -X POST http://localhost:3000 \
            -H "Content-Type: application/json" \
            -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query","arguments":{"q":"'"'"' OR 1=1--"}}}')

          if echo "$response" | jq -e '.error.code == -32003'; then
            echo "✅ SQL injection correctly blocked"
          else
            echo "❌ Attack not blocked!" && exit 1
          fi

      - name: Verify No False Positives
        run: |
          # Test legitimate request passes
          response=$(curl -X POST http://localhost:3000 \
            -H "Content-Type: application/json" \
            -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_user","arguments":{"userId":"123"}}}')

          if echo "$response" | jq -e '.result'; then
            echo "✅ Legitimate request passed"
          else
            echo "❌ False positive!" && exit 1
          fi
```

---

## 📦 Complete Examples by Use Case

### Example 1: First-Time Validation

```bash
# Quick validation of your MCP server
mcp-verify validate "node your-server.js"
```

**Expected Output:**

```
✓ Testing handshake
✓ Discovering capabilities
✓ Validating schema
✓ Running security audit
✓ Generating report

Validation Report:
──────────────────────────────────────────
Server: my-mcp-server
Status: ✓ Valid
Security Score: 85/100 (GOOD)
Quality Score: 92/100
──────────────────────────────────────────
Reports saved to: ./reportes/
```

---

### Example 2: Pre-Production Security Check

```bash
# Full security audit with LLM analysis
mcp-verify validate "node server.js" \
   \
  --llm ollama:llama3.2 \
  --format html \
  --format sarif \
  --output ./production-reports \
  --fail-on-critical
```

**Use Case**: Before deploying to production, ensure no critical vulnerabilities.

---

### Example 3: CI/CD Pipeline

```bash
# Automated validation in CI
mcp-verify validate "node server.js" \
   \
  --llm anthropic:claude-haiku-4-5-20251001 \
  --format sarif \
  --compare-baseline ./baseline.json \
  --fail-on-degradation \
  --quiet
```

**Use Case**: Block PRs with security regressions.

---

### Example 4: Third-Party Server Audit

```bash
# Audit external MCP server before installing
mcp-verify validate "npx @external/mcp-server" \
   \
  --llm ollama:llama3.2 \
  --format html \
  --output ./audit-reports
```

**Use Case**: Security engineer evaluating third-party MCP server.

---

### Example 5: Local Development

```bash
# Quick check during development
mcp-verify validate "node server.js" --verbose
```

**Use Case**: Developer testing changes locally.

---

## 🎨 Output Customization

### Colored vs Plain Output

```bash
# Colored output (default)
mcp-verify validate "node server.js"

# No colors (for CI/CD logs)
mcp-verify validate "node server.js" --no-color
```

### JSON to stdout (for piping)

```bash
# Pipe JSON to jq
mcp-verify validate "node server.js" --json-stdout | jq '.security.score'

# Save specific field to file
mcp-verify validate "node server.js" --json-stdout | \
  jq '.security' > security-report.json
```

---

## 📚 Related Documentation

- [LLM Setup Guide](./LLM_SETUP.md) - Configure Anthropic/Ollama/OpenAI
- [CI/CD Guide](./CI_CD.md) - Detailed CI/CD integration
- [Security Scoring](../SECURITY_SCORING.md) - How scoring works
- [Troubleshooting](../TROUBLESHOOTING.md) - Common errors + solutions

---

## 💡 Tips & Best Practices

### Tip 1: Start Simple

```bash
# Begin with basic validation
mcp-verify validate "node server.js"

# Then add features incrementally
mcp-verify validate "node server.js"
mcp-verify validate \"node server.js\" --llm ollama:llama3.2
```

### Tip 2: Use Baselines in CI/CD

```bash
# Save baseline on main branch
if [ "$BRANCH" == "main" ]; then
  mcp-verify validate "node server.js" --save-baseline ./baseline.json
fi

# Compare on PRs
if [ "$BRANCH" != "main" ]; then
  mcp-verify validate "node server.js" --compare-baseline ./baseline.json --fail-on-degradation
fi
```

### Tip 3: Combine with Other Tools

```bash
# TypeScript + ESLint + mcp-verify
npm run type-check && \
npm run lint && \
mcp-verify validate "node server.js"
```

### Tip 4: Cache LLM Results

LLM analysis results are cached for 24 hours by default. Run multiple validations without extra API costs:

```bash
# First run: Calls LLM API
mcp-verify validate "node server.js" --llm ollama:llama3.2

# Second run (within 24h): Uses cache
mcp-verify validate "node server.js" --llm ollama:llama3.2
```

---

## ❓ FAQ

**Q: What's the difference between standard security and `--llm`?**
A: mcp-verify runs 60 comprehensive security rules. `--llm` adds deep semantic analysis. Use both for maximum coverage.

---

## 🔒 Sandbox Execution (Safety First)

Always run unknown or third-party servers in a sandbox to prevent them from accessing your local files or environment variables.

```bash
# Isolated execution in Deno sandbox (Node.js/Deno only)
mcp-verify validate \"node server.js\" --sandbox

# Static analysis only (no execution)
mcp-verify validate "python server.py" --no-sandbox
```

**Q: How do I know which format to use?**
A:

- JSON: Programmatic processing
- HTML: Human review
- SARIF: GitHub Security tab
- Markdown: Documentation

**Q: Can I validate multiple servers at once?**
A: Not yet (planned for v1.2). Use shell scripts for now:

```bash
for server in server1.js server2.js; do
  mcp-verify validate "node $server"
done
```
