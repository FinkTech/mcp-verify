# Quick Start Guide

Get started with **mcp-verify** in 5 minutes! 🚀

---

## Installation

### Prerequisites

- Node.js >= 18.0.0
- npm >= 9.0.0

### Install Dependencies

```bash
cd mcp-verify
npm install
```

---

## Option 1: Using as CLI Tool (Classic)

### Build the CLI

```bash
npm run build
```

After building, run `npm link` to make the `mcp-verify` command available globally. The following examples assume you have done this.

### Validate an MCP Server

```bash
# Validate a local server
mcp-verify validate \
  --server "node path/to/your-server.js"

# Validate with output file
mcp-verify validate \
  --server "node path/to/your-server.js" \
  --output report.json
```

### Test with Mock Servers

```bash
# Test with valid server (should pass)
mcp-verify validate \
  --server "node tools/mocks/servers/simple-server.js"

# Test with vulnerable server (should fail)
mcp-verify validate \
  --server "node tools/mocks/servers/vulnerable-server.js"

# Test with broken server (protocol violations)
mcp-verify validate \
  --server "node tools/mocks/servers/broken-server.js"
```

---

## Option 2: Using as MCP Server (AI Agent Integration) ⭐ NEW!

This is the **game-changer** - AI agents can now call mcp-verify to validate MCP servers!

### Build the MCP Server

```bash
# Build all packages
npm run build

# Or build just the MCP server
cd apps/mcp-server
npm run build
```

### Configure in Claude Desktop

Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json` on Mac, `%APPDATA%\Claude\claude_desktop_config.json` on Windows):

```json
{
  "mcpServers": {
    "mcp-verify": {
      "command": "node",
      "args": [
        "./apps/mcp-server/dist/apps/mcp-server/src/index.js"
      ],
      "cwd": "/absolute/path/to/mcp-verify"
    }
  }
}
```

**Important**: Replace `/absolute/path/to/mcp-verify` with your actual project path.

### Available Tools

Once configured, Claude (or any AI agent) can call these tools:

#### 1. validateServer

Comprehensive validation (handshake, discovery, schema, security, quality, protocol compliance).

```typescript
// In Claude
validateServer({
  command: "node",
  args: ["./tools/mocks/servers/simple-server.js"]
})
```

**Response**:
```json
{
  "status": "valid",
  "serverName": "simple-test-server",
  "protocolVersion": "2024-11-05",
  "capabilities": {
    "tools": 2,
    "resources": 1,
    "prompts": 1
  },
  "security": {
    "score": 95,
    "findings": 0,
    "critical": 0,
    "high": 0
  },
  "quality": {
    "score": 98,
    "issues": 0
  }
}
```

#### 2. scanSecurity

Security-only scan (faster, focused on vulnerabilities).

```typescript
scanSecurity({
  command: "node",
  args: ["./tools/mocks/servers/vulnerable-server.js"]
})
```

**Response**:
```json
{
  "status": "success",
  "security": {
    "score": 30,
    "totalFindings": 8,
    "bySeverity": {
      "critical": 4,
      "high": 3,
      "medium": 1,
      "low": 0
    },
    "findings": [
      {
        "ruleCode": "SEC-001",
        "severity": "critical",
        "message": "SQL injection vulnerability detected",
        "component": "execute_sql",
        "remediation": "Use parameterized queries"
      }
      // ... more findings
    ]
  }
}
```

#### 3. analyzeQuality

Quality-only analysis (documentation, naming, clarity).

```typescript
analyzeQuality({
  command: "node",
  args: ["./tools/mocks/servers/simple-server.js"]
})
```

#### 4. generateReport

Generate detailed reports (JSON, SARIF, or text format).

```typescript
generateReport({
  command: "node",
  args: ["./tools/mocks/servers/simple-server.js"],
  format: "json",
  outputPath: "./reports/my-server-report.json"
})
```

---

## Option 3: Using Security Proxy (Runtime Protection) 🛡️ NEW!

Deploy a **Security Gateway v1.0** proxy that sits between AI agents and MCP servers, providing real-time threat detection with 3-layer progressive analysis.

### Why Use the Proxy?

- **Real-time protection**: Blocks malicious requests before they reach your MCP server
- **Zero code changes**: Works with any existing MCP server
- **Explainable blocking**: Every rejection includes rule ID, severity, CWE, OWASP, and remediation
- **Client-aware isolation**: Prevents DoS by isolating misbehaving clients

### Build and Start the Proxy

```bash
# Build all packages
npm run build

# Start proxy with default settings (Layer 1+2 only)
mcp-verify proxy \
  --target "node path/to/your-server.js" \
  --port 3000
```

### Configuration Options

```bash
# Production mode (fast layers only)
mcp-verify proxy \
  --target "node my-server.js" \
  --port 3000 \
  --rate-limit 100 \
  --audit-log ./logs/security-audit.jsonl

# High-security mode (enable LLM layer)
mcp-verify proxy \
  --target "node my-server.js" \
  --port 3000 \
  --enable-llm-layer \
  --audit-log ./logs/security-audit.jsonl
```

**Options**:
- `--target`: Command to start your MCP server (required)
- `--port`: Proxy listening port (default: 3000)
- `--rate-limit`: Max requests per minute per tool (default: 100)
- `--enable-llm-layer`: Enable Layer 3 (AI-powered deep analysis, adds 500-2000ms latency)
- `--no-llm-layer`: Explicitly disable Layer 3 (default in production)
- `--audit-log`: Path to audit log file in JSONL format

### Connect Claude Desktop Through Proxy

Update your Claude Desktop config to point to the proxy instead of the direct server:

```json
{
  "mcpServers": {
    "my-protected-server": {
      "command": "node",
      "args": [
        "/path/to/stdio-proxy-client.js",
        "http://localhost:3000"
      ]
    }
  }
}
```

**Note**: You'll need a stdio-to-HTTP proxy client. See `tools/demo/stdio-proxy-client.js` for example implementation.

### 3-Layer Defense System

Requests pass through 3 progressive layers with early exit optimization:

| Layer | Type | Latency | Detection Method | Cost (approx.) |
|-------|------|---------|------------------|----------------|
| **Layer 1: Fast Rules** | Static patterns | <10ms | Regex + hardcoded patterns (SQL, CMD injection) | $0 |
| **Layer 2: Suspicious** | Heuristic analysis | <50ms | Scoring + anomaly detection | $0 |
| **Layer 3: LLM** | Deep semantic | 500-2000ms | AI-powered context analysis (opt-in) | $5-$15 per 1K req* |

*LLM costs vary by provider and usage patterns. Layer 3 is disabled by default.

### Panic Stop System (Anti-DoS)

The proxy tracks rate limit errors per client and implements progressive backoff:

| Strike | Backoff | Trigger | Behavior |
|--------|---------|---------|----------|
| **Strike 1** | 30 seconds | First 429 error | Client blocked for 30s, auto-resume after |
| **Strike 2** | 60 seconds | Second 429 within session | Client blocked for 60s, warning logged |
| **Strike 3** | Permanent | Third 429 within session | **PANIC MODE** - permanently blocked until proxy restart |

**Client Isolation**: Each client is tracked separately by ID (from `x-client-id` header or IP address), preventing one malicious client from affecting others.

### Example: Blocking a SQL Injection Attack

```bash
# Start proxy
mcp-verify proxy --target "node my-server.js" --port 3000

# Client sends malicious request
# (happens automatically when Claude tries to exploit)
```

**Request from Claude**:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "query_users",
    "arguments": {
      "filter": "' OR 1=1--"
    }
  }
}
```

**Proxy Response (blocked at Layer 1 in 8ms)**:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32003,
    "message": "Security Gateway blocked request",
    "data": {
      "blocked": true,
      "layer": 1,
      "latency_ms": 8,
      "findings": [{
        "ruleCode": "SEC-003",
        "severity": "critical",
        "message": "SQL injection detected in parameter 'filter'",
        "cwe": "CWE-89",
        "owasp": "A03:2021 - Injection",
        "remediation": "Use parameterized queries instead of string concatenation",
        "matchedPattern": "OR 1=1",
        "affectedParameter": "filter"
      }]
    }
  }
}
```

The malicious request never reaches your MCP server.

### Viewing Audit Logs

```bash
# View recent security events
tail -f ./logs/security-audit.jsonl | jq .

# Count blocked requests by layer
jq -s 'group_by(.layer) | map({layer: .[0].layer, count: length})' ./logs/security-audit.jsonl

# Find all critical findings
jq 'select(.findings[].severity == "critical")' ./logs/security-audit.jsonl
```

---

## Common Workflows

### Workflow 1: Quick Security Check

```bash
# CLI
mcp-verify validate \
  --server "node my-server.js" \
  --output security-report.json

# View security findings
jq '.security.findings' security-report.json
```

Or with AI agent:

```typescript
scanSecurity({
  command: "node",
  args: ["my-server.js"]
})
```

### Workflow 2: CI/CD Integration

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
          node-version: '18'

      - name: Install mcp-verify
        run: npm install -g mcp-verify

      - name: Validate MCP Server
        run: |
          mcp-verify validate \
            --server "node src/my-server.js" \
            --output validation-report.json

      - name: Check Security Score
        run: |
          SCORE=$(jq '.security.score' validation-report.json)
          if [ "$SCORE" -lt 70 ]; then
            echo "Security score too low: $SCORE"
            exit 1
          fi
```

### Workflow 3: AI Agent Self-Diagnosis

An AI agent validating another MCP server:

```typescript
// Agent A calls mcp-verify to validate Agent B
const report = await validateServer({
  command: "node",
  args: ["agent-b-server.js"]
});

if (report.security.score < 70) {
  console.log("⚠️ Agent B has security issues!");
  console.log("Critical findings:", report.security.critical);

  // AI can make decisions based on security score
  if (report.security.critical > 0) {
    console.log("BLOCKING: Critical vulnerabilities found");
  }
}
```

### Workflow 4: Real-time Protection with Security Proxy

Deploy a security proxy in front of your production MCP server:

```bash
# Step 1: Start proxy with audit logging
mcp-verify proxy \
  --target "node production-server.js" \
  --port 3000 \
  --rate-limit 100 \
  --audit-log ./logs/security-audit.jsonl

# Step 2: Configure Claude Desktop to use proxy
# Edit claude_desktop_config.json:
{
  "mcpServers": {
    "production-server": {
      "command": "node",
      "args": ["stdio-proxy-client.js", "http://localhost:3000"]
    }
  }
}

# Step 3: Monitor security events in real-time
tail -f ./logs/security-audit.jsonl | jq 'select(.blocked == true)'

# Step 4: Analyze attack patterns
jq -s 'group_by(.findings[].ruleCode) | map({rule: .[0].findings[0].ruleCode, count: length}) | sort_by(.count) | reverse' ./logs/security-audit.jsonl
```

**Real-world scenario**: A client sends 3 SQL injection attempts:
1. **Request 1** (Layer 1, 8ms): Blocked immediately, client receives detailed error
2. **Request 2** (Cache hit, <1ms): Identical payload, served from cache
3. **Request 3** (Layer 1, 9ms): Different payload, blocked again

All attacks stopped before reaching your server. Zero false positives.

---

## Understanding Reports

### Technical Vulnerability Score

This score measures technical attack surface indicators (not a security certification):

- **95-100**: Excellent - Minimal attack surface detected
- **80-94**: Good - Minor issues to review
- **60-79**: Fair - Notable vulnerability patterns
- **40-59**: Poor - Significant vulnerabilities detected
- **0-39**: Critical - Major security concerns

### Finding Severities

- **Critical**: Immediate action required (SQL injection, command injection)
- **High**: Important vulnerabilities (SSRF, path traversal)
- **Medium**: Notable issues (data leakage, weak crypto)
- **Low**: Minor concerns (best practices)
- **Info**: Informational (recommendations)

### Quality Score

- **90-100**: Excellent documentation
- **70-89**: Good documentation
- **50-69**: Fair documentation
- **0-49**: Poor documentation

---

## Interpreting Results: False Positives vs. Real Vulnerabilities

⚠️ **CRITICAL**: Not all findings marked as "CRITICAL" are exploitable vulnerabilities. You must manually validate findings before reporting them as security issues.

### Example 1: False Positive (Server Validated Correctly)

```typescript
// mcp-verify finding
🔴 CRITICAL: Boundary overflow - age exceeds maximum
Severity: CRITICAL
Payload: { age: 121 }
Expected: maximum = 120

// Server response
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32602,
    "message": "Invalid params: age must be <= 120"
  }
}

// ✅ Verdict: FALSE POSITIVE
// The server correctly validated the input and rejected it.
// No vulnerability exists.
```

**How to recognize false positives**:
- Server returns an `error` object (not `result`)
- Error message explicitly mentions validation failure
- HTTP status code is 4xx (client error)

### Example 2: Real Vulnerability (Server Accepted Invalid Input)

```typescript
// mcp-verify finding
🔴 CRITICAL: Enum bypass - privilege escalation
Severity: CRITICAL
Payload: { role: 'admin' }
Expected: enum = ['user', 'guest']

// Server response
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "success": true,
    "userId": 12345,
    "role": "admin"  // ← Server accepted 'admin' (NOT in enum!)
  }
}

// ❌ Verdict: REAL VULNERABILITY
// The server accepted a value outside the enum.
// This could be a privilege escalation vulnerability.
```

**How to recognize real vulnerabilities**:
- Server returns a `result` object (not `error`)
- Payload value appears in the response unchanged
- HTTP status code is 2xx (success)

### Example 3: Ambiguous Case (Requires Manual Testing)

```typescript
// mcp-verify finding
🔴 CRITICAL: SSRF attempt - AWS metadata endpoint
Severity: CRITICAL
Payload: { url: 'http://169.254.169.254/latest/meta-data/' }

// Server response
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "success": true,
    "data": "Fetched successfully"
  }
}

// ⚠️ Verdict: NEEDS INVESTIGATION
// Server returned success, but did it actually fetch the AWS metadata?
// Check application logs or use network monitoring (Wireshark, Burp Suite).
```

**How to investigate ambiguous cases**:
1. Check server logs for outbound HTTP requests
2. Use `tcpdump` or Wireshark to monitor network traffic
3. Test with a controlled endpoint (e.g., `https://webhook.site`)
4. Review server code to understand URL handling logic

### Validation Checklist

Before reporting a finding as a vulnerability:

- [ ] **Read the server response carefully** - Does it show `error` or `result`?
- [ ] **Check if the payload was accepted** - Is the malicious value in the response?
- [ ] **Understand the context** - Could this be intentional (e.g., admin tools)?
- [ ] **Reproduce manually** - Can you exploit this with curl or Postman?
- [ ] **Review server logs** - Are there error messages indicating validation?
- [ ] **Consult with security team** - Get a second opinion on ambiguous cases

### When to Escalate

**Escalate to security team if**:
- ✅ Payload was accepted (server returned `result`, not `error`)
- ✅ Manual reproduction confirms exploitability
- ✅ Severity is CRITICAL or HIGH and impact is significant

**Do NOT escalate if**:
- ❌ Server returned a validation error
- ❌ Payload was rejected with 4xx status code
- ❌ You cannot reproduce the issue manually

---

## Troubleshooting

### Error: "Cannot find module"

```bash
# Rebuild everything
npm run build
```

### Error: "Process exited with code 1"

```bash
# Test server manually first
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | node your-server.js
```

### Error: "Connection timeout"

```bash
# Increase timeout in config
{
  "network": {
    "timeout": 60000
  }
}
```

### MCP Server not recognized by Claude

1. Check config file path is correct
2. Verify absolute path is used
3. Restart Claude Desktop
4. Check Claude logs: `Help > View Logs`

### Proxy: Client in "Panic Mode" (Strike 3)

```bash
# Check client strike count in logs
jq 'select(.clientId == "your-client-id") | .strikes' ./logs/security-audit.jsonl

# Restart proxy to reset all clients
# (or implement manual client reset in future version)
```

**Prevention**: Fix the underlying issue causing rate limit errors (429) before the client hits 3 strikes.

### Proxy: Blocking Legitimate Requests

```bash
# Check why request was blocked
tail -f ./logs/security-audit.jsonl | jq 'select(.blocked == true)'

# If false positive, disable specific rule in config
{
  "security": {
    "rules": {
      "SEC-001": { "enabled": false }
    }
  }
}
```

**Tip**: Layer 1 rules have zero false positives by design. If you see a false positive, it's likely from Layer 2 or Layer 3.

### Proxy: High Latency

```bash
# Check if LLM layer is enabled (adds 500-2000ms)
# Disable LLM layer for production:
mcp-verify proxy \
  --target "node my-server.js" \
  --no-llm-layer

# Check cache hit ratio in logs
jq -s 'group_by(.cacheHit) | map({cached: .[0].cacheHit, count: length})' ./logs/security-audit.jsonl
```

**Expected latency**:
- Layer 1+2 only: 10-50ms
- Cache hits: <1ms
- LLM layer enabled: 500-2000ms (only use in high-security environments)

### Proxy: Audit Log Not Created

```bash
# Create logs directory if it doesn't exist
mkdir -p ./logs

# Verify write permissions
ls -la ./logs/

# Check proxy output for errors
mcp-verify proxy \
  --target "node my-server.js" \
  --audit-log ./logs/security-audit.jsonl 2>&1 | grep -i error
```

---

## Advanced Usage

### Custom Configuration

Create `mcp-verify.config.json`:

```json
{
  "security": {
    "rules": {
      "SEC-001": { "enabled": true, "severity": "critical" },
      "SEC-002": { "enabled": true, "severity": "critical" },
      "SEC-003": { "enabled": true, "severity": "high" }
    }
  }
}
```

Use with CLI:

```bash
mcp-verify validate \
  --server "node my-server.js" \
  --config mcp-verify.config.json
```

### SARIF Export (for GitHub Code Scanning)

```bash
# Generate SARIF report
generateReport({
  command: "node",
  args: ["my-server.js"],
  format: "sarif",
  outputPath: "./security-findings.sarif"
})

# Upload to GitHub
# (will appear in Security > Code Scanning tab)
```

---

## Next Steps

1. ✅ **Test with mock servers** - Understand what good/bad looks like
2. 🔍 **Validate your own servers** - Find vulnerabilities before production
3. 🤖 **Integrate with AI agents** - Let agents self-diagnose servers
4. 🔄 **Add to CI/CD** - Automate security checks
5. 📊 **Monitor scores over time** - Track improvement

---

## Resources

- **Documentation**: See [CONTRIBUTING.md](./CONTRIBUTING.md) for development
- **Testing**: See [TESTING.md](./TESTING.md) for test guidelines
- **Architecture**: See [ARCHITECTURE.md](./ARCHITECTURE.md) for system design
- **Mock Servers**: See [tools/mocks/servers/README.md](./tools/mocks/servers/README.md)

---

## Support

- **Issues**: Open a GitHub issue
- **Questions**: Start a GitHub Discussion
- **Security**: Email official.mcpverify@gmail.com

---

**Welcome to mcp-verify v1.0.0** - The first tool that AI agents can call to validate MCP servers! 🎉
