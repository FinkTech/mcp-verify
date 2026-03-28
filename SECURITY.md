# Security Documentation

## Table of Contents

- [Overview](#overview)
- [Security Model](#security-model)
- [API Key Management](#api-key-management)
- [What We Secure](#what-we-secure)
  - [Static Analysis (60 Security Rules)](#static-analysis-60-security-rules)
  - [Protocol Compliance](#protocol-compliance-json-rpc-20)
  - [Runtime Security (Proxy Guardrails)](#runtime-security-proxy-guardrails)
  - [Smart Fuzzer v1.0 Security](#smart-fuzzer-v10-security)
  - [Security Profiles](#security-profiles)
  - [Interactive Shell Security](#interactive-shell-security)
  - [Secret Redaction System](#secret-redaction-system)
  - [Schema Validation](#schema-validation-high-confidence)
  - [Quality Analysis](#quality-analysis-medium-confidence)
- [What We Don't Secure](#what-we-dont-secure)
- [Known Limitations](#known-limitations)
- [Security Boundaries](#security-boundaries)
- [Test Servers](#test-servers)
- [Reporting Vulnerabilities](#reporting-vulnerabilities)
- [Security Best Practices](#security-best-practices)

---

## Overview

**mcp-verify** is a security validation tool for MCP (Model Context Protocol) servers. This document clarifies what security guarantees we provide, what we don't control, and how to use the tool safely.

⚠️ **Important Disclaimer**: mcp-verify is an **independent open-source tool** developed by Fink. It is **NOT** affiliated with, endorsed by, or connected to Anthropic, the Model Context Protocol organization, or any other entity.

---

## Security Model

### What mcp-verify Does

mcp-verify performs **static analysis** of MCP servers:

1. **Schema Validation**: Checks JSON-RPC protocol compliance
2. **Pattern Detection**: Scans tool descriptions and schemas for known vulnerability patterns
3. **Quality Analysis**: Evaluates documentation clarity and consistency
4. **Protocol Compliance**: Validates adherence to MCP specification

### What mcp-verify Does NOT Do

mcp-verify **cannot**:

- ❌ Guarantee runtime behavior of tested servers
- ❌ Detect all possible vulnerabilities (security is probabilistic, not absolute)
- ❌ Prevent exploitation of servers it validates
- ❌ Control or manage the security of upstream MCP servers
- ❌ Replace human security audits
- ❌ Guarantee that a "passing" server is production-ready

**Critical Understanding**: A security score of 100/100 means "no known patterns detected" - it does NOT mean "perfectly secure."

---

## API Key Management

### LLM Semantic Analysis (Optional Feature)

mcp-verify includes **optional** LLM-powered semantic analysis using Claude API. This feature:

- **Costs**: ~$0.001 per validation (less than 1 cent)
- **Enables**: Advanced description-parameter mismatch detection
- **Requires**: User-managed API key

### How API Keys Are Stored

**Important**: mcp-verify **does NOT store or manage API keys**. The user is responsible for security.

#### CLI Usage (Standalone)

When using mcp-verify as a CLI tool:

```bash
# User sets environment variable
export ANTHROPIC_API_KEY=sk-ant-api03-...

# mcp-verify reads it at runtime
mcp-verify validate node server.js --semantic-check
```

**Security Responsibility**: User must secure their environment variables using OS-level protections.

#### MCP Server Mode (Claude Desktop Integration)

When using mcp-verify as an MCP server within Claude Desktop:

```json
// claude_desktop_config.json
{
  "mcpServers": {
    "mcp-verify": {
      "command": "node",
      "args": ["./apps/mcp-server/dist/apps/mcp-server/src/index.js"],
      "cwd": "/path/to/mcp-verify",
      "env": {
        "ANTHROPIC_API_KEY": "sk-ant-api03-..."
      }
    }
  }
}
```

**Security Responsibility**: Claude Desktop manages the keychain and process isolation. mcp-verify inherits whatever security model Claude Desktop provides.

### API Key Security Best Practices

1. **Never commit API keys** to version control
2. **Use environment variables** for local development
3. **Use secrets management** (AWS Secrets Manager, HashiCorp Vault) in production
4. **Rotate keys regularly** if exposed
5. **Monitor usage** via Anthropic Console

### What We Do to Protect API Keys

- ✅ Never log API keys (redacted in all logs)
- ✅ Validate key format before API calls
- ✅ Graceful degradation when key is missing
- ✅ Clear user messaging about key requirements
- ✅ No persistent storage (environment variables only)

### What We DON'T Control

- ❌ How user stores environment variables
- ❌ Claude Desktop's keychain security
- ❌ Network interception (use HTTPS)
- ❌ API key rotation policies
- ❌ Access control to user's filesystem

---

## What We Secure

### Static Analysis (60 Security Rules)

mcp-verify detects vulnerability patterns across 60 security rules organized in 6 threat category blocks (OWASP Top 10, MCP-specific, OWASP LLM Top 10, Multi-Agent Attacks, Enterprise Compliance, AI Weaponization). Below are the core OWASP and MCP-specific rules (first 21 of 60 total):

| Code         | Rule                       | Description                                  |
|--------------|----------------------------|----------------------------------------------|
| **SEC-001**  | Authentication Bypass      | Weak auth patterns, credential exposure      |
| **SEC-002**  | Command Injection          | `exec()`, `eval()`, shell commands           |
| **SEC-003**  | SQL Injection              | Dynamic SQL queries, unparameterized queries |
| **SEC-004**  | SSRF                       | Server-side request forgery patterns         |
| **SEC-005**  | XXE Injection              | XML external entity vulnerabilities          |
| **SEC-006**  | Insecure Deserialization   | Unsafe object deserialization                |
| **SEC-007**  | Path Traversal             | Directory traversal, file access             |
| **SEC-008**  | Data Leakage               | API keys, secrets in descriptions            |
| **SEC-009**  | Sensitive Data Exposure    | PII, credentials in parameters               |
| **SEC-010**  | Rate Limiting              | Missing rate limit protection                |
| **SEC-011**  | ReDoS                      | Regular expression denial of service         |
| **SEC-012**  | Weak Cryptography          | MD5, SHA1, weak algorithms                   |
| **SEC-013**  | Prompt Injection           | Indirect injection vectors, missing limits   |

### Protocol Compliance (JSON-RPC 2.0)

- Schema validation, required fields, type checking

### Runtime Security (Security Gateway v1.0)

mcp-verify includes a **Security Gateway v1.0** (`mcp-verify proxy`) - a production-ready, multi-layered defense system that provides real-time threat detection and client-aware panic stop mechanism to prevent DoS attacks.

#### Architecture

```
┌──────────────┐        ┌─────────────────────────────────────────┐        ┌─────────────┐
│ Claude       │   →    │ mcp-verify Security Gateway v1.0        │   →    │ MCP Server  │
│ Desktop      │        │ ┌─────────────────────────────────────┐ │        │ (Your Code) │
│              │        │ │ 3-Layer Defense System              │ │        │             │
│              │        │ │ • Layer 1: Fast Rules (<10ms)       │ │        │             │
│              │        │ │ • Layer 2: Suspicious (<50ms)       │ │        │             │
│              │        │ │ • Layer 3: LLM (opt-in, 500-2000ms) │ │        │             │
│              │        │ └─────────────────────────────────────┘ │        │             │
│              │        │ ┌─────────────────────────────────────┐ │        │             │
│              │        │ │ Client-Aware Panic Stop             │ │        │             │
│              │        │ │ • Map<clientId, state>              │ │        │             │
│              │        │ │ • Progressive backoff (30s/60s/∞)   │ │        │             │
│              │        │ └─────────────────────────────────────┘ │        │             │
│              │        │ ┌─────────────────────────────────────┐ │        │             │
│              │        │ │ 5 Classic Guardrails                │ │        │             │
│              │        │ │ (run after Gateway passes request)  │ │        │             │
│              │        │ └─────────────────────────────────────┘ │        │             │
└──────────────┘        └─────────────────────────────────────────┘        └─────────────┘
                                          ↓ Security Events
                                  ┌─────────────────┐
                                  │ Audit Logs      │
                                  │ (JSONL stream)  │
                                  └─────────────────┘
```

The Security Gateway operates **transparently** with defense-in-depth:
1. **3-Layer Defense System** - Progressive analysis with early exit on detection
2. **Client-Aware Panic Stop** - Isolated strikes per client to prevent global DoS
3. **5 Classic Guardrails** - Additional protection layer (HTTPS, Input Sanitization, PII Redaction, Rate Limiting, Command Blocking)

**Key Innovation**: The 3-layer defense system runs BEFORE the classic guardrails, providing an additional security barrier that blocks threats at the protocol level before they reach traditional defenses.

---

#### Security Gateway: 3-Layer Defense System

The Security Gateway implements **progressive threat detection** with early exit optimization - each layer runs only if previous layers pass the request.

##### Layer 1: Fast Rules (<10ms)

**Purpose**: Block high-confidence threats with zero false positives using pattern-based detection.

**Detection Methods**:
- **SQL Injection (SEC-001)**: Detects `OR 1=1`, `UNION SELECT`, `'; DROP TABLE`, SQL comments
- **Command Injection (SEC-002)**: Detects shell metacharacters (`;`, `|`, `&`, `` ` ``), command substitution (`$()`), dangerous commands (`rm -rf`, `del /f`)
- **Path Traversal (SEC-003)**: Detects `../`, `..\\`, absolute paths (`/etc/`, `C:\`)

**Characteristics**:
- **Runtime Analysis**: Checks actual parameter values (not just schemas)
- **Universal Application**: Runs on ALL tools (not filtered by name)
- **Guaranteed Latency**: <10ms via pure regex (no I/O)
- **Zero False Positives**: Only blocks confirmed attack patterns

**Example**:
```typescript
// Client sends SQL injection
{ method: 'tools/call', params: { name: 'query_users', arguments: { filter: "' OR 1=1--" } } }

// Gateway blocks at Layer 1 (8ms latency)
{
  "error": {
    "code": -32003,
    "message": "Security Gateway blocked request",
    "data": {
      "blocked": true,
      "layer": 1,
      "latency_ms": 8,
      "findings": [{
        "ruleId": "SEC-001",
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

##### Layer 2: Suspicious Rules (<50ms)

**Purpose**: Detect complex attack patterns using heuristic scoring and stateful analysis.

**Detection Methods**:
- **Dangerous Tool Chaining (SEC-020)**: Detects suspicious sequences like `execute→read_file` (execute then exfiltrate)
- **Excessive Permissions (SEC-023)**: Flags `skipConfirmation: true`, `bypassValidation: true`, missing `confirm: true`
- **Anomaly Detection**: Statistical analysis of parameter distributions

**Characteristics**:
- **Stateful Analysis**: Tracks tool call history per session
- **Heuristic Scoring**: Accumulates evidence across multiple parameters
- **Configurable Thresholds**: Tune sensitivity per deployment

**Example**:
```typescript
// Client requests privileged action without confirmation
{ method: 'tools/call', params: { name: 'delete_all', arguments: { skipConfirmation: true } } }

// Gateway blocks at Layer 2 (35ms latency)
{
  "error": {
    "code": -32003,
    "message": "Security Gateway blocked request",
    "data": {
      "blocked": true,
      "layer": 2,
      "latency_ms": 35,
      "findings": [{
        "ruleId": "SEC-023",
        "severity": "high",
        "message": "Excessive agency detected: negative confirmation flag",
        "remediation": "Require explicit user confirmation for destructive actions"
      }]
    }
  }
}
```

##### Layer 3: LLM Rules (500-2000ms, Opt-In)

**Purpose**: Detect novel attacks and semantic threats using AI-powered analysis.

**Detection Methods**:
- **Semantic Prompt Injection**: Context-aware analysis of tool call intent
- **Polymorphic Attacks**: Novel patterns not covered by static rules
- **Social Engineering**: Context-based manipulation detection

**When to Enable**:
- ✅ Research environments (studying novel attacks)
- ✅ High-security deployments (military, finance, healthcare)
- ✅ Honeypot/deception systems
- ❌ Production (latency penalty too high - adds 500-2000ms)
- ❌ High-throughput systems (LLM API costs $5-$15 per 1000 requests)

**Configuration**:
```bash
# Enable Layer 3 (disabled by default)
mcp-verify proxy "node server.js" --enable-llm-layer

# Production mode (Layers 1+2 only, <50ms latency)
mcp-verify proxy "node server.js" --no-llm-layer
```

**Characteristics**:
- **Context-Aware**: Understands semantic meaning beyond patterns
- **Adaptive**: Learns from novel attack vectors
- **Explainable**: Provides reasoning for each detection

---

#### Client-Aware Panic Stop System

The Panic Stop system prevents **Denial of Service (DoS) attacks** caused by malicious clients triggering global rate limits.

##### Problem: Global DoS Vulnerability

**Without client isolation**:
```
Client A (malicious) → Triggers 3x HTTP 429 errors → GLOBAL panic mode activated
Client B (legitimate) → BLOCKED as collateral damage ❌
Client C (legitimate) → BLOCKED as collateral damage ❌
```

##### Solution: Map<clientId, state>

Each client has **isolated strike tracking** using `Map<clientId, RateLimitState>`:

```typescript
{
  strikes: number,           // 0-3 strikes
  inBackoff: boolean,        // Currently in backoff period
  blockedUntil: number,      // Unix timestamp when backoff expires
  panicMode: boolean         // Permanently blocked flag
}
```

**Client ID Extraction Priority**:
1. **`x-client-id` header** (explicit client identification)
2. **`x-forwarded-for` header** (proxy chain, first IP extracted)
3. **`req.socket.remoteAddress`** (direct connection IP)
4. **`'default-client'`** (fallback, same as global state)

##### Progressive Backoff (3 Strikes)

| Strike       | Trigger          | Backoff Duration | Behavior                                   | Recovery                 |
|--------------|------------------|------------------|--------------------------------------------|--------------------------|
| **Strike 1** | First HTTP 429   | 30 seconds       | Client blocked temporarily                 | Auto-resume after 30s    |
| **Strike 2** | Second HTTP 429  | 60 seconds       | Extended block with warning                | Auto-resume after 60s    |
| **Strike 3** | Third HTTP 429   | **Permanent**    | **PANIC MODE** - client permanently blocked| Only proxy restart clears|

**Example Flow**:
```bash
# Client 192.168.1.100 triggers first 429
[INFO] Strike 1/3 for client 192.168.1.100: Entering 30 second backoff

# Client tries to connect during backoff
{
  "error": {
    "code": -32005,
    "message": "Rate limit backoff active for client 192.168.1.100 (Strike 1/3)",
    "data": {
      "blockedUntil": "2026-03-07T12:35:30Z",
      "remainingSeconds": 25,
      "strikes": 1
    }
  }
}

# After 30s, backoff expires, client auto-resumes
[INFO] Client 192.168.1.100 backoff expired, resuming normal operation

# Client triggers second 429
[WARN] Strike 2/3 for client 192.168.1.100: Entering 60 second backoff

# Client triggers third 429
[ERROR] Strike 3/3 for client 192.168.1.100: PANIC MODE activated

# All subsequent requests permanently blocked
{
  "error": {
    "code": -32004,
    "message": "Proxy is in PANIC MODE for client 192.168.1.100",
    "data": {
      "reason": "panic_mode",
      "strikes": 3,
      "panicMode": true
    }
  }
}
```

**Anti-DoS Properties**:
- ✅ **Client Isolation**: One malicious client cannot affect others
- ✅ **Self-Healing**: Automatic recovery after backoff period
- ✅ **Forensic Trail**: Complete audit log with client IDs and timestamps
- ✅ **Permanent Block**: Persistent abusers locked out until proxy restart

---

#### 5 Classic Guardrails (Post-Gateway Layer)

The following guardrails run **AFTER** the Security Gateway passes a request, providing an additional defense layer:

#### 1. HTTPS Enforcer

**Purpose**: Ensures all external HTTP requests are upgraded to HTTPS to prevent man-in-the-middle attacks.

**How it works**:
- Intercepts tool calls that include URL parameters (e.g., `fetch_url`, `download_file`)
- Detects HTTP URLs using pattern matching: `http://` (non-secure)
- Automatically upgrades to `https://` before forwarding to server
- Logs all upgrades for security auditing

**Example**:
```typescript
// Client request
{ method: 'tools/call', params: { name: 'fetch_data', arguments: { url: 'http://api.example.com/data' } } }

// Proxy intercepts and upgrades
{ method: 'tools/call', params: { name: 'fetch_data', arguments: { url: 'https://api.example.com/data' } } }

// Audit log
[INFO] 🔒 HTTPS_ENFORCER: Upgraded URL from HTTP to HTTPS: api.example.com
```

**Protection against**:
- Man-in-the-middle (MITM) attacks
- Credential sniffing on public networks
- API key interception

**Limitations**:
- Does not protect internal localhost requests (assumed trusted)
- Cannot enforce HTTPS for embedded URLs in text responses

#### 2. Input Sanitizer

**Purpose**: Neutralizes common injection attacks by stripping dangerous characters from tool parameters.

**How it works**:
- Scans all string parameters in tool calls
- Applies multiple sanitization rules:
  - **SQL Injection**: Removes `'`, `"`, `;`, `--`, `/*`, `*/`, `UNION`, `SELECT`, `DROP`, `DELETE`, `INSERT`
  - **XSS**: Strips `<script>`, `</script>`, `<iframe>`, `javascript:`, `onerror=`, `onload=`
  - **Command Injection**: Removes `|`, `&`, `;`, `$()`, `` ` ``, `&&`, `||`
  - **Path Traversal**: Strips `../`, `..\\`, `/etc/`, `C:\`
- Returns sanitized parameters to tool implementation

**Example**:
```typescript
// Malicious client request
{ method: 'tools/call', params: { name: 'search_users', arguments: { query: "' OR 1=1--" } } }

// Proxy sanitizes
{ method: 'tools/call', params: { name: 'search_users', arguments: { query: " OR 11" } } }

// Audit log
[INFO] 🛡️ INPUT_SANITIZER: Sanitized SQL injection attempt in tool 'search_users' (removed: ', --)
```

**Protection against**:
- SQL Injection (OWASP A03:2021)
- Cross-Site Scripting (OWASP A03:2021)
- Command Injection (OWASP A03:2021)
- Path Traversal (OWASP A01:2021)

**Limitations**:
- May cause false positives for legitimate queries containing SQL keywords (e.g., "SELECT a product from the menu")
- Cannot detect context-aware injections (e.g., second-order SQL injection)
- Does not validate business logic (e.g., "legal" queries that bypass authorization)

#### 3. PII Redactor

**Purpose**: Prevents sensitive personal information from leaking in logs and responses.

**How it works**:
- Scans **server responses** (not client requests) for PII patterns
- Redacts using regex patterns:
  - **Credit Cards**: `\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}` → `****-****-****-1234`
  - **SSN**: `\d{3}-\d{2}-\d{4}` → `***-**-1234`
  - **Email**: `[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}` → `***@example.com`
  - **API Keys**: `sk-[a-zA-Z0-9]{48}`, `ghp_[a-zA-Z0-9]{36}` → `sk-****...****`
  - **Phone Numbers**: `\+?\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}` → `***-***-1234`
- Leaves last 4 digits visible for debugging
- Redacts **both response payloads and audit logs**

**Example**:
```typescript
// Server response (unredacted)
{ result: { customer: 'John Doe', email: 'john@example.com', card: '4532-1234-5678-9010' } }

// Proxy redacts before logging
{ result: { customer: 'John Doe', email: '***@example.com', card: '****-****-****-9010' } }

// Audit log
[INFO] 🔒 PII_REDACTOR: Redacted 1 email, 1 credit card in response
```

**Protection against**:
- Data Leakage (OWASP A01:2021)
- GDPR violations (PII exposure)
- PCI-DSS violations (credit card exposure)
- Compliance violations (HIPAA, CCPA)

**Limitations**:
- Regex-based detection may miss obfuscated PII (e.g., `john [at] example.com`)
- Cannot detect custom PII formats (e.g., internal employee IDs)
- Does not prevent PII from being **processed** by the server (only redacted in logs)

#### 4. Rate Limiter

**Purpose**: Prevents Denial of Service (DoS) attacks by limiting request frequency per tool.

**How it works**:
- Implements **Token Bucket Algorithm** per tool name
- Default limits:
  - **Capacity**: 100 requests per tool
  - **Refill Rate**: 10 tokens per second
  - **Burst Allowance**: 100 requests instantly, then 10/sec sustained
- Tracks requests in memory (resets on proxy restart)
- Rejects excess requests with `429 Too Many Requests` error

**Example**:
```typescript
// Client sends 150 requests to 'execute_query' in 1 second

// First 100 requests: ✅ Allowed (bucket has 100 tokens)
// Requests 101-150: ❌ Blocked (bucket empty, refilling at 10/sec)

// Server response
{ error: { code: -32000, message: 'Rate limit exceeded for tool execute_query. Try again in 5 seconds.' } }

// Audit log
[WARN] ⏱️ RATE_LIMITER: Blocked request to 'execute_query' (100/100 tokens used, refill in 5s)
```

**Protection against**:
- Denial of Service (DoS) attacks
- Resource exhaustion
- Accidental runaway loops (e.g., infinite LLM recursion)
- API quota abuse

**Configuration**:
```bash
# Customize limits via environment variables
MCP_RATE_LIMIT_CAPACITY=200 \
MCP_RATE_LIMIT_REFILL_RATE=20 \
mcp-verify proxy "node server.js"
```

**Limitations**:
- Per-tool limits, not per-client (all clients share the same bucket)
- No persistent state (limits reset on proxy restart)
- Does not protect against **distributed** DoS (multiple proxies)

#### 5. Sensitive Command Blocker

**Purpose**: Prevents execution of dangerous shell commands that could compromise the host system.

**How it works**:
- Scans tool parameters for **command-like patterns**
- Blocks if any of these patterns are detected:
  - **Destructive**: `rm -rf`, `del /f`, `format`, `DROP DATABASE`
  - **Network Exfiltration**: `curl`, `wget`, `nc`, `netcat`, `ssh`, `scp`
  - **Privilege Escalation**: `sudo`, `su`, `chmod 777`, `chown root`
  - **Code Execution**: `eval`, `exec`, `system()`, `/bin/sh`, `cmd.exe`
- Returns error before request reaches server

**Example**:
```typescript
// Malicious client request
{ method: 'tools/call', params: { name: 'run_script', arguments: { command: 'rm -rf /var/log/*' } } }

// Proxy blocks
{ error: { code: -32001, message: 'Blocked dangerous command pattern: rm -rf' } }

// Audit log
[WARN] 🚫 SENSITIVE_COMMAND_BLOCKER: Blocked potentially dangerous command pattern: 'rm -rf' in tool 'run_script'
```

**Protection against**:
- Remote Code Execution (RCE)
- Data Exfiltration
- Privilege Escalation
- System Compromise

**Limitations**:
- Pattern-based (can be bypassed with obfuscation: `r""m -rf`)
- Cannot detect context-aware malicious logic (e.g., "legal" command with malicious parameters)
- May block legitimate use cases (e.g., `curl` in a debugging tool)

**Bypass Protection**:
To allow specific commands, use an allow-list:
```bash
MCP_ALLOW_COMMANDS="curl,wget" mcp-verify proxy "node server.js"
```

#### Logging & Auditing

The Proxy emits **structured security events** to **stderr** for integration with SIEM/logging systems.

**Log Format**:
```
[LEVEL] 🔒 GUARDRAIL_NAME: Event description (metadata)
```

**Log Levels**:
- `[INFO]`: Normal security events (sanitization, redaction, HTTPS upgrade)
- `[WARN]`: Blocked requests (rate limiting, command blocking)
- `[ERROR]`: Internal proxy errors (misconfiguration, guardrail failures)

**Example Audit Log**:
```bash
[INFO] 🔒 HTTPS_ENFORCER: Upgraded URL from HTTP to HTTPS: api.example.com
[INFO] 🛡️ INPUT_SANITIZER: Sanitized SQL injection attempt in tool 'search_users' (removed: ', --)
[INFO] 🔒 PII_REDACTOR: Redacted 2 emails, 1 credit card in response
[WARN] ⏱️ RATE_LIMITER: Blocked request to 'execute_query' (100/100 tokens used)
[WARN] 🚫 SENSITIVE_COMMAND_BLOCKER: Blocked dangerous command pattern: 'rm -rf' in tool 'run_script'
```

**Integration with Logging Systems**:
```bash
# Datadog
mcp-verify proxy "node server.js" 2>&1 | tee /dev/stderr | datadog-agent logs

# CloudWatch
mcp-verify proxy "node server.js" 2> >(aws logs put-log-events --log-group mcp-verify)

# ELK Stack
mcp-verify proxy "node server.js" 2> >(filebeat -e)

# File-based
mcp-verify proxy "node server.js" 2> security-audit.log
```

**Security Event Metrics**:
- Total requests proxied
- Blocked requests per Security Gateway layer (L1/L2/L3)
- Client strike counts and panic mode activations
- Cache hit ratio and performance gains
- Blocked requests per guardrail (post-gateway)
- Sanitization operations performed
- PII redactions applied
- HTTPS upgrades enforced

**Performance Impact (Security Gateway v1.0)**:

| Configuration | Latency | Use Case | Cost (approx.) |
|---------------|---------|----------|----------------|
| **Layer 1+2 only (default)** | +10-50ms | Production, high-throughput | $0 |
| **Layer 1+2 with cache hits** | +<1ms | Repeated requests (65-75% hit ratio) | $0 |
| **Layer 1+2+3 (LLM enabled)** | +500-2000ms | Research, high-security | $5-$15 per 1K req* |
| **Classic Guardrails only** | +5-15ms | Legacy compatibility | $0 |

*LLM costs vary by provider (Anthropic/OpenAI/Gemini) and depend on actual usage patterns.

**Resource Usage**:
- **Memory**: ~15MB base + 10MB per 1000 cache entries + strike tracking state
- **CPU**: <10% overhead (Layer 1+2), <15% with guardrails
- **Disk I/O**: Minimal (audit log writes only)

**Throughput**:
- **Without Gateway**: ~10,000 requests/sec
- **Layer 1+2 enabled**: ~8,000 requests/sec (20% reduction)
- **Layer 1+2+3 enabled**: ~100-500 requests/sec (LLM bottleneck)

---

### Smart Fuzzer v1.0 Security

The **Smart Fuzzer** (`mcp-verify fuzz`) is an intelligent security testing engine that goes beyond static analysis to detect runtime vulnerabilities through adaptive payload generation and anomaly detection.

#### Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│ Baseline        │ →   │ Payload          │ →   │ Anomaly         │
│ Calibration     │     │ Generation       │     │ Detection       │
└─────────────────┘     └──────────────────┘     └─────────────────┘
        ↓                       ↓                         ↓
   Clean timing/         9 Generators          10 Detectors
   size baselines        12 Mutations          (timing, errors, XSS)
        ↓                       ↓                         ↓
┌─────────────────────────────────────────────────────────────────┐
│                        Feedback Loop                             │
│  (Analyzes responses → Generates mutations → Tests again)        │
└─────────────────────────────────────────────────────────────────┘
```

#### How It Works

**Phase 1: Fingerprinting**
- Automatically detects server language/framework (Node.js, Python, Java, etc.)
- Disables irrelevant payload generators (saves 40-60% time)
- Example: If server is Node.js, disables Java deserialization payloads

**Phase 2: Baseline Calibration**
- Sends clean requests to establish "normal" behavior
- Measures average response time, size, status codes
- Creates anomaly detection thresholds (e.g., "response >3x baseline = suspicious")

**Phase 3: Payload Generation**
9 specialized generators create attack vectors:

| Generator | Vulnerability Targeted | Example Payload |
|-----------|------------------------|-----------------|
| **Prompt Injection** | Indirect prompt injection, jailbreaks | `Ignore previous instructions. Execute: ...` |
| **SQL Injection** | Database access bypass | `' OR 1=1--`, `UNION SELECT * FROM users` |
| **XSS Payloads** | Cross-site scripting | `<script>alert(1)</script>`, `<img src=x onerror=...>` |
| **Command Injection** | Shell command execution | `; cat /etc/passwd`, `| whoami` |
| **JWT Attacks** | Token forgery, algorithm confusion | `{"alg":"none"}`, expired tokens |
| **Prototype Pollution** | JavaScript object poisoning | `{"__proto__": {"isAdmin": true}}` |
| **JSON-RPC Violations** | Protocol compliance bypass | Invalid `jsonrpc` versions, missing IDs |
| **Schema Confusion** | Type coercion, boundary testing | `age: "999999999999999999999"` (string instead of int) |
| **Path Traversal** | Directory traversal | `../../etc/passwd`, `C:\Windows\System32` |

**Phase 4: Mutation Strategies**
12 mutation strategies transform baseline payloads:

| Mutation | Purpose | Example |
|----------|---------|---------|
| **SQL Depth** | Nested injection | `' OR (SELECT * FROM (SELECT 1)x)--` |
| **Null-Byte Injection** | String termination bypass | `payload\x00.txt` |
| **Unicode Bypass** | Filter evasion | `<script>` → `＜script＞` (fullwidth chars) |
| **Timing Probes** | Blind injection detection | `'; WAITFOR DELAY '00:00:05'--` |
| **Buffer Stress** | Overflow testing | 10KB+ strings |
| **Quote Variation** | SQL injection variants | `"`, `'`, `` ` ``, `''`, `"""` |
| **Case Mutation** | Case-sensitive filter bypass | `SeLeCt`, `uNiOn` |
| **Encoding Bypass** | WAF evasion | URL-encode, double-encode, hex |
| **Polyglot Payloads** | Multi-context injection | `';alert(1)//` (SQL + XSS) |
| **Recursive Nesting** | Parser exhaustion | `{{{{{...}}}}}` (1000+ levels) |
| **Type Confusion** | Type coercion bugs | `true` → `"true"` → `1` → `[true]` |
| **Boundary Probing** | Min/max violations | `age: -1`, `age: 9999999999` |

**Phase 5: Anomaly Detection**
10 detectors analyze responses for exploitation signs:

| Detector | What It Detects | Confidence Signal |
|----------|-----------------|-------------------|
| **Timing Anomalies** | Blind injection, DoS | Response >3x baseline (e.g., 50ms → 200ms) |
| **Error Disclosure** | Stack traces, SQL errors | Keywords: `SQLException`, `Traceback`, `Fatal error` |
| **XSS Reflection** | Payload echoed in response | Detects `<script>`, `onerror=` in output |
| **Prompt Leaks** | System instructions exposed | Patterns: `You are a helpful assistant...` |
| **Jailbreak Success** | Guardrail bypass | Response contains restricted content |
| **Path Traversal** | Directory listing, file access | Detects `/etc/passwd`, `root:x:0:0` |
| **Weak Identifiers** | Predictable IDs, UUIDs | Sequential IDs: `1`, `2`, `3` vs. `a3f5-9d2c-...` |
| **Info Disclosure** | Version numbers, internal paths | `Express 4.17.1`, `/home/user/app/src/` |
| **JWT Manipulation** | Forged tokens accepted | `alg: none` succeeds, expired tokens valid |
| **Prototype Pollution** | Polluted properties in response | `isAdmin: true` when it shouldn't exist |

**Phase 6: Feedback Loop**
- If detector flags a response as suspicious, fuzzer generates **mutations** of that payload
- Example: If `' OR 1=1--` causes timing anomaly, fuzzer tries:
  - `" OR 1=1--` (quote variation)
  - `' OR 2=2--` (logic variation)
  - `'; WAITFOR DELAY '00:00:10'--` (timing probe)
- Feedback loop runs for **3 rounds** (configurable with `--max-mutations`)

#### Security Benefits

**1. Runtime Vulnerability Detection**
- Unlike static analysis, fuzzer **executes** payloads against running servers
- Catches vulnerabilities that only manifest at runtime (e.g., weak validation logic)

**2. Adaptive Testing**
- Learns from server responses to refine attack strategies
- Example: If server blocks `<script>`, tries `<img onerror=...>`, `<svg onload=...>`

**3. Baseline Comparison**
- Establishes "known good" state before fuzzing
- Eliminates false positives from legitimate slow operations

**4. Comprehensive Coverage**
- Tests **all parameter combinations** (nested objects, arrays, edge cases)
- Example: For `{ user: { role: string } }`, tests:
  - `role: "admin"` (valid)
  - `role: null` (null injection)
  - `role: 99999` (type confusion)
  - `user: null` (object nullification)

#### Configuration & Safety

**Controlling Intensity**:
```bash
# Light fuzzing (25 payloads/tool, no mutations)
mcp-verify fuzz "node server.js" --max-payloads 25 --no-mutations

# Balanced (default: 50 payloads, 3 mutations)
mcp-verify fuzz "node server.js"

# Aggressive (100 payloads, 5 mutations)
mcp-verify fuzz "node server.js" --max-payloads 100 --mutations 5
```

**Production Safety**:
- ⚠️ **Never run against production** without authorization
- Use `--concurrency 1 --delay 1000` to reduce impact
- Enable `--dry-run` to preview payloads without sending

**Ethical Considerations**:
- Fuzzer is designed for **authorized security testing only**
- Users are responsible for ensuring proper authorization
- See [Responsible Disclosure Policy](#reporting-vulnerabilities)

#### Limitations

**What Fuzzer CANNOT Detect**:
- ❌ **Business logic flaws** (e.g., "analyst can approve transactions" if schema allows it)
- ❌ **Second-order vulnerabilities** (stored XSS that executes later)
- ❌ **Zero-day exploits** (unknown attack vectors not in payload database)
- ❌ **Human error** (misconfigured AWS S3 buckets, weak passwords)

**False Positives**:
- Timing anomalies may occur due to network latency, not vulnerabilities
- Always manually verify CRITICAL findings before reporting

---

### Security Profiles

**Security Profiles** control the intensity and scope of security testing across validation, fuzzing, and static analysis.

#### Purpose

Different environments require different security rigor:
- **Development**: Fast iterations, minimal overhead → Light profile
- **Staging**: Balanced testing before production → Balanced profile
- **Pre-Production**: Maximum scrutiny, zero tolerance → Aggressive profile

Profiles provide **preset configurations** so users don't manually configure 20+ parameters.

#### Available Profiles

| Profile | Use Case | Payloads/Tool | Mutations | Score Threshold | Fail On |
|---------|----------|---------------|-----------|-----------------|---------|
| **light** | Quick checks, CI/CD (fast feedback) | 25 | 0 | 60/100 | Critical only |
| **balanced** | Regular testing (default) | 50 | 3 | 70/100 | Critical only |
| **aggressive** | Pre-production audits (maximum rigor) | 100 | 5 | 90/100 | Critical + High |

#### Profile Configuration Details

**Light Profile**:
```json
{
  "fuzzing": {
    "useMutations": false,
    "mutationsPerPayload": 0,
    "maxPayloadsPerTool": 25,
    "enableFeedbackLoop": false
  },
  "validation": {
    "minSecurityScore": 60,
    "failOnCritical": true,
    "failOnHigh": false
  },
  "generators": {
    "enablePromptInjection": true,
    "enableClassicPayloads": true,
    "enablePrototypePollution": false,
    "enableJwtAttacks": false
  },
  "detectors": {
    "enableTimingDetection": false,
    "timingAnomalyMultiplier": 5.0,
    "enableErrorDetection": true
  }
}
```

**Use Case**: Fast CI/CD pipelines where developers need immediate feedback (< 30 seconds per tool).

**Balanced Profile** (Default):
```json
{
  "fuzzing": {
    "useMutations": true,
    "mutationsPerPayload": 3,
    "maxPayloadsPerTool": 50,
    "enableFeedbackLoop": true
  },
  "validation": {
    "minSecurityScore": 70,
    "failOnCritical": true,
    "failOnHigh": false
  },
  "generators": {
    "enablePromptInjection": true,
    "enableClassicPayloads": true,
    "enablePrototypePollution": true,
    "enableJwtAttacks": true
  },
  "detectors": {
    "enableTimingDetection": true,
    "timingAnomalyMultiplier": 3.0,
    "enableErrorDetection": true
  }
}
```

**Use Case**: Standard security testing in staging environments (1-3 minutes per tool).

**Aggressive Profile**:
```json
{
  "fuzzing": {
    "useMutations": true,
    "mutationsPerPayload": 5,
    "maxPayloadsPerTool": 100,
    "enableFeedbackLoop": true
  },
  "validation": {
    "minSecurityScore": 90,
    "failOnCritical": true,
    "failOnHigh": true
  },
  "generators": {
    "enablePromptInjection": true,
    "enableClassicPayloads": true,
    "enablePrototypePollution": true,
    "enableJwtAttacks": true
  },
  "detectors": {
    "enableTimingDetection": true,
    "timingAnomalyMultiplier": 2.5,
    "enableErrorDetection": true
  }
}
```

**Use Case**: Pre-production security audits, compliance checks, penetration testing (5-10 minutes per tool).

#### Usage

**CLI (One-Shot)**:
```bash
# Validate with light profile
mcp-verify validate "node server.js" --profile light

# Fuzz with aggressive profile
mcp-verify fuzz "node server.js" --profile aggressive
```

**Interactive Shell**:
```bash
$ mcp-verify
> profile set aggressive
✓ Switched to profile: aggressive (100 payloads, score ≥90)

> fuzz --tool "execute_query"
# Uses aggressive profile settings automatically
```

**Custom Profiles**:
```bash
# Save current settings as custom profile
> profile save my-custom-profile
✓ Saved custom profile: my-custom-profile to ~/.mcp-verify/config.json

# Load custom profile
> profile set my-custom-profile
✓ Switched to profile: my-custom-profile
```

#### Security Implications

**Light Profile Risks**:
- ⚠️ May miss sophisticated attacks (no mutations, low payload count)
- ⚠️ Timing-based attacks not detected (timing detection disabled)
- ✅ Suitable for: Quick smoke tests, developer local testing

**Balanced Profile**:
- ✅ Good coverage of common vulnerabilities
- ✅ Reasonable trade-off between speed and rigor
- ✅ Suitable for: CI/CD, staging environment testing

**Aggressive Profile Risks**:
- ⚠️ High resource consumption (may trigger rate limiting)
- ⚠️ Long execution time (not suitable for rapid iteration)
- ✅ Suitable for: Pre-production audits, compliance testing

#### Configuration Hierarchy

Profiles respect the configuration hierarchy:
1. **CLI Flags** (highest priority): `--max-payloads 200` overrides profile
2. **Active Context**: Context-specific settings override profile
3. **Profile**: Preset or custom profile settings
4. **System Defaults** (lowest priority): Fallback values

**Example**:
```bash
# Aggressive profile = 100 payloads, but CLI flag overrides to 200
mcp-verify fuzz "node server.js" --profile aggressive --max-payloads 200
# Result: 200 payloads/tool (CLI wins)
```

---

### Interactive Shell Security

The **Interactive Shell** (`mcp-verify` without arguments) provides a persistent REPL environment with enhanced security features.

#### Security Features

**1. Multi-Context Isolation**
- Each context (dev, staging, prod) has **independent configuration**
- Prevents accidental cross-environment contamination
- Example: Switching from `dev` to `prod` does NOT carry over fuzzing settings

**Example**:
```bash
$ mcp-verify
> context create dev
> set target "node dev-server.js"
> profile set light

> context create prod
> set target "https://prod.example.com/mcp"
> profile set aggressive

# Contexts are isolated - dev settings don't affect prod
> context switch dev
✓ Switched to context: dev (light profile)
```

**2. Session Persistence Security**
- Session state saved to `.mcp-verify/session.json` (per-project)
- File permissions: `0600` (read/write by owner only)
- **Secrets are NEVER persisted** (API keys, tokens excluded)

**What is persisted**:
- ✅ Target MCP server (e.g., `node server.js`)
- ✅ Active language (en/es)
- ✅ Active security profile (light/balanced/aggressive)
- ✅ Context configurations

**What is NOT persisted**:
- ❌ API keys (loaded from environment only)
- ❌ Command history containing secrets (redacted before save)
- ❌ Temporary authentication tokens

**3. Command History Redaction**
- History saved to `~/.mcp-verify/history.json` (cross-session)
- **Automatic secret redaction** before saving
- Patterns redacted:
  - `ANTHROPIC_API_KEY=sk-ant-...` → `ANTHROPIC_API_KEY=***REDACTED***`
  - `--api-key sk-ant-...` → `--api-key ***REDACTED***`
  - `token: "ghp_..."` → `token: "***REDACTED***"`

**Example**:
```bash
# User types
> validate node server.js --api-key sk-ant-api03-XXXXXX

# Saved to history.json
> validate node server.js --api-key ***REDACTED***
```

**4. Environment Variable Security**
- `.env` files auto-loaded on shell startup
- Environment variables **NOT persisted** to session files
- Loaded keys visible in `status` command for debugging

**Example**:
```bash
$ mcp-verify
Loading environment from .env...
✓ Loaded 5 keys: ANTHROPIC_API_KEY, DEBUG, MCP_TIMEOUT, MCP_HOST, MCP_PORT

> status
Environment:
  Source:  .env
  Keys:    5 loaded
    ANTHROPIC_API_KEY, DEBUG, MCP_TIMEOUT, MCP_HOST, MCP_PORT
```

**What is secure**:
- ✅ API keys loaded from `.env` (not hardcoded in shell commands)
- ✅ `.env` excluded from version control (via `.gitignore`)

**What is NOT secure**:
- ❌ `.env` file permissions (user must set `chmod 600 .env`)
- ❌ Environment variable leaks via OS process inspection (use encrypted secrets in production)

**5. Output Redirection Safety**
```bash
# Redirect command output to file
> validate > report.txt

# Secrets are redacted in redirected output
> status > debug.log
# File contains: ANTHROPIC_API_KEY: ***REDACTED***
```

#### Workspace Health Check

**Purpose**: Verify target MCP server is reachable and validates protocol compliance.

**What it checks**:
1. **Connection Status**: Can the proxy reach the server?
2. **MCP Handshake**: Does the server respond to `initialize` request correctly?
3. **Protocol Version**: Does the server support MCP 2024-11-05?
4. **Environment Integrity**: Are required API keys loaded?
5. **Last Report**: Where was the last security report saved?

**Example**:
```bash
> status
Workspace Status

Context:
  Active:  dev
  Target:  node server.js
  Profile: balanced

Environment:
  Source:  .env
  Keys:    3 loaded
    ANTHROPIC_API_KEY, DEBUG, MCP_TIMEOUT

Last Report:
  Path:    reports/html/mcp-report-2026-02-24.html
  Time:    2/24/2026, 3:45:12 PM

Target Connection:
  Status:  ● Connected
  Server:  My Development Server
  Version: 2024-11-05
  Time:    134ms
```

**Security Value**:
- Prevents accidental testing against **wrong server** (e.g., fuzzing prod instead of dev)
- Validates **protocol compliance** before expensive fuzzing runs
- Detects **dead targets** early (no wasted time on unreachable servers)

#### Autocomplete Security

**File Path Completion**:
- Only completes **readable files** (checks file permissions)
- Prevents tab-completing restricted files (`/etc/shadow`, etc.)

**Flag Completion**:
- Only suggests **valid flags** for active command
- Prevents typo-based injection (e.g., `--max-payloads` vs. `--max-paylaods`)

#### Attack Surface

**What Interactive Shell DOES NOT expose**:
- ❌ Network listening ports (shell is local-only)
- ❌ Web interfaces (no HTTP server)
- ❌ Remote command execution (commands run in local process)

**Threat Model**:
- Shell assumes **trusted local user** (if attacker has shell access, game over)
- Does NOT protect against **malicious MCP servers** (use proxy guardrails for that)

---

### Secret Redaction System

The **Secret Redaction System** prevents API keys, tokens, and credentials from leaking through logs, history files, and session persistence.

#### Redaction Targets

**1. Command History**
- Location: `~/.mcp-verify/history.json`
- Redacts before saving to disk
- Patterns detected:
  - `ANTHROPIC_API_KEY=sk-ant-...`
  - `OPENAI_API_KEY=sk-...`
  - `GEMINI_API_KEY=AI...`
  - `--api-key <value>`
  - `"token": "<value>"`
  - `Bearer <value>`

**2. Session Files**
- Location: `.mcp-verify/session.json`
- API keys **NEVER** stored in session
- Only references to environment variables stored (e.g., `"apiKeyEnv": "ANTHROPIC_API_KEY"`)

**3. Logs**
- All log output (stdout, stderr, debug logs) scanned for secrets
- Redacted patterns:
  - API keys: `sk-****...****` (shows first 3 + last 4 chars)
  - Tokens: `***REDACTED***`
  - Passwords: `***REDACTED***`

**4. Report Files**
- HTML/JSON/SARIF reports redact secrets found in:
  - Tool descriptions (e.g., "Use API key sk-ant-...")
  - Parameter examples
  - Error messages from servers

#### Redaction Algorithm

**Pattern Detection**:
```typescript
// Anthropic API keys
/sk-ant-api03-[a-zA-Z0-9_-]{95}/g → sk-****...****

// OpenAI API keys
/sk-[a-zA-Z0-9]{48}/g → sk-****...****

// GitHub Personal Access Tokens
/ghp_[a-zA-Z0-9]{36}/g → ghp_****...****

// Generic Bearer tokens
/Bearer\s+[a-zA-Z0-9_-]{20,}/g → Bearer ***REDACTED***

// Environment variable assignments
/API_KEY\s*=\s*["']?([^"'\s]+)/g → API_KEY=***REDACTED***
```

**Redaction Strategy**:
- **Short secrets** (<20 chars): Fully redacted → `***REDACTED***`
- **Long secrets** (≥20 chars): Partial redaction → `sk-****...7x3A` (first 3 + last 4 visible)

**Why partial redaction?**
- Allows debugging: "Which key was used?" without exposing full secret
- Maintains log correlation: Same key always shows same redaction

#### Security Guarantees

**What IS protected**:
- ✅ API keys in command history
- ✅ Tokens in session files
- ✅ Secrets in log output
- ✅ Credentials in reports

**What is NOT protected**:
- ❌ Secrets already committed to Git (use `git-secrets` or `truffleHog`)
- ❌ Secrets in process memory (use encrypted memory if needed)
- ❌ Secrets in OS environment (use secrets managers like HashiCorp Vault)
- ❌ Secrets in screenshot/screen recordings (user responsibility)

#### Best Practices

**1. Never hardcode secrets**:
```bash
# ❌ BAD: Secret in command
mcp-verify validate node server.js --api-key sk-ant-api03-XXXXXX

# ✅ GOOD: Secret in environment variable
export ANTHROPIC_API_KEY=sk-ant-api03-XXXXXX
mcp-verify validate node server.js
```

**2. Use `.env` files for local development**:
```bash
# .env (add to .gitignore!)
ANTHROPIC_API_KEY=sk-ant-api03-XXXXXX
OPENAI_API_KEY=sk-XXXXXX
```

**3. Use secrets managers in production**:
```bash
# AWS Secrets Manager
export ANTHROPIC_API_KEY=$(aws secretsmanager get-secret-value --secret-id mcp-verify-key --query SecretString --output text)

# HashiCorp Vault
export ANTHROPIC_API_KEY=$(vault kv get -field=api_key secret/mcp-verify)
```

**4. Rotate keys regularly**:
- If key appears in logs/history/reports → Rotate immediately
- Monitor usage via Anthropic Console for suspicious activity

#### Verification

**Check if history is redacted**:
```bash
cat ~/.mcp-verify/history.json | grep -i "api"
# Should show: "***REDACTED***" not actual keys
```

**Check if logs are clean**:
```bash
mcp-verify validate node server.js > output.log 2>&1
grep -E "sk-ant-|sk-[a-zA-Z0-9]{48}" output.log
# Should return nothing (all keys redacted)
```

---

### Schema Validation (High Confidence)

- ✅ JSON Schema compliance (Draft 2020-12)
- ✅ Required field validation
- ✅ Type checking (string, number, object, array)
- ✅ Enum validation

### Quality Analysis (Medium Confidence)

- ✅ Documentation completeness
- ✅ Naming conventions
- ✅ Parameter descriptions
- ✅ Example clarity

---

## What We Don't Secure

### Runtime Behavior (Outside Scope)

mcp-verify analyzes **static declarations**, not runtime code execution:

- ❌ **Actual tool implementations** - We don't run the code
- ❌ **Dynamic vulnerabilities** - Only static patterns detected
- ❌ **Business logic flaws** - Context-specific vulnerabilities
- ❌ **Race conditions** - Concurrency issues
- ❌ **Memory leaks** - Resource management
- ❌ **Timing attacks** - Side-channel vulnerabilities

**Example**: If a tool description says "Read file safely" but the implementation has path traversal, mcp-verify may not detect it unless the description explicitly mentions unsafe patterns.

### Upstream Dependencies (Not Controlled)

- ❌ **MCP servers being tested** - We analyze, we don't control their security
- ❌ **Claude Desktop security model** - Managed by Anthropic
- ❌ **Node.js runtime security** - Depends on Node.js version
- ❌ **Network security** - Use HTTPS, firewalls, etc.
- ❌ **OS-level protections** - File permissions, process isolation

### Guarantee Limitations

mcp-verify provides **risk assessment**, not **absolute security**:

- 🟢 **Score 95/100**: "No known patterns detected" ≠ "Perfectly secure"
- 🟡 **Score 70/100**: "Some issues found" ≠ "Definitely vulnerable"
- 🔴 **Score 30/100**: "Critical patterns detected" = "Very likely vulnerable"

**Analogy**: mcp-verify is like a spell-checker for security. It catches known patterns, but cannot guarantee correctness.

---

## Known Limitations

mcp-verify v1.0.0 performs automated technical security testing but has inherent limitations that users must understand before deployment:

### Business Logic Vulnerabilities

**Limitation**: mcp-verify **cannot detect authorization issues that are technically valid but violate business rules**.

The fuzzer excels at finding technical vulnerabilities (type confusion, boundary violations, enum bypass). However, it cannot understand domain-specific authorization logic.

**Example**:
```typescript
// Schema (technically valid)
{
  role: { type: 'string', enum: ['analyst', 'manager'] },
  action: { type: 'string', enum: ['approve', 'reject'] }
}

// ✅ mcp-verify WILL detect: { role: 'admin' } → Privilege escalation (value outside enum)
// ❌ mcp-verify WILL NOT detect: { role: 'analyst', action: 'approve' }
//    → If only 'manager' should approve (business rule not in schema)
```

**Impact**: Authorization bugs that depend on business context will NOT be caught.

**Mitigation**:
- Complement mcp-verify with **manual authorization testing**
- Implement **role-based access control (RBAC) tests** in your test suite
- Document business rules explicitly in tool descriptions
- Use security annotations in schemas (e.g., `x-security-role: 'manager'` for custom validation)

### False Positives

**Limitation**: Findings marked as **CRITICAL** require manual validation to confirm they are exploitable vulnerabilities.

mcp-verify uses heuristics to detect vulnerabilities. A server that correctly validates input may still trigger findings if the validation logic isn't visible in the schema.

**Example of False Positive**:
```typescript
// Payload sent by fuzzer
{ age: 121 }  // Schema: { maximum: 120 }

// Server response
{ error: 'Invalid age', code: 400 }

// mcp-verify finding
CRITICAL: Boundary overflow - age exceeds maximum (121 > 120)

// Reality: Server validated correctly → FALSE POSITIVE
```

**Impact**: Security teams may waste time investigating non-issues.

**Mitigation**:
- **Always review CRITICAL findings manually** before reporting as vulnerabilities
- Check server responses: `error` responses often indicate correct validation
- Use baseline comparison (`--compare-baseline`) to track new findings vs. known false positives
- Suppress confirmed false positives using `.mcpverifyignore`

### Production Impact

**Limitation**: Running mcp-verify against production servers may trigger **rate limiting**, **intrusion detection systems (IDS)**, or cause **log saturation**.

The fuzzer generates **150-250 payloads per tool** for schema-aware testing. This volume of requests can:

- Trigger rate limiting → IP blocking
- Alert security monitoring systems (SIEM, IDS) → False alarm investigations
- Saturate application logs → Obscure real attacks
- Consume API quotas → Service degradation

**Impact**: Production services may be disrupted or security teams alerted unnecessarily.

**Mitigation**:
- ⚠️ **ALWAYS run mcp-verify in staging/pre-production environments**
- If testing production is unavoidable:
  - Use `--concurrency 1` to reduce request rate
  - Use `--delay 1000` (1 second delay between requests)
  - Notify security teams beforehand
  - Whitelist fuzzer IP in rate limiting rules
  - Run during maintenance windows

**Example Safe Configuration**:
```bash
# Safe for production (slower, less aggressive)
mcp-verify fuzz "https://api.example.com" \
  --tool my-tool \
  --concurrency 1 \
  --delay 1000 \
  --timeout 30000
```

### Second-Order Vulnerabilities

**Limitation**: mcp-verify **cannot detect vulnerabilities that manifest later** (stored XSS, delayed injection).

The fuzzer checks immediate responses only. If a malicious payload is stored and executed when another user accesses it, mcp-verify will NOT detect it.

**Example**:
```typescript
// Fuzzer sends
{ comment: '<script>alert(1)</script>' }

// Server responds (STORED, not executed yet)
{ success: true, id: '12345' }

// mcp-verify sees: No error → No vulnerability detected

// Later: Another user views the comment → XSS executes
// mcp-verify MISSED this (second-order vulnerability)
```

**Mitigation**:
- Perform **manual penetration testing** for stored data scenarios
- Use **dynamic application security testing (DAST)** tools for runtime analysis
- Implement **content security policy (CSP)** to mitigate stored XSS

### Rate Limiting and Server Behavior

**Limitation**: Servers with **always-successful responses** (e.g., always return `200 OK`) may hide vulnerabilities.

mcp-verify relies on response patterns to detect vulnerabilities (errors, timing differences). Servers that return success codes even for invalid input can produce false negatives.

**Example**:
```typescript
// Fuzzer sends SSRF payload
{ url: 'http://169.254.169.254/latest/meta-data/' }

// Vulnerable server (but hides it)
{ success: true, result: 'Data fetched' }  // ← Always 200 OK

// mcp-verify sees: Success → No vulnerability detected
// Reality: Server fetched AWS metadata → SSRF exists but hidden
```

**Mitigation**:
- Review application logs for suspicious outbound requests
- Use **traffic monitoring** (Wireshark, Burp Suite) during fuzzing
- Test with verbose error messages enabled (in staging only)

---

## Security Boundaries

### What mcp-verify Controls

| Component | Control Level | Description |
|-----------|---------------|-------------|
| Static Analysis Rules | **Full Control** | We define detection patterns |
| Report Generation | **Full Control** | JSON/SARIF/HTML outputs |
| CLI Interface | **Full Control** | Command-line behavior |
| MCP Server Interface | **Full Control** | Tool schemas and responses |

### What mcp-verify Does NOT Control

| Component | Control Level | Description |
|-----------|---------------|-------------|
| Tested MCP Servers | **No Control** | We analyze external servers |
| Claude Desktop Keychain | **No Control** | Managed by Anthropic |
| User's Environment Variables | **No Control** | User responsibility |
| Network Security | **No Control** | HTTPS, firewalls, etc. |
| Runtime Exploits | **No Control** | Dynamic vulnerabilities |

### Responsibility Matrix

| Scenario | Responsible Party |
|----------|-------------------|
| mcp-verify reports false positive | **mcp-verify (Fink)** - Report as bug |
| mcp-verify misses a vulnerability | **mcp-verify (Fink)** - Report as enhancement |
| Tested server is exploited despite 100/100 score | **Server Developer** - mcp-verify analyzes statically |
| API key leaked via environment variable | **User** - Secure your environment |
| Claude Desktop keychain compromised | **Anthropic** - Not controlled by mcp-verify |
| Network interception of API key | **User** - Use HTTPS, secure networks |

---

## Test Servers

mcp-verify includes **intentionally vulnerable test servers** for validation:

### Location

```
tools/mocks/servers/
├── simple-server.js      # Clean server (should score 95+)
├── vulnerable-server.js  # Vulnerable server (should score <50)
└── broken-server.js      # Protocol violations (should fail)
```

### Purpose

1. **simple-server.js**: Demonstrates best practices (reference implementation)
2. **vulnerable-server.js**: Contains SQL injection, command injection, SSRF, etc. (tests detection)
3. **broken-server.js**: Invalid JSON-RPC responses (tests protocol compliance)

### ⚠️ WARNING: Do NOT Use in Production

These servers are **INTENTIONALLY INSECURE** for testing purposes:

- ❌ **DO NOT** deploy `vulnerable-server.js` anywhere
- ❌ **DO NOT** copy code from `vulnerable-server.js`
- ❌ **DO NOT** use as templates for real servers
- ✅ **DO** use `simple-server.js` as a reference for best practices

---

## Reporting Vulnerabilities

### Vulnerabilities in mcp-verify Itself

If you find a security vulnerability in mcp-verify:

1. **Do NOT open a public GitHub issue**
2. Email: security@your-domain.com (replace with actual email)
3. Include:
   - Description of vulnerability
   - Steps to reproduce
   - Impact assessment
   - Proof of concept (if available)

We will respond within **48 hours** and provide a fix within **7 days** for critical issues.

### Vulnerabilities in Tested Servers

If mcp-verify **fails to detect** a known vulnerability:

1. Open a GitHub issue: https://github.com/FinkTech/mcp-verify/issues
2. Tag with: `security`, `false-negative`
3. Include:
   - Server code or description
   - Vulnerability type (SQL injection, SSRF, etc.)
   - Expected detection rule
   - Actual mcp-verify output

### False Positives

If mcp-verify **incorrectly flags** safe code:

1. Open a GitHub issue: https://github.com/FinkTech/mcp-verify/issues
2. Tag with: `security`, `false-positive`
3. Include:
   - Server code or description
   - Why the finding is incorrect
   - Expected behavior

---

## Security Best Practices

When using mcp-verify:

### ✅ DO

- ✅ Use mcp-verify as **one layer** in a defense-in-depth strategy
- ✅ Combine with manual code review
- ✅ Run in CI/CD pipelines before deployment
- ✅ Review all findings manually
- ✅ Use HTTPS for API calls
- ✅ Secure environment variables
- ✅ Rotate API keys regularly

### ❌ DON'T

- ❌ Rely solely on mcp-verify for security
- ❌ Assume 100/100 score means "perfectly secure"
- ❌ Deploy servers without manual review
- ❌ Commit API keys to version control
- ❌ Use test servers in production
- ❌ Ignore low-severity findings

---

## Conclusion

mcp-verify is a **security validation tool**, not a **security guarantee**. It helps identify known vulnerability patterns through static analysis, but cannot replace human judgment, manual code review, or comprehensive security testing.

**Use mcp-verify as part of a broader security strategy, not as a replacement for it.**

For questions, open a GitHub issue: https://github.com/FinkTech/mcp-verify/issues

---

**Last Updated**: 2026-02-24
**Version**: 1.0.0
