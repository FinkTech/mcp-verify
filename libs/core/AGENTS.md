# @mcp-verify/core - Domain Library

> Enterprise-grade security validation, quality analysis, and reporting
> Three-layer clean architecture, framework-agnostic, 60 security rules

---

## Quick Start (5 Minutes)

1. Read this file (core library architecture overview)
2. Identify which component to modify:
   - Security rules → `domain/security/rules/` (60 rules)
   - Report formats → `domain/reporting/` (5 formats)
   - LLM providers → `domain/quality/providers/` (4 providers)
   - Transports → `domain/transport.ts` (3 transports)
3. Follow clean architecture layers (Domain → Infrastructure → Use Cases)
4. Test: `cd libs/core && npm test`

---

## Architecture (3 Layers)

```
┌─────────────────────────────────────────────────────────┐
│             USE CASES LAYER                             │
│  MCPValidator, SecurityScanner, Fuzzer, ProxyServer    │
│  StressTester, ProtocolTester, PlaygroundExecutor      │
├─────────────────────────────────────────────────────────┤
│             DOMAIN LAYER (Pure Business Logic)          │
│  Security Rules (60 total), Report Generators,         │
│  Quality Analyzers, Transport Interfaces, Config Types │
├─────────────────────────────────────────────────────────┤
│             INFRASTRUCTURE LAYER                         │
│  Logger, Error Handler, Config Manager, Health Monitor │
└─────────────────────────────────────────────────────────┘
```

**Key principle**: Domain layer has **zero framework dependencies**. 100% unit testable without mocks.

---

## Security Rules (60 Total - 6 Blocks)

**Location**: `libs/core/domain/security/rules/*.rule.ts`

**Organization**: Rules organized in 6 threat category blocks (OWASP, MCP, A, B, C, D)

### Block OWASP: OWASP Top 10 Aligned (13 rules)
| Rule | OWASP | Detection |
|------|-------|-----------|
| SQL Injection | A03:2021 | Pattern matching, schema analysis |
| Command Injection | A03:2021 | Shell metacharacter detection |
| SSRF | A10:2021 | URL validation, network patterns |
| Data Leakage | A01:2021 | PII/key pattern detection |
| Path Traversal | A01:2021 | Directory traversal patterns |
| XXE Injection | A05:2021 | XML entity expansion |
| Insecure Deserialization | A08:2021 | Unsafe serialization |
| Weak Cryptography | A02:2021 | Weak algorithm detection |
| Auth Bypass | A07:2021 | Auth logic analysis, JWT |
| Sensitive Exposure | A02:2021 | Hardcoded secrets |
| Rate Limiting | A04:2021 | Missing rate limit headers |
| ReDoS | A04:2021 | Regex complexity analysis |
| Prompt Injection | Emerging | LLM prompt patterns |

### Block MCP: MCP-Specific Rules (8 rules)
| Rule | Category | Detection |
|------|----------|-----------|
| Dangerous Tool Chaining | MCP Security | Tool composition abuse patterns |
| Excessive Permissions | MCP Security | Over-privileged tool definitions |
| Exposed Endpoint | MCP Security | Unintended endpoint exposure |
| Insecure URI Scheme | MCP Security | Non-HTTPS/insecure schemes |
| Missing Authentication | MCP Security | Auth requirement gaps |
| Missing Input Constraints | MCP Security | Unbounded input parameters |
| Secrets in Descriptions | MCP Security | Credentials in metadata |
| Unencrypted Credentials | MCP Security | Plaintext credential storage |

### Block A: OWASP LLM Top 10 in MCP Context (9 rules)
- Excessive Agency, Prompt Injection via Tools, Insecure Output Handling
- Supply Chain Tool Dependencies, Sensitive Data in Tool Responses
- Training Data Poisoning, Model DoS via Tools, Insecure Plugin Design
- Excessive Data Disclosure

### Block B: Multi-Agent & Agentic Attacks (11 rules)
- Tool Result Tampering, Recursive Agent Loop, Multi-Agent Privilege Escalation
- Agent State Poisoning, Distributed Agent DDoS, Agent Swarm Coordination
- Agent Identity Spoofing, Cross-Agent Prompt Injection
- Agent Reputation Hijacking, Tool Chaining Path Traversal, Agent Memory Injection

### Block C: Operational & Enterprise Compliance (9 rules)
- Missing Audit Logging, Insecure Session Management, Exposed Endpoint
- Insecure Default Configuration, Missing CORS Validation, Schema Versioning Absent
- Missing Capability Negotiation, Timing Side-Channel in Auth, Insufficient Output Entropy

### Block D: AI Weaponization & Supply Chain MCP (10 rules)
> **Note**: Most rules in this block are **disabled by default** for safety reasons.
- Weaponized MCP Fuzzer, Autonomous MCP Backdoor, Malicious Config File
- API Endpoint Hijacking, Jailbreak-as-a-Service, Phishing via MCP
- Data Exfiltration via Steganography, Self-Replicating MCP
- Unvalidated Tool Authorization, Missing Transaction Semantics

**Rule Interface**:
```typescript
interface ISecurityRule {
  id: string;           // SEC-001, SEC-002, etc.
  name: string;         // Human-readable name
  severity: 'critical' | 'high' | 'medium' | 'low';
  check(context: ServerContext): Promise<SecurityFinding[]>;
}
```

**Orchestrator**: `SecurityScanner` in `domain/security/security-scanner.ts`

---

## Reporting Formats (5 Formats)

**Location**: `libs/core/domain/reporting/`

| Format | File | Purpose |
|--------|------|---------|
| HTML | `html-generator.ts` | Rich interactive reports with charts |
| Markdown | `markdown-generator.ts` | GitHub-compatible documentation |
| SARIF | `sarif-generator.ts` | GitHub Code Scanning integration |
| JSON | `enhanced-reporter.ts` | Structured data for parsing |
| Text | `text-generator.ts` | Plain-text CLI output |

**i18n Support**: 30+ languages in `i18n.ts` (en, es, fr, de, ja, zh, etc.)

**Orchestrator**: `EnhancedReporter` handles multi-format generation with single call.

---

## Transport Layer (3 Transports)

**Location**: `libs/core/domain/transport.ts`

| Transport | Protocol | Use Case |
|-----------|----------|----------|
| StdioTransport | stdio (stdin/stdout) | CLI, MCP Server |
| HttpTransport | HTTP/REST | Web Dashboard, API |
| SSETransport | Server-Sent Events | Real-time streaming |

**Interface**:
```typescript
interface ITransport {
  connect(): Promise<void>;
  send(message: unknown): Promise<void>;
  receive(): Promise<unknown>;
  disconnect(): Promise<void>;
}
```

**Key behavior**: All transports enforce timeout (default 120s), auto-retry on transient errors, and graceful cleanup.

---

## Quality Analysis (4 LLM Providers)

**Location**: `libs/core/domain/quality/providers/`

| Provider | File | Model Examples |
|----------|------|----------------|
| Anthropic | `anthropic-provider.ts` | claude-3-5-sonnet-20241022 |
| OpenAI | `openai-provider.ts` | gpt-4o, gpt-4-turbo |
| Ollama | `ollama-provider.ts` | llama2, mistral, codellama |
| Gemini | `gemini-provider.ts` | gemini-1.5-pro, gemini-1.5-flash |

**Orchestrator**: `LLMSemanticAnalyzer` in `quality/llm-semantic-analyzer.ts`

**What it analyzes**:
- Tool/resource/prompt naming conventions
- Description completeness and clarity
- Parameter documentation quality
- Best practices vs. anti-patterns

**Weighted scoring**: Documentation 40%, Naming 30%, Clarity 20%, Completeness 10%

---

## Use Cases Layer (7 Core)

**Location**: `libs/core/use-cases/`

### 1. Validator (`validator/validator.ts`)
Full MCP protocol validation (handshake, discovery, schema, security, quality).

**Key method**: `validate(): Promise<ValidationReport>`

---

### 2. SecurityScanner (integrated in Validator)
Runs all 60 security rules (13 OWASP + 8 MCP + 39 advanced threats (LLM Top 10, Multi-Agent, Compliance, Weaponization)) and generates security findings.

**Key method**: `scan(context): Promise<SecurityFinding[]>`

---

### 3. Fuzzer (`fuzzer/fuzzer.ts`)
Intelligent payload generation with feedback loops and mutation.

**Key method**: `fuzz(tool, payloads): Promise<FuzzResult>`

**Detectors**: Error detection, timing analysis, data leakage, crash detection.

---

### 4. ProxyServer (`proxy/proxy-server.ts`)
Security proxy with 5 guardrails (HTTPS enforcement, rate limiting, input sanitization, PII redaction, sensitive command blocking).

**Key method**: `start(): Promise<void>`

---

### 5. StressTester (`stress-tester/stress-tester.ts`)
Load and concurrency testing with configurable RPS, duration, and concurrency.

**Key method**: `stress(config): Promise<StressResult>`

---

### 6. ProtocolTester (`compliance/protocol-tester.ts`)
MCP 2024-11-05 spec compliance testing.

**Key method**: `testCompliance(): Promise<ComplianceReport>`

---

### 7. PlaygroundExecutor (`playground/tool-executor.ts`)
Interactive tool execution for testing.

**Key method**: `execute(tool, args): Promise<ToolResult>`

---

## Infrastructure Layer

**Location**: `libs/core/infrastructure/`

### Logger (`logging/logger.ts`)
- Scoped loggers per module
- Audit trail for security events
- File + console output
- Redacts secrets automatically

### Config Manager (`config/config-manager.ts`)
- Loads from `mcp-verify.config.json` (cwd or ancestors)
- Validates with Zod schema
- Merges CLI flags > env vars > config file > defaults

### Error Handler (`errors/error-handler.ts`)
- `ValidationError`, `NetworkError`, `TimeoutError`
- User-facing errors use i18n `t()`
- Technical errors go to logger

### Health Monitor (`monitoring/health-check.ts`)
- Node.js version check
- Git availability
- Deno runtime (if needed)
- MCP SDK compatibility

---

## Critical Patterns

### Timeout Enforcement
All async operations have strict timeouts:
- **Handshake**: 10s
- **Tool execution**: 30s
- **Validation**: 120s
- **Fuzzing**: 300s
- **Stress test**: 600s

**Implementation**: `AbortController` with `setTimeout()` for all network/subprocess calls.

---

### Atomic File Operations
All file writes use atomic pattern:
1. Write to `.tmp` file
2. `fs.renameSync(tmpPath, targetPath)` (atomic at OS level)
3. On error, cleanup `.tmp` file

**Files**: Reports, history, session state, baselines.

---

### Secret Redaction
Before persistence or logging:
- Redact API keys (`--api-key`, `--token`, etc.)
- Redact passwords (`--password`, `--secret`, etc.)
- Redact URLs with credentials (`https://user:pass@host`)
- Pattern: `--secret-flag [REDACTED]`

**Implementation**: `redactSecrets()` in `ShellSession` and `logger`.

---

## Modifying the Core Library

**Add new security rule**:
1. Create `domain/security/rules/my-rule.rule.ts`
2. Implement `ISecurityRule` interface
3. Export from `domain/security/rules/index.ts`
4. Add to `SECURITY_RULES` array in `security-scanner.ts`
5. Current count: 60 rules (assign SEC-061, SEC-062, etc. for new rules)

**Add new report format**:
1. Create `domain/reporting/my-format-generator.ts`
2. Implement `generate(report): Promise<string>` function
3. Export from `domain/reporting/index.ts`
4. Add to `EnhancedReporter.generateReport()` switch case

**Add new LLM provider**:
1. Create `domain/quality/providers/my-provider.ts`
2. Implement `ILLMProvider` interface
3. Export from `domain/quality/providers/index.ts`
4. Add to `LLMSemanticAnalyzer.getProvider()` switch case

**Add new i18n language**:
1. Edit `domain/reporting/i18n.ts`
2. Add new language code to `translations` object
3. Copy `en` translations and translate all keys
4. Export new language from `Language` type

---

## Troubleshooting

### Security rule not triggering
- **Check**: Is rule registered in `SecurityScanner.SECURITY_RULES` array?
- **Check**: Is rule exported from `rules/index.ts`?
- **Check**: Does `check()` method return findings for vulnerable code?
- **Debug**: Add `console.log` at start of `check()` to verify execution
- **Debug**: Test rule standalone with known vulnerable context

### Transport connection failing
- **Check**: Is target server running and accessible?
- **Check**: Is command/args correct? (test manually: `node server.js`)
- **Check**: Are timeouts sufficient? (default: 120s)
- **Fix**: Check server logs for startup errors
- **Debug**: Run with `DEBUG=mcp-verify:transport:*` for transport logs

### Report generation fails
- **Check**: Is output directory writable?
- **Check**: Is report format valid? (html, md, json, sarif, text)
- **Check**: Is i18n language valid? (en, es, fr, etc.)
- **Fix**: Check for missing translation keys in `i18n.ts`
- **Debug**: Add breakpoint in `EnhancedReporter.generateReport()`

### LLM provider errors
- **Check**: Is API key set? (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, etc.)
- **Check**: Is provider name valid? (anthropic, openai, ollama, gemini)
- **Check**: Is model name correct for provider?
- **Fix**: Test API key manually: `curl -H "x-api-key: $KEY" https://api.anthropic.com/v1/messages`
- **Debug**: Check error message for rate limits, invalid keys, or model unavailability

### Fuzzer not detecting vulnerabilities
- **Check**: Are detectors registered in `FuzzerEngine`?
- **Check**: Is baseline calibration working? (first 10 payloads)
- **Check**: Are anomaly thresholds too strict? (2x response time, 3x size)
- **Fix**: Lower thresholds in detector configuration
- **Debug**: Add `console.log` in detector `detect()` methods

### Timeout errors
- **Check**: Is operation genuinely slow or hanging?
- **Check**: Is timeout value appropriate for operation?
- **Fix**: Increase timeout for slow servers: `{ timeout: 300000 }` (5 min)
- **Fix**: Use `AbortController` for all async operations
- **Debug**: Check if cleanup is called on timeout

### Config loading fails
- **Check**: Is `mcp-verify.config.json` valid JSON?
- **Check**: Is config in cwd or parent directories?
- **Check**: Does config schema match Zod validation?
- **Fix**: Run `npx mcp-verify doctor` to validate config
- **Debug**: Add `console.log` in `ConfigManager.loadConfig()`

### i18n translation missing
- **Check**: Is language code valid? (check `Language` type in `i18n.ts`)
- **Check**: Is translation key present in `en` translations?
- **Check**: Did you add the key to all languages or just one?
- **Fix**: Add missing key to `translations[lang]` object
- **Debug**: Check console for "Missing translation: ..." warnings

### Memory leaks in stress tests
- **Check**: Is `cleanup()` called after each test?
- **Check**: Are event listeners removed? (transport, fuzzer)
- **Check**: Are timers cleared? (`clearTimeout`, `clearInterval`)
- **Fix**: Use `try/finally` to ensure cleanup always runs
- **Debug**: Run with `node --trace-warnings` to detect leaks

### Cross-package imports not working
- **Check**: Are you using `@mcp-verify/*` package names? (not relative paths)
- **Check**: Did you run `npm install` in monorepo root?
- **Check**: Is package exported in `libs/*/package.json`?
- **Fix**: Rebuild workspace: `npm run build`
- **Debug**: Check `node_modules/@mcp-verify/` symlinks

---

## Testing

```bash
# Unit tests (domain layer - zero framework dependencies)
cd libs/core && npm test

# Test specific security rule
npm test -- domain/security/rules/sql-injection.rule.spec.ts

# Test specific report format
npm test -- domain/reporting/sarif-generator.spec.ts

# Test specific LLM provider
npm test -- domain/quality/providers/anthropic-provider.spec.ts

# Integration tests (use cases layer)
npm test -- use-cases/

# Watch mode
npm test -- --watch

# Coverage report (aim for 80%+ domain layer, 60%+ use cases)
npm test -- --coverage
```

**Test scenarios**:
1. **Security Rules**: Each rule with vulnerable/safe code patterns, edge cases
2. **Report Generators**: Validate output structure, i18n, edge cases (empty reports)
3. **Transports**: Connection, send/receive, timeout, cleanup, error recovery
4. **Quality Analyzers**: LLM provider mocking, scoring validation, retry logic
5. **Use Cases**: Full validation flow, fuzzing feedback loop, stress test metrics

**Example test (Security Rule)**:
```typescript
import { SQLInjectionRule } from '../rules/sql-injection.rule';
import type { ServerContext } from '../types';

describe('SQLInjectionRule', () => {
  let rule: SQLInjectionRule;

  beforeEach(() => {
    rule = new SQLInjectionRule();
  });

  it('should detect SQL injection in tool description', async () => {
    const context: ServerContext = {
      tools: [{
        name: 'query_database',
        description: 'Execute SQL: SELECT * FROM users WHERE id = ' + userId,
        inputSchema: {}
      }]
    };

    const findings = await rule.check(context);

    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].ruleId).toBe('SEC-001');
    expect(findings[0].message).toContain('SQL injection');
  });

  it('should not flag parameterized queries', async () => {
    const context: ServerContext = {
      tools: [{
        name: 'query_database',
        description: 'Execute SQL with parameterized query',
        inputSchema: {}
      }]
    };

    const findings = await rule.check(context);

    expect(findings).toHaveLength(0);
  });
});
```

**Example test (Report Generator)**:
```typescript
import { SarifGenerator } from '../reporting/sarif-generator';
import type { ValidationReport } from '../types';

describe('SarifGenerator', () => {
  it('should generate valid SARIF 2.1.0 output', async () => {
    const report: ValidationReport = {
      securityFindings: [{
        ruleId: 'SEC-001',
        severity: 'critical',
        message: 'SQL injection detected',
        location: { file: 'server.js', line: 42 }
      }]
    };

    const sarif = await SarifGenerator.generate(report);
    const parsed = JSON.parse(sarif);

    expect(parsed.version).toBe('2.1.0');
    expect(parsed.$schema).toContain('sarif-schema-2.1.0.json');
    expect(parsed.runs[0].results).toHaveLength(1);
    expect(parsed.runs[0].results[0].level).toBe('error');
  });
});
```

**Critical testing requirements**:
- Domain layer: 80%+ coverage (pure business logic, no mocks needed)
- Use cases: 60%+ coverage (mocks for transports, LLMs, file I/O)
- Infrastructure: 50%+ coverage (real file system, network calls)
- All security rules: 100% coverage (critical for security validation)

---

**Last Updated**: 2026-03-26
