# @mcp-verify/core — Agent Context

**Mission**: Domain library for MCP security validation, quality analysis, and reporting. Clean architecture, framework-agnostic, 60 security rules.

---

## Quick Start

1. Identify what to modify:
   - Security rules → `domain/security/rules/` (60 rules, plugin pattern)
   - Report formats → `domain/reporting/` (5 formats)
   - LLM providers → `domain/quality/providers/` (4 providers)
   - Transports → `domain/transport.ts` (3 transports)
2. Domain layer has **zero framework dependencies** — 100% unit testable without mocks
3. `cd libs/core && npm test`

---

## Architecture (3 Layers)

```
USE CASES       MCPValidator · SecurityScanner · Fuzzer · ProxyServer
                StressTester · ProtocolTester · PlaygroundExecutor
────────────────────────────────────────────────────────────────────
DOMAIN          Security Rules (60) · Report Generators · Quality Analyzers
                Transport Interfaces · Config Types
────────────────────────────────────────────────────────────────────
INFRASTRUCTURE  Logger · ErrorHandler · ConfigManager · HealthMonitor
```

---

## Security Rules (60 — 6 Blocks)

**Location**: `domain/security/rules/*.rule.ts` | **Orchestrator**: `SecurityScanner` in `domain/security/security-scanner.ts`

**Interface**:
```typescript
interface ISecurityRule {
  code: string;           // SEC-001 format
  severity: 'critical' | 'high' | 'medium' | 'low';
  evaluate(discovery: DiscoveryResult): SecurityFinding[];
}
```

### Block OWASP (13 rules)
| Rule | OWASP | Detection |
|---|---|---|
| SQL Injection | A03:2021 | Pattern matching, schema analysis |
| Command Injection | A03:2021 | Shell metacharacter detection |
| SSRF | A10:2021 | URL validation, network patterns |
| Path Traversal | A01:2021 | Directory traversal patterns |
| Data Leakage | A01:2021 | PII/key pattern detection |
| XXE Injection | A05:2021 | XML entity expansion |
| Insecure Deserialization | A08:2021 | Unsafe serialization patterns |
| Weak Cryptography | A02:2021 | Weak algorithm detection |
| Auth Bypass | A07:2021 | Auth logic analysis, JWT |
| Sensitive Exposure | A02:2021 | Hardcoded secrets |
| Rate Limiting | A04:2021 | Missing rate limit headers |
| ReDoS | A04:2021 | Regex complexity analysis |
| Prompt Injection | Emerging | LLM prompt patterns |

### Block MCP (8 rules)
Dangerous Tool Chaining · Excessive Permissions · Exposed Endpoint · Insecure URI Scheme · Missing Authentication · Missing Input Constraints · Secrets in Descriptions · Unencrypted Credentials

### Block A — OWASP LLM Top 10 in MCP Context (9 rules)
Excessive Agency · Prompt Injection via Tools · Insecure Output Handling · Supply Chain Tool Dependencies · Sensitive Data in Tool Responses · Training Data Poisoning · Model DoS via Tools · Insecure Plugin Design · Excessive Data Disclosure

### Block B — Multi-Agent & Agentic Attacks (11 rules)
Tool Result Tampering · Recursive Agent Loop · Multi-Agent Privilege Escalation · Agent State Poisoning · Distributed Agent DDoS · Agent Swarm Coordination · Agent Identity Spoofing · Cross-Agent Prompt Injection · Agent Reputation Hijacking · Tool Chaining Path Traversal · Agent Memory Injection

### Block C — Operational & Enterprise Compliance (9 rules)
Missing Audit Logging · Insecure Session Management · Exposed Endpoint · Insecure Default Config · Missing CORS Validation · Schema Versioning Absent · Missing Capability Negotiation · Timing Side-Channel in Auth · Insufficient Output Entropy

### Block D — AI Weaponization & Supply Chain (10 rules) ⚠️ disabled by default
Weaponized MCP Fuzzer · Autonomous MCP Backdoor · Malicious Config File · API Endpoint Hijacking · Jailbreak-as-a-Service · Phishing via MCP · Data Exfiltration via Steganography · Self-Replicating MCP · Unvalidated Tool Authorization · Missing Transaction Semantics

---

## Transport Layer (3)

| Transport | Protocol | Use Case |
|---|---|---|
| `StdioTransport` | stdin/stdout | CLI, MCP Server |
| `HttpTransport` | HTTP/REST | Web Dashboard, API |
| `SSETransport` | Server-Sent Events | Real-time streaming |

All transports: timeout enforced (default 120s) · auto-retry on transient errors · graceful cleanup required.

---

## Reporting (5 Formats)

| Format | File | Purpose |
|---|---|---|
| HTML | `html-generator.ts` | Interactive reports with charts |
| Markdown | `markdown-generator.ts` | GitHub-compatible docs |
| SARIF | `sarif-generator.ts` | GitHub Code Scanning integration |
| JSON | `enhanced-reporter.ts` | Structured data for parsing |
| Text | `text-generator.ts` | Plain-text CLI output |

**Orchestrator**: `EnhancedReporter` — single call, multi-format output.
**i18n**: 30+ languages in `domain/reporting/i18n.ts`.

---

## Quality Analysis — LLM Providers (4)

| Provider | File | Models |
|---|---|---|
| Anthropic | `anthropic-provider.ts` | claude-3-5-sonnet-20241022 |
| OpenAI | `openai-provider.ts` | gpt-4o, gpt-4-turbo |
| Ollama | `ollama-provider.ts` | llama2, mistral, codellama |
| Gemini | `gemini-provider.ts` | gemini-1.5-pro, gemini-1.5-flash |

**Orchestrator**: `LLMSemanticAnalyzer` in `quality/llm-semantic-analyzer.ts`.
**Scoring weights**: Documentation 40% · Naming 30% · Clarity 20% · Completeness 10%.

---

## Use Cases (7)

| Use Case | File | Key Method |
|---|---|---|
| `MCPValidator` | `validator/validator.ts` | `validate(): Promise<ValidationReport>` |
| `SecurityScanner` | integrated in Validator | `scan(ctx): Promise<SecurityFinding[]>` |
| `Fuzzer` | `fuzzer/fuzzer.ts` | `fuzz(tool, payloads): Promise<FuzzResult>` |
| `ProxyServer` | `proxy/proxy-server.ts` | `start(): Promise<void>` — 5 guardrails |
| `StressTester` | `stress-tester/stress-tester.ts` | `run(config): Promise<StressReport>` |
| `ProtocolTester` | `protocol-tester/protocol-tester.ts` | `test(): Promise<ProtocolReport>` |
| `PlaygroundExecutor` | `playground/playground-executor.ts` | `execute(script): Promise<Result>` |

---

## Extension Guide

**Add security rule**: Create `rules/my-rule.rule.ts` implementing `ISecurityRule` → export from `rules/index.ts` → register in `SecurityScanner.SECURITY_RULES[]`.

**Add report format**: Create `reporting/my-generator.ts` with `generate(report): Promise<string>` → export from `reporting/index.ts` → add case to `EnhancedReporter.generateReport()`.

**Add LLM provider**: Create `quality/providers/my-provider.ts` implementing `ILLMProvider` → export from `providers/index.ts` → add case to `LLMSemanticAnalyzer.getProvider()`.

**Add i18n language**: Edit `reporting/i18n.ts` → copy `en` block → translate all keys → add code to `Language` type.

---

## Testing

```bash
cd libs/core && npm test
npm test -- --coverage
npm test -- domain/security/rules/sql-injection.rule.spec.ts
npm test -- use-cases/
```

| Layer | Min coverage |
|---|---|
| Security rules | **100%** — test vulnerable + safe path per rule |
| Domain layer | 80% — no mocks needed (pure logic) |
| Use cases | 60% — mock transports and LLM providers |
| Infrastructure | 50% |

---

**Last Updated**: 2026-03-31 | Maintainer: @FinkTech via Claude Code
