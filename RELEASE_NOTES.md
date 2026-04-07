# 🛡️ MCP Verify v1.0.0 — The Birth of MCP Security

**Release Date:** TBD  
**License:** AGPL-3.0  
**Author:** Ariel A. Fink — [FinkTech](https://github.com/FinkTech)

---

The MCP ecosystem just got its first enterprise-grade security scanner. **mcp-verify v1.0.0** ships with **60 security rules**, a **Smart Fuzzer** that learns from live server responses, an interactive shell built for professionals, and a reporting engine that turns vulnerability data into surgical-precision visual intelligence. Whether you're shipping MCP servers to production or vetting third-party integrations, this is the tool that stands between your infrastructure and the next zero-day.

---

## 🔐 60 Security Rules — 6 Threat Categories

The most comprehensive rule engine ever built for the Model Context Protocol.

| Block            | Category                        | Rules                  | Highlights                                                                |
| ---------------- | ------------------------------- | ---------------------- | ------------------------------------------------------------------------- |
| **OWASP Core**   | OWASP Top 10 Aligned            | SEC-001 → SEC-013 (13) | SQL/CMD Injection, SSRF, XXE, Path Traversal, Prompt Injection            |
| **MCP-Specific** | Protocol-Native Threats         | SEC-014 → SEC-021 (8)  | Exposed Endpoints, Dangerous Tool Chaining, Unencrypted Credentials       |
| **Block A**      | OWASP LLM Top 10                | SEC-022 → SEC-030 (9)  | Excessive Agency, Supply Chain Dependencies, Model DoS                    |
| **Block B**      | Multi-Agent Attacks             | SEC-031 → SEC-041 (11) | Agent Swarm Coordination, Identity Spoofing, Cross-Agent Prompt Injection |
| **Block C**      | Enterprise Compliance           | SEC-042 → SEC-050 (9)  | Audit Logging, Session Management, Timing Side-Channels                   |
| **Block D**      | AI Weaponization & Supply Chain | SEC-051 → SEC-060 (10) | CVE-2025-59536, CVE-2026-21852, Self-Replicating MCP Detection            |

Every rule maps to an industry standard. Every finding scores on a 0–100 Unified Scoring Engine.

---

## 🎮 Interactive Shell (REPL)

A professional workspace, not a toy CLI.

- **Contextual Autocomplete** — Tab-complete commands, flags, file paths, and tool names
- **Multi-Context Workspaces** — Switch between `dev`, `staging`, and `prod` with isolated targets, profiles, and configs
- **Security Profiles** — `light` (CI/CD, 25 payloads), `balanced` (default, 50), `aggressive` (audits, 100)
- **Custom Profiles** — Save your own preset and share it across projects
- **Session Persistence** — State saved to `.mcp-verify/session.json`; secrets **never** persisted
- **Secret Redaction** — API keys automatically scrubbed from history
- **Output Redirection** — `validate > report.txt` or `fuzz >> results.log`

```
[staging] mcp-verify (balanced) https://staging.example.com/mcp >
```

---

## 🧬 Smart Fuzzer v1.0

An adaptive security testing engine that learns while it attacks.

| Capability                    | Detail                                                                                                                                                                                                |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Feedback Loop**             | Detects interesting responses (timing anomalies, crashes, structural drift) and auto-generates targeted mutations                                                                                     |
| **12 Mutation Strategies**    | SQL depth, null-byte injection, unicode bypass, timing probes, buffer stress, quote variation, case mutation, encoding bypass, polyglot payloads, recursive nesting, type confusion, boundary probing |
| **8 Payload Generators**      | Prompt Injection, SQL/XSS/CMD Injection, JWT Attacks, Prototype Pollution, JSON-RPC Violations, Schema Confusion, Path Traversal, Time-Based                                                          |
| **9 Vulnerability Detectors** | Timing anomalies, error disclosure, XSS reflection, prompt leaks, jailbreak success, path traversal, weak IDs, info disclosure, protocol violation                                                    |
| **Automatic Fingerprinting**  | Detects server language/framework and disables irrelevant generators (saves 40–60% execution time)                                                                                                    |
| **Schema-Aware Fuzzing**      | Parses tool JSON Schemas to generate 150–250+ targeted payloads per tool — type confusion, boundary violations, enum bypass, format-specific attacks                                                  |

```
Smart Fuzzer v1.0
──────────────────────────────────────────────────
Payloads  : 250/280
Vulns     : 3 (2 critical, 1 high)
Mutations : 45 injected across 2 rounds
Timing anomalies : 5
```

---

## 🏗️ Infrastructure 2.0

Enterprise-grade internals built for reliability at scale.

- **🔒 Build Integrity v2** — SHA-256 verification of CLI & Server binaries, with history tracking of last 20 builds and Git commit traceability
- **📋 Rotation-Ready JSONL Logging** — Structured security events to stderr, ready for Datadog, CloudWatch, ELK, or file-based rotation
- **✅ Full Zod Configuration Validation** — Every config field validated at parse time; no runtime surprises
- **🧱 Clean Architecture** — Hexagonal (Ports & Adapters) with strict layers: Domain → Use Cases → Infrastructure → Apps
- **🧪 549 Unit Tests Passing** — ~80% coverage across domain, use-cases, infrastructure, and application layers
- **🔄 Atomic File Operations** — Crash-safe writes for integrity history and session state

---

## 🔬 Surgical Glass Reporting

Reports so clear they double as executive briefings.

| Format          | Use Case                                                                               |
| --------------- | -------------------------------------------------------------------------------------- |
| **HTML**        | High-aesthetic interactive reports with visual **Attack Chains** and **Risk Heatmaps** |
| **JSON**        | Machine-readable for CI/CD pipelines and automation                                    |
| **SARIF 2.1.0** | GitHub Security tab integration                                                        |
| **Markdown**    | GitHub-friendly, PR-embeddable summaries                                               |
| **SVG Badges**  | shields.io-format badges for your README                                               |

Scores map to clear operational tiers: **≥ 90** Production · **≥ 70** Staging · **≥ 50** Internal Tools.

---

## 🛡️ Anti-Weaponization Engine

Real-time detection of malicious configuration patterns and adversarial MCP abuse.

- **CVE-2025-59536** — Malicious Config File injection via poisoned `mcp-verify.config.json`
- **CVE-2026-21852** — API Endpoint Hijacking through crafted MCP server manifests
- **Self-Replicating MCP Detection** (SEC-058) — Identifies servers attempting autonomous propagation
- **Autonomous Backdoor Detection** (SEC-052) — Catches hidden persistence mechanisms in MCP servers
- **Jailbreak-as-a-Service Detection** (SEC-055) — Flags servers designed to bypass LLM guardrails

> ⚠️ Block D rules (SEC-051 to SEC-060) are **disabled by default** due to their adversarial nature. Enable with caution in controlled environments only. Three rules (SEC-054, SEC-059, SEC-060) ship enabled for passive defense.

---

## 🛡️ Security Gateway v1.0 (Runtime Protection)

Real-time threat detection that sits between AI agents and MCP servers.

### 3-Layer Progressive Defense

| Layer                         | Type               | Latency    | Detection Method                                          | Cost (approx.)      |
| ----------------------------- | ------------------ | ---------- | --------------------------------------------------------- | ------------------- |
| **Layer 1: Fast Rules**       | Pattern-based      | <10ms      | Regex + hardcoded patterns (SQL, CMD injection)           | $0                  |
| **Layer 2: Suspicious Rules** | Heuristic analysis | <50ms      | Scoring + anomaly detection                               | $0                  |
| **Layer 3: LLM Rules**        | Deep semantic      | 500-2000ms | AI-powered context analysis (opt-in, disabled by default) | $5-$15 per 1K req\* |

\*LLM costs vary by provider. Layer 3 is disabled by default.

### Client-Aware Panic Stop

Progressive backoff system prevents DoS attacks by isolating misbehaving clients:

| Strike       | Backoff    | Trigger                   | Behavior                                                 |
| ------------ | ---------- | ------------------------- | -------------------------------------------------------- |
| **Strike 1** | 30 seconds | First 429 error           | Client blocked for 30s, auto-resume after                |
| **Strike 2** | 60 seconds | Second 429 within session | Client blocked for 60s, warning logged                   |
| **Strike 3** | Permanent  | Third 429 within session  | **PANIC MODE** - permanently blocked until proxy restart |

**Key Innovation**: Each client tracked separately by ID (from `x-client-id` header or IP address), preventing one malicious client from affecting others.

### Cache Architecture

- **SHA-256 hashing** of {toolName, args} for deterministic cache keys
- **60-second TTL** with automatic expiration
- **LRU eviction** at 1000 entries to prevent memory exhaustion
- **Sub-millisecond cache hits** for repeated requests (65-75% hit ratio in typical workloads)

### Explainable Blocking

Every blocked request includes full forensic context:

```json
{
  "error": {
    "code": -32003,
    "message": "Security Gateway blocked request",
    "data": {
      "blocked": true,
      "layer": 1,
      "latency_ms": 8,
      "findings": [
        {
          "ruleCode": "SEC-003",
          "severity": "critical",
          "message": "SQL injection detected in parameter 'filter'",
          "cwe": "CWE-89",
          "owasp": "A03:2021 - Injection",
          "remediation": "Use parameterized queries",
          "matchedPattern": "OR 1=1",
          "affectedParameter": "filter"
        }
      ]
    }
  }
}
```

### Classic Guardrails (Post-Gateway)

5 traditional guardrails run AFTER the 3-layer gateway passes a request:

- **HTTPS Enforcer** - Blocks non-HTTPS URLs
- **Input Sanitizer** - Sanitizes user inputs
- **PII Redactor** - Redacts sensitive data
- **Rate Limiter** - Prevents DoS (configurable)
- **Sensitive Command Blocker** - Blocks dangerous shell commands

**Usage**:

```bash
# Start proxy (Layers 1+2 only, production-safe)
mcp-verify proxy --target "node my-server.js" --port 3000

# Enable Layer 3 (development/high-security only)
mcp-verify proxy --target "node my-server.js" --enable-llm-layer

# With audit logging
mcp-verify proxy --target "node my-server.js" \
  --audit-log ./logs/security.jsonl
```

---

## 🚀 Everything Else in the Box

| Feature                         | Description                                                                                            |
| ------------------------------- | ------------------------------------------------------------------------------------------------------ |
| **4 Interfaces**                | Interactive Shell, CLI Commands (11 tools), MCP Server (7 tools for AI agents), VSCode Extension       |
| **Multi-LLM Semantic Analysis** | Gemini (FREE tier), Anthropic Claude, OpenAI GPT, Ollama — optional deep analysis                      |
| **Baseline Comparison**         | `--compare-baseline` with `--fail-on-degradation` for regression detection                             |
| **CI/CD Exit Codes**            | `0` pass · `1` warnings · `2` critical — GitHub Actions ready                                          |
| **Internationalization**        | Full English + Spanish support (i18n)                                                                  |
| **Monorepo Architecture**       | `apps/` (CLI, MCP Server, VSCode, Web Dashboard) + `libs/` (Core, Fuzzer, Shared, Protocol, Transport) |

---

## ⚡ Get Started

```bash
# Clone & Build
git clone https://github.com/FinkTech/mcp-verify.git
cd mcp-verify
npm install
npm run build

# Launch the Interactive Shell
mcp-verify

# Or run a one-shot scan
mcp-verify validate "node server.js"
```

**Node.js ≥ 18.0.0** required. NPM package publication coming in **v1.0.1**.

---

## 📖 Documentation

| Document                                       | Description                  |
| ---------------------------------------------- | ---------------------------- |
| [README.md](./README.md)                       | Full feature reference       |
| [QUICKSTART.md](./QUICKSTART.md)               | 3-minute setup guide         |
| [SECURITY.md](./SECURITY.md)                   | Security model & limitations |
| [ARCHITECTURE.md](./ARCHITECTURE.md)           | Clean Architecture deep-dive |
| [COMMANDS.md](./COMMANDS.md)                   | All 11 CLI commands          |
| [API_REFERENCE.md](./API_REFERENCE.md)         | Programmatic API             |
| [CONTRIBUTING.md](./CONTRIBUTING.md)           | Contribution guide           |
| [RESPONSIBLE_USAGE.md](./RESPONSIBLE_USAGE.md) | Ethical guidelines           |

---

<p align="center">
  <b>mcp-verify v1.0.0</b> — Built by <a href="https://github.com/FinkTech">FinkTech</a> · AGPL-3.0
  <br/>
  <i>Because if you can't verify it, you can't trust it.</i>
</p>
