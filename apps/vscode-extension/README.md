# MCP Verify for Visual Studio Code

Enterprise-grade security validation for Model Context Protocol (MCP) servers directly from VS Code.

[![Version](https://img.shields.io/badge/version-1.0.0-blue)](https://github.com/FinkTech/mcp-verify)
[![Status](https://img.shields.io/badge/status-stable-green)](https://github.com/FinkTech/mcp-verify)
[![License](https://img.shields.io/badge/License-AGPL--3.0-yellow.svg)](https://www.gnu.org/licenses/agpl-3.0)

---

## ✨ Enterprise-Ready v1.0.0

This VS Code extension provides **production-ready** enterprise-grade security validation for MCP servers.

**Core Features (Stable):**

- ✅ Full security validation with **60 security rules across 6 threat categories**
- ✅ Advanced fuzzing engine with smart payload generation
- ✅ Real-time diagnostics in Problems panel
- ✅ Tree views for servers, findings, tools, and history
- ✅ HTML report generation with WebView panel
- ✅ SARIF export for CI/CD integration
- ✅ Shield Pattern for secure schema generation
- ✅ Multi-language support (English, Spanish)

**In Development:**

- 🚧 Security proxy with guardrails
- 🚧 Interactive tool execution playground
- 🚧 Real-time dashboard monitoring

**For contributors:** See [CLAUDE.md](./CLAUDE.md) for comprehensive architecture documentation and development guide.

---

## Overview

**MCP Verify** is a VS Code extension that provides comprehensive security validation for MCP servers. Detect SQL injection, command injection, prompt injection, SSRF, and **56+ other critical vulnerabilities** across 6 threat categories without leaving your editor.

### Key Features

- **60 Security Rules** - Complete threat coverage across 6 blocks: OWASP fundamentals (13), MCP-specific vulnerabilities (8), OWASP LLM Top 10 (9), Multi-Agent Attacks (11), Enterprise Compliance (9), and AI Weaponization (10)
- **Smart Fuzzing Engine** - Production-ready automated vulnerability discovery with 8 payload generators and 9 vulnerability detectors
- **Shield Pattern** - Automated secure schema generation that hardens JSON schemas without modifying original files
- **Stress Testing** - Load testing to identify performance and DoS vulnerabilities
- **Tree View Sidebar** - Dedicated panel for servers, findings, tools, and history
- **Interactive Reports** - HTML reports with detailed findings and remediation
- **SARIF Export** - Integration with GitHub Advanced Security and other tools
- **Multi-language** - English and Spanish (auto-detected)

---

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/FinkTech/mcp-verify.git
cd mcp-verify

# Install dependencies
npm install

# Build the extension
npm run build

# Open in VS Code and press F5 (Extension Development Host)
```

### From Marketplace (Coming Soon)

1. Open VS Code
2. Go to Extensions (`Ctrl+Shift+X`)
3. Search for "MCP Verify"
4. Click Install

---

## Quick Start

1. Open Command Palette (`Ctrl+Shift+P`)
2. Type: **"MCP Verify: Validate MCP Server"**
3. Enter your MCP server command (e.g., `npx -y @modelcontextprotocol/server-memory`)
4. View results in:
   - **MCP Verify Sidebar** - Tree view with findings
   - **Problems Panel** - Security issues as diagnostics
   - **Report WebView** - Interactive HTML report

---

## Commands

All commands available via Command Palette (`Ctrl+Shift+P`):

| Command                               | Description                  |
| ------------------------------------- | ---------------------------- |
| `MCP Verify: Validate MCP Server`     | Full security validation     |
| `MCP Verify: Fuzz MCP Server`         | Run fuzzing session          |
| `MCP Verify: Stress Test MCP Server`  | Load testing                 |
| `MCP Verify: Run Diagnostics`         | Check environment setup      |
| `MCP Verify: Open Playground`         | Interactive tool execution   |
| `MCP Verify: Start Security Proxy`    | Proxy with guardrails        |
| `MCP Verify: Open Dashboard`          | Real-time monitoring         |
| `MCP Verify: Export SARIF Report`     | Export for CI/CD integration |
| `MCP Verify: Generate Security Badge` | Create SVG badge             |
| `MCP Verify: Compare with Baseline`   | Regression detection         |
| `MCP Verify: Clear Scan History`      | Clear stored results         |

---

## Sidebar Views

The extension adds a dedicated **MCP Verify** panel to the Activity Bar with four views:

### Servers

List of configured MCP servers with status indicators:

- Connection status (idle, scanning, connected, error)
- Last scan date and security score
- Quick actions to validate or remove

### Security Findings

Hierarchical view of security issues:

- Grouped by severity (Critical, High, Medium, Low, Info)
- Sub-grouped by rule (SEC-001, SEC-002, etc.)
- Click to view detailed finding information

### Discovered Tools

Tools exposed by the MCP server:

- Tool name and description
- Input schema preview
- Security issue indicators
- Click to execute in playground

### Scan History

Past validation results:

- Grouped by date (Today, Yesterday, etc.)
- Server name, score, and timestamp
- Click to view historical report

---

## Security Rules

The extension validates against **60 security rules** organized in **6 threat category blocks**:

### Block OWASP: OWASP Top 10 Aligned (SEC-001 to SEC-013)

| Rule    | Severity | Description                        |
| ------- | -------- | ---------------------------------- |
| SEC-001 | Critical | Authentication Bypass Detection    |
| SEC-002 | Critical | Command Injection Detection        |
| SEC-003 | Critical | SQL Injection Detection            |
| SEC-004 | High     | Server-Side Request Forgery (SSRF) |
| SEC-005 | High     | XML External Entity (XXE)          |
| SEC-006 | High     | Insecure Deserialization           |
| SEC-007 | High     | Path Traversal Detection           |
| SEC-008 | Medium   | Data Leakage Prevention            |
| SEC-009 | Medium   | Sensitive Data Exposure            |
| SEC-010 | Medium   | Missing Rate Limiting              |
| SEC-011 | Medium   | ReDoS Detection                    |
| SEC-012 | Medium   | Weak Cryptography                  |
| SEC-013 | Medium   | Prompt Injection Detection         |

### Block MCP: MCP-Specific Security (SEC-014 to SEC-021)

| Rule    | Severity | Description                               |
| ------- | -------- | ----------------------------------------- |
| SEC-014 | High     | Exposed Network Endpoint Prevention       |
| SEC-015 | Critical | Missing Authentication Implementation     |
| SEC-016 | High     | Insecure URI Scheme Prevention            |
| SEC-017 | High     | Excessive Permissions Prevention          |
| SEC-018 | Medium   | Sensitive Data in Descriptions Prevention |
| SEC-019 | Medium   | Missing Input Constraints Prevention      |
| SEC-020 | High     | Dangerous Tool Chaining Prevention        |
| SEC-021 | Critical | Unencrypted Credential Storage Prevention |

### Block A: OWASP LLM Top 10 in MCP Context (SEC-022 to SEC-030)

| Rule    | Severity | Description                      |
| ------- | -------- | -------------------------------- |
| SEC-022 | High     | Insecure Output Handling         |
| SEC-023 | High     | Excessive Agency                 |
| SEC-024 | Critical | Prompt Injection via Tools       |
| SEC-025 | High     | Supply Chain Tool Dependencies   |
| SEC-026 | High     | Sensitive Data in Tool Responses |
| SEC-027 | Medium   | Training Data Poisoning          |
| SEC-028 | High     | Model DoS via Tools              |
| SEC-029 | High     | Insecure Plugin Design           |
| SEC-030 | High     | Excessive Data Disclosure        |

### Block B: Multi-Agent & Agentic Attacks (SEC-031 to SEC-041)

| Rule    | Severity | Description                      |
| ------- | -------- | -------------------------------- |
| SEC-031 | Critical | Agent Identity Spoofing          |
| SEC-032 | Critical | Tool Result Tampering            |
| SEC-033 | High     | Recursive Agent Loop             |
| SEC-034 | Critical | Multi-Agent Privilege Escalation |
| SEC-035 | High     | Agent State Poisoning            |
| SEC-036 | High     | Distributed Agent DDoS           |
| SEC-037 | Critical | Cross-Agent Prompt Injection     |
| SEC-038 | Medium   | Agent Reputation Hijacking       |
| SEC-039 | High     | Tool Chaining Path Traversal     |
| SEC-040 | High     | Agent Swarm Coordination Attack  |
| SEC-041 | Critical | Agent Memory Injection           |

### Block C: Operational & Enterprise Compliance (SEC-042 to SEC-050)

| Rule    | Severity | Description                    |
| ------- | -------- | ------------------------------ |
| SEC-042 | High     | Missing Audit Logging          |
| SEC-043 | High     | Insecure Session Management    |
| SEC-044 | Medium   | Schema Versioning Absent       |
| SEC-045 | Medium   | Insufficient Error Granularity |
| SEC-046 | High     | Missing CORS Validation        |
| SEC-047 | High     | Insecure Default Configuration |
| SEC-048 | Medium   | Missing Capability Negotiation |
| SEC-049 | Medium   | Timing Side-Channel Auth       |
| SEC-050 | Medium   | Insufficient Output Entropy    |

### Block D: AI Weaponization & Supply Chain (SEC-051 to SEC-060)

| Rule    | Severity | Description                         | Default     |
| ------- | -------- | ----------------------------------- | ----------- |
| SEC-051 | High     | Weaponized MCP Fuzzer               | ❌ Disabled |
| SEC-052 | Critical | Autonomous MCP Backdoor             | ❌ Disabled |
| SEC-053 | Critical | Malicious Config File               | ❌ Disabled |
| SEC-054 | Critical | API Endpoint Hijacking              | ✅ Enabled  |
| SEC-055 | High     | Jailbreak-as-a-Service              | ❌ Disabled |
| SEC-056 | High     | Phishing via MCP                    | ❌ Disabled |
| SEC-057 | Medium   | Data Exfiltration via Steganography | ❌ Disabled |
| SEC-058 | Critical | Self-Replicating MCP                | ❌ Disabled |
| SEC-059 | High     | Unvalidated Tool Authorization      | ✅ Enabled  |
| SEC-060 | Medium   | Missing Transaction Semantics       | ✅ Enabled  |

> **⚠️ Note**: Most Block D rules are **disabled by default** due to their adversarial nature. Enable them only in controlled environments for offensive security testing.

Each finding includes:

- Detailed description
- Evidence from the scan
- Remediation guidance
- OWASP/CWE references
- Quick fixes via Code Actions (for enabled rules)

---

## Configuration

Configure via VS Code Settings (`Ctrl+,` → search "MCP Verify"):

### Validation

| Setting                                    | Default | Description                              |
| ------------------------------------------ | ------- | ---------------------------------------- |
| `mcpVerify.language`                       | `auto`  | Language for reports (en, es, auto)      |
| `mcpVerify.validation.enableFuzzing`       | `false` | Enable fuzzing during validation         |
| `mcpVerify.validation.enableSemanticCheck` | `false` | LLM-powered semantic analysis            |
| `mcpVerify.validation.llmProvider`         | `none`  | LLM provider (anthropic, openai, ollama) |
| `mcpVerify.validation.saveHistory`         | `true`  | Save results to history                  |
| `mcpVerify.validation.outputFormat`        | `html`  | Report format (json, html, md, sarif)    |

### Fuzzing

| Setting                         | Default   | Description                       |
| ------------------------------- | --------- | --------------------------------- |
| `mcpVerify.fuzzing.concurrency` | `1`       | Concurrent fuzzing workers (1-10) |
| `mcpVerify.fuzzing.timeout`     | `5000`    | Timeout per request in ms         |
| `mcpVerify.fuzzing.generators`  | `["all"]` | Payload generators to use         |
| `mcpVerify.fuzzing.stopOnFirst` | `false`   | Stop on first vulnerability       |

### Stress Testing

| Setting                            | Default | Description              |
| ---------------------------------- | ------- | ------------------------ |
| `mcpVerify.stress.concurrentUsers` | `5`     | Virtual concurrent users |
| `mcpVerify.stress.duration`        | `10`    | Test duration in seconds |

### Proxy

| Setting                            | Default | Description                |
| ---------------------------------- | ------- | -------------------------- |
| `mcpVerify.proxy.port`             | `8080`  | Proxy server port          |
| `mcpVerify.proxy.enableGuardrails` | `true`  | Enable security guardrails |
| `mcpVerify.proxy.guardrails`       | `[...]` | Active guardrails list     |

### Baseline

| Setting                                | Default | Description            |
| -------------------------------------- | ------- | ---------------------- |
| `mcpVerify.baseline.path`              | `""`    | Path to baseline file  |
| `mcpVerify.baseline.failOnDegradation` | `false` | Fail if score drops    |
| `mcpVerify.baseline.allowedScoreDrop`  | `5`     | Max allowed score drop |

### Security Rules Override

```json
{
  "mcpVerify.security.rules": {
    "SEC-001": { "enabled": true, "severity": "critical" },
    "SEC-011": { "enabled": false }
  }
}
```

---

## Code Actions

When security issues are detected, the extension provides quick fixes:

1. **Generate fix suggestion** - Creates a markdown file with:
   - Problem description
   - Vulnerable code snippet
   - Secure code example
   - Step-by-step remediation
   - OWASP/CWE references

2. **Learn about [rule]** - Opens the OWASP documentation for the specific vulnerability

---

## Shield Pattern (Secure Schema Generation)

**Command**: `MCP Verify: Suggest Secure Schema`

The Shield Pattern automatically hardens JSON schemas by adding security constraints without modifying your original files.

### How It Works

1. Open a tool schema file (JSON format)
2. Run `MCP Verify: Suggest Secure Schema` from Command Palette
3. Extension analyzes the schema and applies security constraints:
   - Adds `additionalProperties: false` to prevent injection
   - Adds `maxLength` limits to string fields (10MB default)
   - Adds validation patterns for critical parameters (email, URL, path)
   - Adds `minimum/maximum` bounds to numeric fields
   - Adds `maxItems/minItems` to arrays
   - Adds `maxProperties` to nested objects
4. Opens hardened schema in a **new "Untitled" editor** (side-by-side)
5. Review and manually apply changes to your original file

### Key Features

- **Non-destructive** - Never overwrites original files
- **Recursive** - Hardens nested schemas automatically
- **Context-aware** - Applies stricter patterns to critical parameters (queries, paths, URLs)
- **Based on SEC-019** - Implements missing input constraints rule recommendations

### Example

**Original Schema:**

```json
{
  "type": "object",
  "properties": {
    "query": { "type": "string" },
    "limit": { "type": "number" }
  }
}
```

**Hardened Schema:**

```json
{
  "type": "object",
  "properties": {
    "query": {
      "type": "string",
      "maxLength": 10485760,
      "pattern": "^[a-zA-Z0-9 ._-]+$"
    },
    "limit": {
      "type": "number",
      "minimum": 0,
      "maximum": 1.7976931348623157e308
    }
  },
  "additionalProperties": false
}
```

---

## Keyboard Shortcuts

No default shortcuts are configured. You can set your own via:

1. `File > Preferences > Keyboard Shortcuts`
2. Search for "MCP Verify"
3. Click the + icon to assign your preferred keys

Suggested shortcuts:

- `Ctrl+Shift+M V` - Validate
- `Ctrl+Shift+M F` - Fuzz
- `Ctrl+Shift+M D` - Doctor

---

## Project Structure

```
apps/vscode-extension/
├── package.json                 # Extension manifest
├── media/
│   └── shield.svg               # Sidebar icon
├── src/
│   ├── extension.ts             # Main entry point
│   ├── commands/
│   │   └── index.ts             # Command handlers
│   ├── views/
│   │   ├── servers-tree.ts      # Servers view
│   │   ├── results-tree.ts      # Findings view
│   │   ├── tools-tree.ts        # Tools view
│   │   └── history-tree.ts      # History view
│   ├── providers/
│   │   ├── diagnostics.ts       # Problems panel
│   │   ├── report-panel.ts      # HTML report webview
│   │   └── code-actions.ts      # Quick fixes
│   ├── state/
│   │   └── global-state.ts      # Shared state management
│   └── utils/
│       └── logger.ts            # Output channel
└── README.md
```

---

## Requirements

- **VS Code**: 1.80.0 or higher
- **Node.js**: 18.0.0 or higher

### Optional

- **LLM API Keys**: For semantic analysis
  - `GOOGLE_API_KEY` for Gemini (FREE tier available!)
  - `ANTHROPIC_API_KEY` for Claude
  - `OPENAI_API_KEY` for GPT-4
  - Ollama for local LLMs

---

## Security & Privacy

- **No telemetry**: Extension does NOT send data to external servers
- **Local execution**: All validation runs locally
- **No API keys required**: Core validation works offline
- **Secure parsing**: Uses `shell-quote` for command parsing

---

## Resources

### Documentation

- **[CLAUDE.md](./CLAUDE.md)** - 📚 **Complete architecture & development guide** (for contributors)
- [MCP Verify Documentation](https://github.com/FinkTech/mcp-verify#readme) - Main project README
- [Security Scoring Guide](https://github.com/FinkTech/mcp-verify/blob/main/SECURITY_SCORING.md) - Understanding security scores
- [Model Context Protocol](https://modelcontextprotocol.io/) - MCP specification

### Support & Community

- [GitHub Issues](https://github.com/FinkTech/mcp-verify/issues) - Bug reports & feature requests
- [GitHub Discussions](https://github.com/FinkTech/mcp-verify/discussions) - Questions & ideas
- [Email](mailto:hello.finksystems@gmail.com) - Direct support

---

## Contributing

**For Contributors:**

1. Read [CLAUDE.md](./CLAUDE.md) - Complete architecture and development guide
2. See [CONTRIBUTING.md](https://github.com/FinkTech/mcp-verify/blob/main/CONTRIBUTING.md) - Contribution guidelines
3. Check [DEVELOPMENT.md](https://github.com/FinkTech/mcp-verify/blob/main/DEVELOPMENT.md) - Local setup

**Quick Start for Contributors:**

```bash
# Clone the repository
git clone https://github.com/FinkTech/mcp-verify.git
cd mcp-verify/apps/vscode-extension

# Install dependencies
npm install

# Start watch mode (auto-recompile)
npm run watch

# Press F5 in VS Code to launch Extension Development Host
```

---

## License

AGPL-3.0 - See [LICENSE](https://github.com/FinkTech/mcp-verify/blob/main/LICENSE)

---

## Development Status

**Current Version**: 1.0.0 (Enterprise-Ready)
**Last Updated**: 2026-02-25

### Stability Matrix

| Feature                | Status     | Notes                                       |
| ---------------------- | ---------- | ------------------------------------------- |
| Security Validation    | ✅ Stable  | Full 60 rules across 6 threat categories    |
| Diagnostics Provider   | ✅ Stable  | Problems panel integration                  |
| Fuzzing Engine         | ✅ Stable  | 8 generators, 9 detectors, production-ready |
| Shield Pattern         | ✅ Stable  | Secure schema generation (SEC-019)          |
| Tree Views             | ✅ Stable  | Results, Servers, Tools, History            |
| HTML Reports           | ✅ Stable  | WebView panel rendering                     |
| SARIF Export           | ✅ Stable  | CI/CD integration                           |
| Code Actions           | ✅ Stable  | Quick fixes (dynamic rule suggestions)      |
| Stress Testing         | ✅ Stable  | Load testing with configurable parameters   |
| Security Proxy         | 🔜 Planned | Guardrails integration                      |
| Interactive Playground | 🔜 Planned | Tool execution environment                  |
| Real-time Dashboard    | 🔜 Planned | Terminal-style monitoring                   |

---

**Made by [FinkTech](https://github.com/FinkTech)**

hello.finksystems@gmail.com
