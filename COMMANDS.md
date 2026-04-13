# MCP Verify: Complete Command Reference

This document provides a comprehensive reference for all commands, options, scripts, and utilities available in `mcp-verify`.

## Overview

`mcp-verify` is an enterprise-grade security validation and testing tool for Model Context Protocol (MCP) servers. It helps developers ensure their MCP servers are secure, reliable, and compliant with the protocol specifications.

---

## 📚 Documentation for AI Agents & Developers

This project uses **enterprise-grade `CLAUDE.md` documentation files** throughout the codebase for optimal context and navigation:

### Main Documentation Files

| File                                    | Purpose                                                        | Read First?   |
| --------------------------------------- | -------------------------------------------------------------- | ------------- |
| [`/CLAUDE.md`](./CLAUDE.md)             | **Project overview** - Architecture, structure, critical rules | ✅ Start here |
| [`/apps/CLAUDE.md`](./apps/CLAUDE.md)   | Apps overview - CLI, MCP Server, VSCode extension              | -             |
| [`/libs/CLAUDE.md`](./libs/CLAUDE.md)   | Libraries overview - Core, Fuzzer, Shared, etc.                | -             |
| [`/tests/CLAUDE.md`](./tests/CLAUDE.md) | Testing strategy and patterns                                  | -             |

### Detailed Documentation by Component

**Applications:**

- [`/apps/cli-verifier/CLAUDE.md`](./apps/cli-verifier/CLAUDE.md) - Interactive shell, commands, multi-context system
- [`/apps/mcp-server/CLAUDE.md`](./apps/mcp-server/CLAUDE.md) - 7 MCP tools, LLM formatting, self-audit
- [`/apps/vscode-extension/CLAUDE.md`](./apps/vscode-extension/CLAUDE.md) - Extension architecture, providers, views

**Libraries:**

- [`/libs/core/CLAUDE.md`](./libs/core/CLAUDE.md) - Domain logic, 61 security rules, validators, reporting
- [`/libs/fuzzer/CLAUDE.md`](./libs/fuzzer/CLAUDE.md) - Smart Fuzzer v1.0, detectors, generators, mutations
- [`/libs/shared/CLAUDE.md`](./libs/shared/CLAUDE.md) - i18n, CLI helpers, path validator, utilities

### Quick Navigation Pattern

For AI agents working on this project:

```
1. Read /CLAUDE.md for project overview
2. Read specific component's CLAUDE.md (e.g., /apps/cli-verifier/CLAUDE.md)
3. Use "Where to Find" sections to locate exact files
4. Follow "Patterns" sections for implementation examples
```

**Token Savings:** ~90% reduction in context exploration by using these files.

---

## Global Options

These options can be used with any command:

| Option              | Description                                        | Default     |
| ------------------- | -------------------------------------------------- | ----------- |
| `-v, --version`     | Output the current version with Yogui mascot       | -           |
| `-h, --help`        | Display help for command                           | -           |
| `-q, --quiet`       | Suppress all output except errors                  | `false`     |
| `--json-stdout`     | Output logs in JSON format for parsing             | `false`     |
| `--no-color`        | Disable colored output                             | `false`     |
| `-l, --lang <lang>` | Set the display language (e.g., 'en', 'es')        | Auto-detect |
| `--mascot`          | Show the Yogui mascot in output                    | `false`     |
| `--profile <name>`  | Set security profile (light, balanced, aggressive) | `balanced`  |

---

## Interactive Mode

If you run `mcp-verify` without any arguments, it starts in **Interactive Mode**. This mode provides a powerful REPL (Read-Eval-Print Loop) with multi-context workspaces, security profiles, and contextual autocompletion.

```bash
mcp-verify
```

### Interactive Shell Features

- **Multi-Context Workspaces**: Switch between dev, staging, prod targets
- **Security Profiles**: Light, Balanced, Aggressive presets
- **Contextual Autocomplete**: Tab completion for commands, flags, and paths
- **Persistent History**: Command history saved to `~/.mcp-verify/history.json`
- **Session Persistence**: Context state saved to `.mcp-verify/session.json`
- **Secret Redaction**: Automatic API key redaction in history
- **Output Redirection**: Support for `>` (overwrite) and `>>` (append)

### Interactive Commands

Once in the shell, you can use all one-shot commands plus these interactive-specific commands:

#### Session Management

| Command                | Description                     | Example                           |
| ---------------------- | ------------------------------- | --------------------------------- |
| `set target <url>`     | Set the default target server   | `set target node server.js`       |
| `set lang <language>`  | Change display language (en/es) | `set lang es`                     |
| `config <key> <value>` | Set configuration value         | `config output.formats json,html` |
| `history`              | Show command history            | `history`                         |
| `history clear`        | Clear command history           | `history clear`                   |

#### Multi-Context Commands

| Command                 | Description                   | Example                  |
| ----------------------- | ----------------------------- | ------------------------ |
| `context list`          | List all workspace contexts   | `context list`           |
| `context switch <name>` | Switch to a different context | `context switch prod`    |
| `context create <name>` | Create a new context          | `context create staging` |
| `context delete <name>` | Delete a context              | `context delete old-dev` |

#### Security Profile Commands

| Command               | Description                             | Example                   |
| --------------------- | --------------------------------------- | ------------------------- |
| `profile set <name>`  | Switch to a security profile            | `profile set aggressive`  |
| `profile save <name>` | Save current settings as custom profile | `profile save my-profile` |
| `profile list`        | List all available profiles             | `profile list`            |
| `profile show`        | Show current profile details            | `profile show`            |

#### Status & Information

| Command          | Description                                 | Example     |
| ---------------- | ------------------------------------------- | ----------- |
| `status`         | Show workspace health and connection status | `status`    |
| `help [command]` | Show help for a command                     | `help fuzz` |
| `version`        | Show version information                    | `version`   |
| `examples`       | Show usage examples                         | `examples`  |

#### Navigation & Shell

| Command                 | Description                | Example   |
| ----------------------- | -------------------------- | --------- |
| `clear` or `cls`        | Clear the terminal screen  | `clear`   |
| `exit` or `quit` or `q` | Exit the interactive shell | `exit`    |
| `!<command>`            | Execute shell command      | `!ls -la` |

#### Links & Resources

| Command   | Description                   |
| --------- | ----------------------------- |
| `docs`    | Open documentation in browser |
| `github`  | Open GitHub repository        |
| `discord` | Open Discord community        |
| `twitter` | Open Twitter/X profile        |

### Prompt Indicators

The interactive shell prompt shows your current context and profile:

```bash
# Default context with balanced profile
mcp-verify (balanced) >

# Named context with aggressive profile
mcp-verify (prod:aggressive) node server.js >

# Workspace with target set
[my-project] mcp-verify (dev:light) https://api.example.com >
```

---

## One-Shot Commands

These commands can be used both in interactive mode and as one-shot CLI commands:

### `validate`

Runs a comprehensive validation suite against an MCP server. This includes protocol compliance, security checks, and optional capability analysis.

**Usage:**

```bash
mcp-verify validate <target> [options]
```

**Options:**

| Option                          | Description                                                                                                             | Default                  |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------------- | ------------------------ |
| `-t, --transport <type>`        | Transport type (`stdio`, `http`, `sse`)                                                                                 | Auto-detect              |
| `-o, --output <path>`           | Directory to save reports                                                                                               | `./reports`              |
| `-c, --config <path>`           | Path to configuration file                                                                                              | `mcp-verify.config.json` |
| `--rules <list>`                | **(Filter)** Comma-separated list of rule blocks to run (e.g., `OWASP,MCP`). Overrides config file.                     | `all`                    |
| `--exclude-rules <list>`        | **(Filter)** Comma-separated list of rule blocks or IDs to skip (e.g., `SEC-001,Weaponization`). Overrides config file. | `(none)`                 |
| `--min-severity <level>`        | **(Filter)** Minimum severity to report (`info`, `low`, `medium`, `high`, `critical`). Overrides config file.           | `info`                   |
| `--html`                        | Generate an HTML report                                                                                                 | `false`                  |
| `--format <type>`               | Report format (`json`, `sarif`, `text`)                                                                                 | `json`                   |
| `-e, --env <pairs...>`          | Environment variables (e.g., `KEY=VALUE`)                                                                               | -                        |
| `--fuzz`                        | Enable fuzzing during validation                                                                                        | `false`                  |
| `--sandbox`                     | Run validation in a sandboxed environment                                                                               | `false`                  |
| `--semantic-check`              | Enable semantic analysis of tool descriptions                                                                           | `false`                  |
| `--llm <provider:model>`        | Configure LLM for semantic checks (e.g., `anthropic:claude-3`)                                                          | -                        |
| `--save`                        | Save the scan results                                                                                                   | `false`                  |
| `--verbose`                     | Enable verbose logging                                                                                                  | `false`                  |
| `--save-baseline <path>`        | Save results as a baseline for future comparisons                                                                       | -                        |
| `--compare-baseline <path>`     | Compare current results against a baseline                                                                              | -                        |
| `--fail-on-degradation`         | Fail the process if regression is detected                                                                              | `false`                  |
| `--allowed-score-drop <number>` | Allowed score drop before failing                                                                                       | `5`                      |

---

### `fuzz` (Smart Fuzzer)

Performs fuzz testing by sending random or malformed data to the server to find robustness issues.

**Usage:**

```bash
mcp-verify fuzz <target> [options]
```

**Options:**

| Option                       | Description                                                                                                                | Default     |
| ---------------------------- | -------------------------------------------------------------------------------------------------------------------------- | ----------- |
| `-t, --transport <type>`     | Transport type (`stdio`, `http`, `sse`)                                                                                    | Auto-detect |
| `-c, --concurrency <number>` | Fuzzing concurrency level                                                                                                  | `1`         |
| `--timeout <ms>`             | Request timeout                                                                                                            | `5000`      |
| `--tool <name>`              | Specific tool to fuzz                                                                                                      | `echo`      |
| `--param <name>`             | Specific parameter to fuzz                                                                                                 | `input`     |
| `--generators <list>`        | Comma-separated generators (`prompt`, `jsonrpc`, `sql`, `command`, `path`, `ssti`, `proto`, `auth`, `blind`, `raw`, `all`) | `all`       |
| `--detectors <list>`         | Comma-separated detectors (`leak`, `protocol`, `path`, `entropy`, `info`, `time`, `pattern`, `xss`, `all`)                 | `all`       |
| `--stop-on-first`            | Stop immediately after finding the first vulnerability                                                                     | `false`     |
| `--fingerprint`              | Enable server fingerprinting to optimize payloads                                                                          | `false`     |
| `--verbose`                  | Enable verbose logging                                                                                                     | `false`     |
| `-o, --output <path>`        | Output directory for reports                                                                                               | -           |
| `--format <type>`            | Output format (`json`, `sarif`, `text`, `html`, `all`)                                                                     | `json`      |
| `-H, --header <header...>`   | HTTP headers (e.g., "Auth: Bearer ...")                                                                                    | -           |

**Fingerprinting Capabilities:**
The `--fingerprint` flag auto-detects:

- **Languages:** Node.js, Python, Rust, Go, Java, C#, Ruby, PHP.
- **Frameworks:** FastMCP, MCP SDK (TS/PY), Express, Fastify, Flask, Django, Actix, Axum, Gin, Echo, Spring.
- **Databases:** PostgreSQL, MySQL, SQLite, MongoDB, Redis.

---

### `stress`

Runs load and stress tests to evaluate server performance and stability.

**Usage:**

```bash
mcp-verify stress <target> [options]
```

**Options:**

| Option                     | Description                             | Default     |
| -------------------------- | --------------------------------------- | ----------- |
| `-t, --transport <type>`   | Transport type (`stdio`, `http`, `sse`) | Auto-detect |
| `-u, --users <number>`     | Number of concurrent virtual users      | `5`         |
| `-d, --duration <seconds>` | Duration of the test in seconds         | `10`        |
| `--verbose`                | Enable verbose logging                  | `false`     |

---

### `doctor`

Professional diagnostic assistant that inspects four domains:

1.  **Binary Integrity**: SHA-256 self-verification.
2.  **Environment**: Node/Python/Git/Deno runtime checks.
3.  **MCP Server**: Protocol handshake and capability inventory.
4.  **Environment Audit**: Detection of sensitive variable names.

**Usage:**

```bash
mcp-verify doctor [target] [options]
```

**Options:**

| Option                   | Description                                             | Default     |
| ------------------------ | ------------------------------------------------------- | ----------- |
| `-t, --transport <type>` | Transport type (`stdio`, `http`, `sse`)                 | Auto-detect |
| `--watch`                | Monitor the target continuously (auto-refresh every 5s) | `false`     |
| `--verbose`              | Print internal sub-steps for each section               | `false`     |
| `--html`                 | Generate a diagnostic HTML report                       | `false`     |
| `--md`                   | Generate a diagnostic Markdown report                   | `false`     |
| `--json`                 | Generate a diagnostic JSON report                       | `false`     |
| `-o, --output <path>`    | Output directory for reports                            | `./reports` |

---

### `dashboard`

Starts a web-based dashboard to visualize server status and test results.

**Usage:**

```bash
mcp-verify dashboard <target> [options]
```

**Options:**

| Option                   | Description               | Default |
| ------------------------ | ------------------------- | ------- |
| `-t, --transport <type>` | Transport type            | `stdio` |
| `-p, --port <number>`    | Dashboard web server port | `5173`  |
| `--timeout <ms>`         | Connection timeout        | -       |

---

### `play` (Playground)

Starts an interactive playground to manually test and interact with an MCP server.

**Usage:**

```bash
mcp-verify play <target> [options]
```

**Options:**

| Option                   | Description                        | Default     |
| ------------------------ | ---------------------------------- | ----------- |
| `-p, --port <number>`    | Port to listen on                  | `8080`      |
| `-t, --transport <type>` | Transport type                     | Auto-detect |
| `--list-only`            | Only list available tools and exit | `false`     |

---

### `proxy`

Starts a **Security Gateway v1.0** proxy server with 3-layer defense system + client-aware panic stop mechanism. Provides real-time threat detection and progressive backoff for rate-limited clients.

**Usage:**

```bash
mcp-verify proxy <target> [options]
```

**Options:**

| Option                  | Description                                  | Default  |
| ----------------------- | -------------------------------------------- | -------- |
| `-p, --port <number>`   | Proxy port                                   | `8080`   |
| `--timeout <ms>`        | Connection timeout                           | `120000` |
| `--enable-llm-layer`    | Enable Layer 3 (LLM-powered deep analysis)   | `false`  |
| `--no-llm-layer`        | Explicitly disable Layer 3 (production mode) | -        |
| `--rate-limit <number>` | Max requests per minute per tool             | `100`    |
| `--audit-log <path>`    | Audit log file path (JSONL format)           | -        |
| `--verbose`             | Enable verbose logging with security events  | `false`  |

**Security Gateway - 3 Layers:**

| Layer                     | Latency    | Detection            | Examples                                                |
| ------------------------- | ---------- | -------------------- | ------------------------------------------------------- |
| **Layer 1: Fast Rules**   | <10ms      | Regex patterns       | SQL injection, command injection, path traversal        |
| **Layer 2: Suspicious**   | <50ms      | Heuristic scoring    | Tool chaining, excessive permissions, anomaly detection |
| **Layer 3: LLM (opt-in)** | 500-2000ms | AI semantic analysis | Novel attacks, semantic prompt injection                |

**Panic Stop System:**

| Strike | Backoff   | Trigger         | Client Behavior                        |
| ------ | --------- | --------------- | -------------------------------------- |
| 1      | 30s       | First HTTP 429  | Temporary block, auto-resume           |
| 2      | 60s       | Second HTTP 429 | Extended block, warning logged         |
| 3      | Permanent | Third HTTP 429  | **PANIC MODE** - blocked until restart |

**Examples:**

```bash
# Basic proxy with Security Gateway (Layers 1+2 enabled)
mcp-verify proxy "node server.js" --port 8080

# Production mode (fast, no LLM)
mcp-verify proxy "node server.js" --port 8080 --no-llm-layer --verbose

# Full security (all 3 layers)
mcp-verify proxy "node server.js" --port 8080 --enable-llm-layer

# With custom rate limiting + audit log
mcp-verify proxy "http://localhost:3000"
  --port 8080
  --rate-limit 50
  --audit-log proxy-events.jsonl

# Monitor panic stop events
mcp-verify proxy "node server.js" --verbose | grep "PANIC"
```

**Security Features:**

- **Explainable Blocking**: Every rejection includes rule ID, CWE, OWASP mapping, remediation steps
- **Client-Aware State**: Isolated strikes per client (prevents global DoS)
- **Cache-First Strategy**: SHA-256 hashing with 60s TTL and LRU eviction (1000 entries)
- **Full Audit Trail**: All security events logged with timestamps and client IDs

---

### `mock`

Starts a mock MCP server for development and testing.

**Usage:**

```bash
mcp-verify mock [options]
```

**Options:**

| Option                | Description                        | Default |
| --------------------- | ---------------------------------- | ------- |
| `-p, --port <number>` | Port to listen on (for HTTP/SSE)   | `3000`  |
| `--timeout <ms>`      | Connection timeout in milliseconds | -       |

---

### `init`

Initializes a configuration file (`mcp-verify.config.json`) in the current directory.

**Usage:**

```bash
mcp-verify init
```

---

### `examples`

Displays usage examples and common patterns.

**Usage:**

```bash
mcp-verify examples
```

---

### `fingerprint`

Performs server fingerprinting to detect technologies, frameworks, and potential vulnerabilities.

**Usage:**

```bash
mcp-verify fingerprint <target> [options]
```

**Options:**

| Option                   | Description            | Default     |
| ------------------------ | ---------------------- | ----------- |
| `-t, --transport <type>` | Transport type         | Auto-detect |
| `--timeout <ms>`         | Connection timeout     | `5000`      |
| `--verbose`              | Enable verbose logging | `false`     |

**Detects:**

- **Languages**: Node.js, Python, Rust, Go, Java, C#, Ruby, PHP
- **Frameworks**: FastMCP, MCP SDK, Express, Fastify, Flask, Django, Actix, etc.
- **Databases**: PostgreSQL, MySQL, SQLite, MongoDB, Redis
- **MCP Protocol Version**: Detected from handshake

---

### `inspect`

Deep inspection of MCP server capabilities and metadata.

**Usage:**

```bash
mcp-verify inspect <target> [options]
```

**Options:**

| Option                   | Description                   | Default     |
| ------------------------ | ----------------------------- | ----------- |
| `-t, --transport <type>` | Transport type                | Auto-detect |
| `--json`                 | Output in JSON format         | `false`     |
| `--verbose`              | Show detailed capability info | `false`     |

**Shows:**

- Server name and version
- Protocol version
- Capabilities (tools, resources, prompts)
- Tool/Resource/Prompt schemas
- Server implementation info

---

## 🕵️ Detectable Vulnerabilities

`mcp-verify` scans for a wide range of security issues, including:

- **Authentication:** Weak hashing, plain-text credentials, user enumeration.
- **Injection:** SQLi, Command Injection, SSRF, XXE, Template Injection, XSS.
- **Data Leakage:** Sensitive fields in responses, internal file path exposure, PII.
- **Deserialization:** Unsafe YAML loading, insecure object reconstruction.
- **Protocol:** JSON-RPC standard violations, schema non-compliance.
- **Infrastructure:** Weak cryptography, ReDoS (Regex Denial of Service).
- **AI/LLM Specific:** Prompt injection (direct/indirect), prompt leaking.

---

## 🤖 MCP Server Mode

`mcp-verify` can run as an MCP server itself, allowing AI agents (like Claude) to call validation tools directly.

**Start the server:**

```bash
# Using the built binary
node dist/mcp-server.js

# Using the Windows batch file
mcp-server.bat

# Using npm
npm run start:server
```

### 🛠️ MCP Server Tools

When running in server mode, the following tools are exposed to the AI client:

| Tool Name              | Parameters                                  | Description                                                                  |
| ---------------------- | ------------------------------------------- | ---------------------------------------------------------------------------- |
| `validateServer`       | `command`, `args[]`, `configPath`           | Validates an MCP server (connection, schema, security, quality).             |
| `scanSecurity`         | `command`, `args[]`, `rules[]`              | Performs a focused security scan on an MCP server.                           |
| `analyzeQuality`       | `command`, `args[]`                         | Analyzes the quality and semantics of MCP tools and resources.               |
| `generateReport`       | `command`, `args[]`, `format`, `outputPath` | Generates a comprehensive validation report.                                 |
| `listInstalledServers` | `configPath`                                | Lists MCP servers configured in the local environment (e.g. Claude Desktop). |
| `selfAudit`            | `configPath`, `skipServerValidation`        | Performs a self-audit of the mcp-verify installation.                        |
| `compareServers`       | `serverNames[]`, `servers[]`                | Compares two MCP servers (e.g. regression testing).                          |

---

## 🛠️ Fuzzing Cheat Sheet (Aliases)

Use these short names in `--generators` and `--detectors`:

### Generators

| Alias                 | Full Name / Category    |
| --------------------- | ----------------------- |
| `prompt`              | `prompt-injection`      |
| `jsonrpc`             | `json-rpc`              |
| `sql`                 | `sqli`                  |
| `command`             | `cmd-injection`         |
| `path`                | `path-traversal`        |
| `ssti`                | `template-injection`    |
| `proto`, `prototype`  | `prototype-pollution`   |
| `auth`                | `jwt-attack`            |
| `blind`, `time-based` | `time-based`            |
| `raw`, `malformed`    | `raw-protocol` (Opt-in) |

### Detectors

| Alias                | Full Name            |
| -------------------- | -------------------- |
| `leak`               | `prompt-leak`        |
| `protocol`           | `protocol-violation` |
| `path`               | `path-traversal`     |
| `entropy`            | `weak-id`            |
| `info`, `disclosure` | `info-disclosure`    |
| `time`, `blind`      | `timing`             |
| `pattern`            | `error`              |
| `xss`                | `xss` (Reflected)    |

---

## 🏗️ Development & NPM Scripts

| Command                    | Description                            |
| -------------------------- | -------------------------------------- |
| `npm run dev`              | Run CLI from source (`ts-node`)        |
| `npm run build`            | Build production bundle with `esbuild` |
| `npm run compile`          | Create native binaries (`dist/bin/`)   |
| `npm run lint`             | Run ESLint check                       |
| `npm run lint:fix`         | Auto-fix linting issues                |
| `npm run format`           | Prettify entire codebase               |
| `npm run type-check`       | Run TSC (no emit)                      |
| `npm test`                 | Run all Jest tests                     |
| `npm run test:unit`        | Unit tests only                        |
| `npm run test:integration` | Integration tests only                 |
| `npm run test:e2e`         | End-to-end tests only                  |
| `npm run test:coverage`    | Generate LCOV report                   |
| `npm run preview:report`   | Generate a preview validation report   |

---

## 🧪 Internal Utility Scripts (`tools/scripts/`)

| Script                       | Purpose                            |
| ---------------------------- | ---------------------------------- |
| `bundle.js`                  | Core build engine logic.           |
| `generate-report-preview.ts` | Creates dummy data for UI testing. |

---

## 💀 Debug & Test Servers

Run these with `node <filename>.js` for local testing:

- `vulnerable-server.js`: SQLi and XSS test lab (Port 3009).
- `fast-server.js`: Ultra-low latency dummy server (Port 3007).
- `ping-server.js`: Simple keep-alive responder.
- `zombie.js`: Simulates a hanging/unresponsive server.
- `debug-server.js`: Logs all incoming MCP traffic to console.

---

## ⚙️ Configuration File (`mcp-verify.config.json`)

You can customize the behavior of `mcp-verify` using a JSON configuration file.

**Main Sections:**

- `output`: Directory, formats (`json`, `html`, `sarif`, `text`), and language.
- `security`: Minimum score, rules configuration, and fail-on conditions.
- `fuzzing`: Timeout, concurrency, and smart features (fingerprinting).
- `network`: Connection/request timeouts and custom headers.
- `sandbox`: Isolation settings (enabled/disabled, permissions).
- `proxy`: PII masking, rate limiting, and blocked command patterns.

---

## 📦 GitHub Action

`mcp-verify` can be integrated into GitHub workflows to validate servers on every PR.

**Inputs:**

- `url`: Target URL of the MCP server.
- `transport`: `http` or `stdio` (Default: `http`).
- `fail-on-issue`: Fail the workflow if issues are found (Default: `true`).
- `format`: Output format (Default: `sarif`).

**Usage Example:**

```yaml
steps:
  - uses: FinkTech/mcp-verify@main
    with:
      url: "https://api.myapp.com/mcp"
      fail-on-issue: "true"
```

---

## 🐳 Docker Usage

You can run `mcp-verify` inside a container to avoid installing dependencies locally.

**Build the image:**

```bash
docker build -t mcp-verify .
```

**Run validation:**

```bash
docker run --rm mcp-verify validate https://api.myapp.com/mcp
```

---

## 🚪 Exit Codes

`mcp-verify` uses standardized exit codes for CI/CD integration:

| Code | Meaning                                                       |
| ---- | ------------------------------------------------------------- |
| `0`  | **Success**: No critical issues found.                        |
| `1`  | **Validation Failed**: General errors or low scores.          |
| `2`  | **Security Risk**: Critical or High vulnerabilities detected. |

---

## 🔑 Environment Variables

| Variable            | Usage                                              |
| ------------------- | -------------------------------------------------- |
| `ANTHROPIC_API_KEY` | Required for Claude semantic analysis.             |
| `OPENAI_API_KEY`    | Required for GPT semantic analysis.                |
| `OLLAMA_HOST`       | Host for local AI analysis (Default: `localhost`). |
| `DEBUG=mcp:*`       | Enable verbose internal tracing.                   |
| `MCP_LANG=es`       | Force Spanish output globally.                     |
