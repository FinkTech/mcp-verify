# Glossary of Terms - mcp-verify

This glossary defines the key concepts, technologies, and specific terminology used in the **mcp-verify** project. It is designed to help developers, DevOps engineers, and security auditors quickly understand the project ecosystem, its main components, and security best practices for the Model Context Protocol (MCP).

---

## A

### Anti-Weaponization Engine

The **Anti-Weaponization Engine** is a specialized detection system that identifies malicious patterns in MCP server configuration and behavior. It detects threats such as malicious configuration injection (CVE-2025-59536), API endpoint hijacking, self-replicating servers, and autonomous backdoors. These rules (SEC-051 to SEC-060) are disabled by default due to their adversarial nature.

- @see `RELEASE_NOTES.md` for the complete list of detected CVEs.
- @see `SECURITY.md` for ethical implications of using these rules.

### Attestation of Origin

**Attestation of Origin** is an integrity verification mechanism that records the SHA-256 hash of generated binaries (CLI and MCP Server) along with Git traceability information. It allows users to verify that artifacts have not been modified since their original build. The history of the last 20 builds is stored in `.mcp-verify/integrity-history.json`.

- @see `ARCHITECTURE.md` section "Infrastructure Layer" for technical implementation.
- @see `libs/core/infrastructure/integrity/` for source code.

### Audit Log

The **Audit Log** is a structured log in JSONL (JSON Lines) format that documents all requests blocked by the Security Gateway. Each entry includes timestamp, client ID, layer that blocked the request, latency, findings with vulnerability details, and client strike status. It is essential for forensic analysis and production security monitoring.

- @see `API_REFERENCE.md` section "Audit Log Format" for the JSON structure.
- @see `guides/EXAMPLES.md` for analysis examples with `jq`.

---

## B

### Baseline Comparison

**Baseline Comparison** is a feature that allows comparing the current security analysis of an MCP server against a previously saved baseline. It detects degradations in security score between code versions. Used with `--save-baseline` flag to create the baseline and `--compare-baseline` for comparison, with `--fail-on-degradation` to fail the build in CI/CD if there are regressions.

- @see `guides/CI_CD.md` section "Baseline Tracking" for pipeline integration.
- @see `COMMANDS.md` `validate` command for command-line options.

---

## C

### Cache (Security Gateway Cache)

The **Security Gateway Cache** uses SHA-256 hashing of `{toolName, args}` as a key to store security analysis results. It implements a 60-second TTL (Time To Live) and LRU (Least Recently Used) eviction when reaching 1000 entries. Cache hits respond in <1ms, typically achieving 65-75% hit ratio in real workloads, drastically reducing average latency.

- @see `ARCHITECTURE.md` section "Security Gateway v1.0 Architecture" for technical diagrams.
- @see `DEVELOPMENT.md` section "Performance Optimization" for cache tuning.

### CI/CD Integration

**CI/CD Integration** refers to the ability of `mcp-verify` to run in continuous integration and deployment pipelines (GitHub Actions, GitLab CI, CircleCI, Azure Pipelines). It uses standard exit codes (0=pass, 1=warnings, 2=critical), generates reports in SARIF format for GitHub Security tab, and supports baseline comparison to block PRs with security regressions.

- @see `guides/CI_CD.md` for complete workflows for GitHub Actions, GitLab CI, and CircleCI.
- @see `guides/EXAMPLES.md` section "CI/CD Integration" for quick examples.

### Client-Aware Panic Stop

The **Client-Aware Panic Stop** is an anti-DoS system that tracks rate limiting errors (HTTP 429) per individual client (identified by `x-client-id` header or IP address). It implements state isolation using `Map<clientId, RateLimitState>`, ensuring that a malicious client cannot bring down the proxy globally. Each client has its own independent strike counter.

- @see `ARCHITECTURE.md` section "Security Gateway v1.0" for system state diagram.
- @see `SECURITY.md` section "Runtime Security" for security implications.

### Commands (CLI)

**CLI Commands** are the 11 command-line tools provided by `mcp-verify`: `validate`, `doctor`, `fuzz`, `stress`, `play`, `mock`, `proxy`, `dashboard`, `interactive`, `init`, and `examples`. Each command has a specific purpose, from basic validation to active fuzzing and Security Gateway deployment. They support common flags like `--verbose`, `--lang`, `--output`, and `--format`.

- @see `COMMANDS.md` for complete reference of all commands and their options.
- @see `QUICKSTART.md` for usage examples of the most common commands.

### Context (Workspace Context)

A **Context** (or Workspace Context) is an isolated configuration environment in the Interactive Shell that allows managing multiple validation targets simultaneously (e.g., `dev`, `staging`, `prod`). Each context has its own target server, security profile, and report format configuration. The context state is persisted in `.mcp-verify/session.json`.

- @see `DEVELOPMENT.md` section "Testing Multi-Context Workspaces" for use cases.
- @see `apps/cli-verifier/src/shell/` for the context system implementation.

### CWE (Common Weakness Enumeration)

**CWE** is a software weakness categorization system maintained by MITRE. Each security finding in `mcp-verify` maps to a specific CWE (e.g., CWE-89 for SQL Injection, CWE-78 for Command Injection). This allows correlation with vulnerability databases and facilitates understanding of the threat type by security teams.

- @see `SECURITY_SCORING.md` for complete mapping of rules to CWE.
- @see https://cwe.mitre.org/ for the official CWE reference.

---

## D

### Documentation by Persona (Persona-driven Documentation)

**Documentation by Persona** is the documentation organization strategy of `mcp-verify` based on 4 clearly defined personas: (1) DevOps Engineer looking for quick wins, (2) Security Engineer doing deep audits, (3) Indie Developer learning MCP, and (4) Contributor expanding the project. Each .md file specifies its target audience and estimated reading time.

- @see `README.md` header "Documentation Index by Persona" for complete mapping.
- @see `CONTRIBUTING.md` for contributor guide (Persona 4).

---

## E

### Exit Codes

**Exit Codes** are numeric codes that `mcp-verify` returns when finishing execution to indicate the analysis result. Follows the standard: `0` = successful validation (no critical vulnerabilities), `1` = warnings found (medium/low vulnerabilities), `2` = critical vulnerabilities detected. These codes are essential for CI/CD integration where failing the build is necessary.

- @see `guides/CI_CD.md` section "Exit Code Handling" for usage examples in pipelines.
- @see `apps/cli-verifier/src/bin/index.ts` for exit code logic.

### Explainable Blocking

**Explainable Blocking** is the Security Gateway feature that provides complete forensic context when blocking a malicious request. Each error response includes: rule ID (e.g., SEC-003), severity (critical/high/medium/low), descriptive message, CWE/OWASP mapping, specific pattern that triggered the rule, affected parameter, and suggested remediation. This facilitates debugging and reduces perceived false positives.

- @see `ARCHITECTURE.md` section "Explainable Blocking" for JSON examples.
- @see `API_REFERENCE.md` section "Response Format (Blocked by Gateway)" for complete schema.

---

## F

### False Positives

**False Positives** are incorrect security detections where `mcp-verify` marks legitimate code as vulnerable. Layer 1 (Fast Rules) has **zero tolerance** for false positives by design. Layer 2 (Suspicious Rules) accepts <5% false positive rate due to its heuristic nature. Layer 3 (LLM Rules) may generate context-dependent false positives and requires manual review.

- @see `SECURITY.md` section "Known Limitations" for specific false positive scenarios.
- @see `RESPONSIBLE_USAGE.md` section "False Positives and Due Process" for ethical guidelines.

### Flexbox

**Flexbox** is a CSS layout module used in HTML reports generated by `mcp-verify` to create responsive layouts and flexible alignment of elements (findings, attack chains, risk heatmaps). It allows distributing space and aligning content efficiently without needing floats or absolute positioning.

- @see `libs/core/domain/reporting/html-generator.ts` for Flexbox usage in HTML templates.

### Smart Fuzzer

The **Smart Fuzzer** is the active security testing engine of `mcp-verify` v1.0. Unlike traditional fuzzers that send random data, it learns from server behavior (response times, structural errors, crashes) to adaptively generate and mutate attack payloads. It implements 12 mutation strategies, 8 payload generators, and 9 vulnerability detectors. The key feature is **Schema-Aware Fuzzing** which generates 150-250+ payloads per tool based on the declared JSON Schema.

- @see `RELEASE_NOTES.md` section "Smart Fuzzer v1.0" for complete capabilities.
- @see `CHANGELOG.md` for comparison with legacy generic fuzzer (10x improvement).

---

## G

### Classic Guardrails

**Classic Guardrails** are the 5 traditional proxy protections that run **AFTER** the Security Gateway (3-layer defense) approves a request: (1) HTTPS Enforcer - blocks non-HTTPS URLs, (2) Input Sanitizer - sanitizes user inputs, (3) PII Redactor - redacts sensitive data, (4) Rate Limiter - prevents DoS with configurable limits, and (5) Sensitive Command Blocker - blocks dangerous shell commands. They add 5-15ms latency.

- @see `SECURITY.md` section "Runtime Security" for complete flow request → gateway → guardrails → server.
- @see `libs/core/use-cases/proxy/guardrails/` for source code of each guardrail.

---

## I

### i18n (Internationalization)

**i18n** refers to the complete multi-language support in `mcp-verify`. Currently supports English (en) and Spanish (es) for all user messages, reports, and CLI output. Translations are managed with a type-safe system that automatically generates TypeScript types from JSON files. Language is selected with `--lang es` or `--lang en`.

- @see `docs/I18N-GUIDE.md` for guide on how to add new languages.
- @see `libs/core/domain/reporting/i18n.ts` for i18n system implementation.

### Interactive Shell (REPL)

The **Interactive Shell** (also called REPL) is the interactive mode of `mcp-verify` that provides contextual autocomplete, multi-context workspaces, security profiles, session persistence, automatic secret redaction, and output redirection (`>`, `>>`). It is launched with the `mcp-verify` command without arguments. Ideal for interactive exploration and iterative testing during development.

- @see `RELEASE_NOTES.md` section "Interactive Shell (REPL)" for complete features.
- @see `apps/cli-verifier/src/shell/` for shell implementation.

---

## J

### JSON-RPC

**JSON-RPC** is the communication protocol used by MCP (Model Context Protocol) for interaction between AI clients and servers. Uses the JSON-RPC 2.0 standard with methods like `initialize`, `tools/list`, `tools/call`, `resources/list`. The Security Gateway inspects and validates all JSON-RPC requests before allowing them to reach the target MCP server.

- @see https://www.jsonrpc.org/specification for the official JSON-RPC 2.0 spec.
- @see `API_REFERENCE.md` section "Proxy Command API" for request/response examples.

---

## L

### Integrity Lab

The **Integrity Lab** is the Build Integrity subsystem that implements SHA-256 binary verification, Git traceability (commit hash, branch, timestamp), and rotating history of the last 20 builds. Each build generates a unique hash stored in `.mcp-verify/integrity-history.json`. Users can verify that downloaded artifacts have not been altered.

- @see `ARCHITECTURE.md` section "Infrastructure Layer" for complete design.
- @see `libs/core/infrastructure/integrity/` for implementation.

### Layer 1: Fast Rules

**Layer 1 (Fast Rules)** is the first Security Gateway layer that uses pattern-based detection (regex, string matching) to identify critical vulnerabilities in <10ms. Includes rules for SQL Injection, Command Injection, Path Traversal, SSRF, XXE, among others. Has **zero tolerance** for false positives and is the most reliable of the 3 layers. Operates on static server analysis (discovery) and runtime parameters.

- @see `ARCHITECTURE.md` diagram "3-Layer Defense System" for request flow.
- @see `DEVELOPMENT.md` section "Adding Custom Fast Rules (Layer 1)" to extend with custom rules.

### Layer 2: Suspicious Rules

**Layer 2 (Suspicious Rules)** is the second Security Gateway layer that uses heuristic analysis and scoring to detect suspicious behaviors in <50ms. Includes detection of malicious tool chaining, excessive permissions, payload size anomalies, and type confusion patterns. Accepts <5% false positive rate and generates findings with `severity: medium` requiring manual review.

- @see `TESTING.md` section "Testing Layer 2: Suspicious Rules" for test strategy.
- @see `DEVELOPMENT.md` section "Adding Suspicious Rules (Layer 2)" for scoring guidelines.

### Layer 3: LLM Rules

**Layer 3 (LLM Rules)** is the third Security Gateway layer that uses semantic analysis powered by LLMs (Anthropic, OpenAI, Gemini, Ollama) to detect novel and context-aware attacks in 500-2000ms. **Disabled by default** for privacy reasons (sends data to external APIs), cost, and latency. Should only be enabled in development/testing environments or using Ollama (self-hosted). Detects prompt injection, data exfiltration patterns, and privilege escalation attempts.

- @see `RESPONSIBLE_USAGE.md` section "LLM Layer Privacy Implications" for privacy considerations.
- @see `DEVELOPMENT.md` section "Adding LLM Rules (Layer 3)" to implement custom LLM providers.

### LLM (Large Language Model)

**LLM** (Large Language Model) refers to the artificial intelligence models that `mcp-verify` can optionally use for deep semantic analysis of MCP servers. Supports 4 providers: (1) Gemini (FREE tier, Google), (2) Anthropic Claude (Haiku/Sonnet/Opus), (3) OpenAI GPT (4o/4o-mini), and (4) Ollama (self-hosted, privacy-safe). LLMs detect subtle threats that static rules cannot capture.

- @see `guides/LLM_SETUP.md` for API key configuration and recommended models.
- @see `libs/core/domain/quality/providers/` for implementation of each provider.

---

## M

### MCP (Model Context Protocol)

**MCP** (Model Context Protocol) is the open protocol developed by Anthropic that allows AI applications to expose tools, resources, and prompts in a standardized way. Defines a JSON-RPC spec for client-server communication, schemas for input validation, and capability discovery conventions. `mcp-verify` is the first enterprise-grade security tool designed specifically to validate MCP servers.

- @see https://modelcontextprotocol.io/ for the official protocol spec.
- @see `README.md` for the motivation of why MCP needs security tools.

### Mermaid Diagrams

**Mermaid Diagrams** are technical diagrams embedded in Markdown using Mermaid syntax (flowcharts, class diagrams, state machines, sequence diagrams). `mcp-verify` uses them extensively in `ARCHITECTURE.md` to visualize Security Gateway architecture, request flows, Panic Stop system, and cache architecture. GitHub automatically renders these diagrams.

- @see `ARCHITECTURE.md` section "Security Gateway v1.0 Architecture" for 4 complete Mermaid diagrams.
- @see https://mermaid.js.org/ for official Mermaid syntax documentation.

### Monorepo

**Monorepo** is the code organization strategy where multiple related applications and libraries live in a single Git repository. `mcp-verify` uses pnpm workspaces to manage 4 apps (`cli-verifier`, `mcp-server`, `vscode-extension`, `web-dashboard`) and 5 shared libs (`core`, `fuzzer`, `protocol`, `shared`, `transport`). This facilitates code sharing, integrated testing, and coordinated versioning.

- @see `ARCHITECTURE.md` section "Project Structure" for complete monorepo tree.
- @see root `package.json` for pnpm workspace configuration.

---

## O

### OWASP

**OWASP** (Open Web Application Security Project) is the non-profit organization that publishes the most critical web vulnerability lists (OWASP Top 10) and security standards. `mcp-verify` maps each security rule to OWASP categories (e.g., A03:2021 - Injection, A01:2021 - Broken Access Control). This facilitates communication with security teams and compliance frameworks.

- @see `SECURITY_SCORING.md` for complete mapping of 60 rules to OWASP categories.
- @see https://owasp.org/www-project-top-ten/ for the updated OWASP Top 10.

---

## P

### Panic Mode

**Panic Mode** is the final state of the Panic Stop system where a client is permanently blocked after receiving 3 strikes (3 consecutive HTTP 429 errors). In Panic Mode, all client requests return error code 503 with message "Client in PANIC MODE - permanently blocked". Only restarting the proxy can reset this state. Prevents distributed denial of service attacks.

- @see `ARCHITECTURE.md` diagram "Panic Stop State Machine" for state flow visualization.
- @see `QUICKSTART.md` section "Troubleshooting > Proxy: Client in Panic Mode" for remediation.

### Security Profiles

**Security Profiles** are predefined configurations of fuzzing and security analysis intensity in the Interactive Shell: (1) `light` - 25 payloads, ideal for fast CI/CD, (2) `balanced` - 50 payloads, recommended default, (3) `aggressive` - 100 payloads, for exhaustive audits. Users can create custom profiles by saving configuration and sharing it between projects.

- @see `DEVELOPMENT.md` section "Testing Multi-Context Workspaces & Security Profiles" for testing.
- @see `apps/cli-verifier/src/commands/profiles/` for profile implementation.

### Progressive Backoff

**Progressive Backoff** is the incremental penalty strategy in the Panic Stop system: Strike 1 → 30 seconds of blocking, Strike 2 → 60 seconds, Strike 3 → permanent. Timers automatically reset after expiration, allowing legitimate clients to recover from transient rate limit errors. This gradation prevents premature blocking while protecting against persistent abuse.

- @see `SECURITY.md` table "3-Strike Panic Stop System" for exact backoff values.
- @see `DEVELOPMENT.md` section "Panic Stop Tuning" to customize timers.

### Security Gateway v1.0

The **Security Gateway v1.0** is the real-time defense system that intercepts requests between AI clients and MCP servers. Implements a 3-layer progressive system (Fast/Suspicious/LLM Rules), anti-DoS Panic Stop system, SHA-256 cache with LRU eviction, client-aware isolation, explainable blocking, and audit logging. It is the flagship feature of `mcp-verify` v1.0.

- @see `RELEASE_NOTES.md` section "Security Gateway v1.0" for complete feature description.
- @see `ARCHITECTURE.md` section "Security Gateway v1.0 Architecture" for deep technical design.

---

## R

### Reports (JSON, HTML, SARIF, MD)

**Reports** are the output formats that `mcp-verify` generates after validation: (1) **JSON** - machine-readable for CI/CD pipelines, (2) **HTML** - interactive report with visual attack chains and risk heatmaps, (3) **SARIF 2.1.0** - direct integration with GitHub Security tab, (4) **Markdown** - GitHub-friendly for PRs, (5) **SVG Badges** - shields.io format for README. Format is specified with `--format json|html|sarif|md`.

- @see `guides/EXAMPLES.md` section "Report Formats" for examples of each format.
- @see `libs/core/domain/reporting/` for generators of each report format.

---

## S

### Sandbox (Isolated Environment)

The **Sandbox** is the isolated execution environment (Deno-based) that `mcp-verify` can use to run MCP servers without giving them access to the filesystem, environment variables, or host network. Enabled with `--sandbox`. **Critical** for validating third-party servers or untrusted code. Only works with Node.js/Deno servers, not Python. The sandbox is in experimental state in v1.0.

- @see `SECURITY.md` section "Sandbox Execution (Safety First)" for limitations.
- @see `libs/core/infrastructure/sandbox/deno-sandbox.ts` for technical implementation.

### SARIF (Static Analysis Results Interchange Format)

**SARIF** is the standard JSON format for static security analysis results interchange, maintained by OASIS. `mcp-verify` generates SARIF 2.1.0 reports that can be loaded directly into GitHub Security tab, allowing inline visualization of vulnerabilities in code view. Each finding includes location, rule metadata, severity, and remediation guidance.

- @see `libs/core/domain/reporting/sarif-generator.ts` for SARIF generator.
- @see https://sarifweb.azurewebsites.net/ for official SARIF spec.

### Schema-Aware Fuzzing

**Schema-Aware Fuzzing** is the key innovation of Smart Fuzzer v1.0 that parses JSON Schemas declared by MCP server tools to generate 150-250+ targeted payloads per tool. Generates specific attacks: type confusion (send number when expecting string), boundary violations (maxLength + 1), enum bypass (send role: 'admin' when only allowing ['user', 'guest']), format-specific attacks (SSRF in URI fields), and prototype pollution. This replaces the legacy generic fuzzer which had 90% rejection rate.

- @see `CHANGELOG.md` section "Schema-Aware Fuzzing" for comparison with generic fuzzer.
- @see `libs/core/use-cases/fuzzer/fuzzer.ts` for schema parser implementation.

### Scroll (Smooth Scrolling)

**Scroll** refers to the smooth scroll behavior implemented in `mcp-verify` HTML reports to navigate between sections (Summary, Security Analysis, Quality Analysis). Uses `scroll-behavior: smooth` in CSS and internal anchors to improve UX when reviewing long reports with multiple findings.

- @see `libs/core/domain/reporting/html-generator.ts` for smooth scrolling implementation.

### Security Score

The **Security Score** is the unified 0-100 metric that `mcp-verify` calculates based on all detected security findings. The score maps to operational tiers: ≥90 = Production-ready, ≥70 = Staging-ready, ≥50 = Internal tools only, <50 = Not recommended. Scoring considers severity (critical=20pts, high=10pts, medium=5pts, low=2pts), number of findings, and coverage of the 60 security rules.

- @see `SECURITY_SCORING.md` for exact score calculation formula.
- @see `README.md` table "Security Score Tiers" for score interpretation.

### 3-Layer Defense System

The **3-Layer Defense System** is the progressive defense architecture of the Security Gateway: Layer 1 (Fast Rules, <10ms, pattern-based), Layer 2 (Suspicious Rules, <50ms, heuristic-based), Layer 3 (LLM Rules, 500-2000ms, AI-powered). Each layer has early exit optimization: if Layer 1 blocks, Layers 2/3 are not executed, minimizing latency. Layer 3 is opt-in and disabled by default for privacy.

- @see `ARCHITECTURE.md` Mermaid diagram "Request Flow with Early Exits" for flow visualization.
- @see `SECURITY.md` comparative table of the 3 layers with latencies and costs.

### Strikes (3-Strike System)

**Strikes** are the rate limiting violation counter that Panic Stop tracks per client. Strike 1: first HTTP 429 error detected (30s backoff), Strike 2: second 429 before Strike 1 backoff expires (60s backoff), Strike 3: third 429 (permanent Panic Mode). Each client has its own isolated counter in `Map<clientId, RateLimitState>`, preventing one client from affecting others.

- @see `TESTING.md` section "Testing Panic Stop System" for 3-strike test cases.
- @see `RESPONSIBLE_USAGE.md` section "Panic Stop System and Fairness" for ethical considerations.

### Supabase

**Supabase** is the open-source platform (alternative to Firebase) that could be used in future versions of `mcp-verify` Web Dashboard for backend-as-a-service (BaaS). Would provide authentication, PostgreSQL database, and real-time subscriptions for real-time security metrics. **Note**: Not implemented in v1.0, is a placeholder for future features.

- @see https://supabase.com/ for more information about the platform.

---

## T

### Tailwind CSS

**Tailwind CSS** is the utility-first CSS framework used in the `mcp-verify` Web Dashboard (app in development at `apps/web-dashboard/`). Allows building responsive UIs quickly using predefined utility classes (e.g., `flex`, `p-4`, `text-blue-500`). The dashboard visualizes security reports, real-time metrics, and Security Gateway audit logs.

- @see `apps/web-dashboard/` for dashboard source code (experimental feature).
- @see https://tailwindcss.com/ for official Tailwind documentation.

### Tool (MCP Tool)

A **Tool** in the MCP context is a function that an MCP server exposes for AI clients to invoke. Each tool has a unique `name`, `description` explaining its purpose, and `inputSchema` (JSON Schema) defining required and optional parameters. `mcp-verify` analyzes tools to detect vulnerabilities in their schemas, descriptions (exposed secrets), and runtime behavior (via fuzzing).

- @see Official MCP Spec at https://modelcontextprotocol.io/docs/concepts/tools for complete definition.
- @see `libs/core/domain/mcp-server/entities/validation.types.ts` for TypeScript tool types.

### Transport (Transport Layer)

The **Transport** (Transport Layer) is the communication layer that `mcp-verify` uses to connect to MCP servers. Supports 3 transports: (1) **STDIO** - stdin/stdout communication, ideal for local servers, (2) **HTTP** - synchronous HTTP requests, (3) **SSE** (Server-Sent Events) - unidirectional server streaming. Auto-detects based on target or specify with `--transport stdio|http|sse`.

- @see `ARCHITECTURE.md` section "Transport Layer" for adapter design.
- @see `libs/transport/` for implementation of each transport (feature in development).

---

## V

### Validation

**Validation** is the core `mcp-verify` process that verifies an MCP server complies with the protocol spec, has no security vulnerabilities, and maintains quality standards. Includes: (1) Protocol Compliance (handshake, discovery, schema validation), (2) Security Analysis (60 OWASP-aligned rules), (3) Quality Analysis (naming consistency, documentation). Executed with the `mcp-verify validate` command.

- @see `QUICKSTART.md` for basic validation examples.
- @see `libs/core/use-cases/validator/validator.ts` for validator implementation.

### VSCode Extension

The **VSCode Extension** is the `mcp-verify` integration in Visual Studio Code that provides: (1) Code Actions for quick vulnerability fixes, (2) Real-time inline Diagnostics in the editor, (3) WebView Report Panel to visualize HTML reports, (4) Commands in Command Palette to execute validations. Located at `apps/vscode-extension/` and will be published to VS Code Marketplace in v1.2+.

- @see `apps/vscode-extension/README.md` for features and installation.
- @see `apps/vscode-extension/src/extension.ts` for extension entry point.

### Real Vulnerability

A **Real Vulnerability** is a genuine security weakness in code that can be exploited by an attacker to compromise confidentiality, integrity, or availability. Distinguished from a false positive in that: (1) a viable attack vector exists, (2) impact is demonstrable, (3) does not depend on specific deployment configuration. Security Gateway Layer 1 only detects real vulnerabilities (zero false positives).

- @see `SECURITY.md` section "Known Limitations" for examples of what does NOT constitute a real vulnerability.
- @see `QUICKSTART.md` section "Interpreting Results" to differentiate real vulnerabilities from false positives.

---

**Last Updated**: 2026-03-08
**Project Version**: v1.0.0

For suggestions or corrections to this glossary, open an issue in the GitHub repository.
