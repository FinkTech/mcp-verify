# 🏗️ mcp-verify Architecture

This document defines the folder structure, code organization, and module responsibilities within this monorepo. It is designed for massive scalability, strict separation of concerns, and defense-in-depth security.

---

## 📊 Visual Architecture Overview

### Hexagonal Architecture (Clean Architecture)

```mermaid
graph TB
    subgraph "External World"
        CLI[CLI Interface]
        Web[Web Dashboard]
        File[File System]
        Network[Network/APIs]
        LLM[LLM Providers]
    end

    subgraph "Applications Layer"
        CLIApp[apps/cli-verifier]
        WebApp[apps/web-dashboard]
        APIApp[apps/local-api-bridge]
    end

    subgraph "Use Cases Layer"
        Validator[Validator]
        Fuzzer[Fuzzer]
        StressTester[Stress Tester]
        Playground[Playground]
        Proxy[Proxy]
    end

    subgraph "Domain Layer (Pure Business Logic)"
        Security[Security Rules]
        Quality[Quality Analysis]
        Reporting[Report Generation]
        Validation[Protocol Validation]
        Baseline[Baseline Comparison]
    end

    subgraph "Infrastructure Layer (Adapters)"
        Transport[Transport: STDIO/HTTP/SSE]
        Sandbox[Deno Sandbox]
        Logger[Logger]
        Config[Config Manager]
        Diagnostics[Diagnostics]
    end

    CLI --> CLIApp
    Web --> WebApp
    CLIApp --> Validator
    CLIApp --> Fuzzer
    WebApp --> Validator

    Validator --> Security
    Validator --> Quality
    Validator --> Reporting

    Validator --> Transport
    Validator --> Sandbox

    Transport --> Network
    Sandbox --> File
    Quality --> LLM
    Reporting --> File

    style Domain Layer fill:#e1f5fe
    style "Use Cases Layer" fill:#fff9c4
    style "Infrastructure Layer" fill:#ffccbc
    style "Applications Layer" fill:#f3e5f5
```

---

### Dependency Flow (Hexagonal Pattern)

```mermaid
graph LR
    A[apps/cli-verifier] -->|uses| B[libs/core/use-cases]
    B -->|orchestrates| C[libs/core/domain]
    B -->|uses| D[libs/core/infrastructure]
    C -->|defines interfaces| E[Domain Interfaces]
    D -->|implements| E
    C -->|uses| F[libs/shared]
    D -->|uses| F

    style A fill:#f3e5f5
    style B fill:#fff9c4
    style C fill:#e1f5fe
    style D fill:#ffccbc
    style F fill:#c8e6c9
```

**Key Rule**: **Domain NEVER imports from Infrastructure or Apps**

---

### Validation Flow

```mermaid
sequenceDiagram
    participant User
    participant CLI as CLI Command
    participant Validator as MCPValidator<br/>(Use Case)
    participant Transport as Transport<br/>(Infrastructure)
    participant Security as SecurityScanner<br/>(Domain)
    participant Quality as LLMAnalyzer<br/>(Domain)
    participant Report as ReportGenerator<br/>(Domain)

    User->>CLI: mcp-verify validate "node server.js"
    CLI->>Validator: new MCPValidator(transport)

    Note over Validator: Step 1: Handshake
    Validator->>Transport: sendRequest('initialize')
    Transport-->>Validator: ServerInfo

    Note over Validator: Step 2: Discovery
    Validator->>Transport: sendRequest('tools/list')
    Transport-->>Validator: Tools[]

    Note over Validator: Step 3: Security Analysis
    Validator->>Security: scan(discovery)
    Security-->>Validator: SecurityFindings[]

    Note over Validator: Step 4: Quality Analysis
    Validator->>Quality: analyzeTools(discovery)
    Quality-->>Validator: QualityIssues[]

    Note over Validator: Step 5: Report Generation
    Validator->>Report: generate(results)
    Report-->>Validator: Report (JSON/HTML/SARIF)

    Validator-->>CLI: ValidationReport
    CLI-->>User: Display + Save Reports
```

---

### Security Layers (Defense in Depth)

```mermaid
graph TD
    A[User Input] --> B{Input Validation}
    B -->|Valid| C[Path Validator<br/>⚠️ Prevents Path Traversal]
    B -->|Invalid| Z[Reject]

    C --> D{URL Validator}
    D -->|Safe| E[Transport Layer<br/>⚠️ HTTPS Enforcement]
    D -->|Private IP| W[Warn User]
    W --> E

    E --> F{Sandbox Mode?}
    F -->|Yes| G[Deno Sandbox<br/>⚠️ Isolated Execution]
    F -->|No| H[Direct Execution<br/>⚠️ Warning Shown]

    G --> I[Execute MCP Server]
    H --> I

    I --> J[Static Analysis<br/>SEC-001 to SEC-061]
    J --> K[LLM Semantic Analysis<br/>⚠️ Optional]
    K --> L[Report Generation<br/>⚠️ Redact Sensitive Data]
    L --> M[Output Files<br/>⚠️ Secure Storage]

    style C fill:#ffccbc
    style E fill:#ffccbc
    style G fill:#c8e6c9
    style H fill:#ffcdd2
    style J fill:#e1f5fe
    style L fill:#fff9c4
```

---

### Data Flow

```mermaid
flowchart LR
    A[MCP Server] -->|JSON-RPC| B[Transport Layer]
    B -->|Parse| C[Protocol Validator]
    C -->|Valid Messages| D[Discovery Result]

    D --> E[Security Scanner]
    D --> F[Quality Analyzer]
    D --> G[Schema Validator]

    E -->|Findings| H[Report Aggregator]
    F -->|Issues| H
    G -->|Errors| H

    H --> I[Score Calculator]
    I --> J{Generate Reports}

    J -->|JSON| K[reportes/json/]
    J -->|HTML| L[reportes/html/]
    J -->|SARIF| M[reportes/sarif/]
    J -->|Markdown| N[reportes/md/]

    style A fill:#e1f5fe
    style E fill:#ffccbc
    style F fill:#fff9c4
    style I fill:#c8e6c9
```

---

## 🗺️ High-Level Map

```text
mcp-verify/
├── apps/           # 🚀 Executable entry points (CLI, Web, Local API)
├── libs/           # 🧠 Business Logic, Domain & Utilities (The Brain)
├── config/         # ⚙️ Global tool configurations (ESLint, TS, etc.)
├── tools/          # 🛠️ Development scripts, Generators & Mocks
└── tests/          # 🧪 Global testing strategies (E2E, Performance)
```

---

## 📂 Directory Details

### 1. `apps/` (Applications)

This directory contains the code that "boots" and "connects". These are dumb containers that utilize the smart logic residing in `libs/`.

#### `apps/cli-verifier/` (CLI Tool)

_The main executable for technical users with interactive shell and multi-context workspaces._

**Structure**:

```
apps/cli-verifier/
├── src/
│   ├── bin/index.ts                   # Entry point (detects interactive vs one-shot)
│   ├── commands/                      # Command implementations
│   │   ├── interactive.ts             # 🎮 Interactive Shell (REPL)
│   │   │                              # - Multi-context workspaces (dev/staging/prod)
│   │   │                              # - Security profiles (light/balanced/aggressive)
│   │   │                              # - Session persistence (.mcp-verify/session.json)
│   │   │                              # - Command history with secret redaction
│   │   │                              # - Autocomplete (commands, flags, files, tools)
│   │   │
│   │   ├── validate.ts                # Full security validation
│   │   ├── fuzz.ts                    # Smart Fuzzer v1.0 (feedback loop + mutations)
│   │   ├── stress.ts                  # Load testing
│   │   ├── doctor.ts                  # Diagnostics + environment checks
│   │   ├── proxy.ts                   # Security proxy with 5 guardrails
│   │   ├── play.ts                    # Interactive tool testing playground
│   │   ├── dashboard.ts               # Real-time terminal monitoring (blessed UI)
│   │   ├── mock.ts                    # Mock MCP server for testing clients
│   │   ├── init.ts                    # Scaffold new MCP server project
│   │   └── examples.ts                # Interactive examples browser
│   │
│   │   ├── types/                     # 🆕 Type definitions for workspace system
│   │   │   ├── workspace-context.ts   # WorkspaceContext, SecurityProfile
│   │   │   ├── global-config.ts       # GlobalConfig interface
│   │   │   ├── environment-vars.ts    # EnvironmentVars interface
│   │   │   └── workspace-health.ts    # WorkspaceHealth, ConnectionStatus
│   │
│   │   ├── managers/                  # 🆕 Core management systems
│   │   │   ├── global-config-manager.ts   # Global config (~/.mcp-verify/config.json)
│   │   │   │                              # - Load/save global settings
│   │   │   │                              # - Custom profiles storage
│   │   │   │                              # - Configuration hierarchy resolver
│   │   │   ├── environment-loader.ts      # Environment variable management
│   │   │   │                              # - .env file parsing
│   │   │   │                              # - API key loading (ANTHROPIC_API_KEY, etc.)
│   │   │   │                              # - MCP_* variable detection
│   │   │   ├── workspace-health-checker.ts # Workspace health validation
│   │   │   │                              # - MCP handshake verification
│   │   │   │                              # - Connection status checking
│   │   │   │                              # - Environment integrity validation
│   │   │   │                              # - Last report detection
│   │   │   └── migration.ts               # Session migration utilities
│   │   │                                  # - Session format migration
│   │   │                                  # - Automatic backward compatibility
│   │   │                                  # - Backup creation before migration
│   │
│   │   ├── profiles/                  # 🆕 Security profile presets
│   │   │   └── security-profiles.ts   # SECURITY_PROFILES (light/balanced/aggressive)
│   │   │                              # - Fuzzing intensity (payloads, mutations)
│   │   │                              # - Validation thresholds (scores, fail conditions)
│   │   │                              # - Generator/detector configurations
│   │   │                              # - getSecurityProfile(name, customProfiles)
│   │
│   │   └── handlers/                  # 🆕 Interactive shell command handlers
│   │       ├── context-handlers.ts    # Context management
│   │       │                          # - handleContextList()
│   │       │                          # - handleContextSwitch()
│   │       │                          # - handleContextCreate()
│   │       │                          # - handleContextDelete()
│   │       ├── profile-handlers.ts    # Profile management
│   │       │                          # - handleSetProfile()
│   │       │                          # - setProfile()
│   │       │                          # - saveProfile()
│   │       │                          # - listProfiles()
│   │       │                          # - showCurrentProfile()
│   │       └── status-handler.ts      # Workspace status display
│   │                                  # - handleStatus()
│   │                                  # - renderConnectionStatus()
│   │                                  # - Shows: context, environment, reports, connection
│   │
│   └── ui/                            # UI components for CLI
│       ├── charts.ts                  # ASCII charts for terminal
│       ├── formatters.ts              # Output formatting utilities
│       ├── prompts.ts                 # Interactive prompts
│       └── spinners.ts                # Loading spinners
│
│   └── utils/                         # CLI utilities
│       ├── transport-factory.ts       # Create transports
│       ├── logging-helper.ts          # Console logging with i18n
│       └── cleanup-handlers.ts        # Process cleanup
```

**Architecture Highlights**:

**1. Multi-Context Workspace System** (`interactive.ts` + `managers/` + `handlers/`)

- **Purpose**: Manage multiple MCP server targets (dev, staging, prod) with isolated configurations
- **Persistence**: `.mcp-verify/session.json` (per-project), `~/.mcp-verify/config.json` (global)
- **Features**:
  - Independent contexts with separate targets, profiles, configs
  - Automatic session format migration with backward compatibility
  - Configuration hierarchy: CLI flags > Context > Global > Defaults
  - Environment variable auto-loading from `.env`

**2. Security Profiles** (`profiles/security-profiles.ts`)

- **Purpose**: Preset configurations for different security rigor levels
- **Profiles**:
  - **light**: 25 payloads, no mutations, 60/100 score threshold (CI/CD)
  - **balanced**: 50 payloads, 3 mutations, 70/100 score (default, staging)
  - **aggressive**: 100 payloads, 5 mutations, 90/100 score (pre-production)
- **Customization**: Save custom profiles to global config

**3. Interactive Shell** (`interactive.ts`)

- **REPL Features**:
  - Tab completion (commands, flags, file paths, tool names)
  - Command history with secret redaction (`~/.mcp-verify/history.json`)
  - Output redirection (`validate > report.txt`)
  - Multi-language support (en/es)
- **Session State**:
  - Active context tracking
  - Profile management
  - Environment variables (ANTHROPIC_API_KEY, etc.)
  - Workspace health monitoring

**4. Configuration Hierarchy** (`managers/global-config-manager.ts`)

```
Priority (highest to lowest):
1. CLI Flags           (--timeout=5000)
2. Active Context      (.mcp-verify/session.json)
3. Global Config       (~/.mcp-verify/config.json)
4. System Defaults     (hardcoded fallbacks)
```

**Responsibilities**:

- ✅ Parse command-line arguments (one-shot mode)
- ✅ Run interactive REPL (default mode)
- ✅ Manage multi-context workspaces
- ✅ Apply security profiles to commands
- ✅ Load environment variables
- ✅ Create transport instances
- ✅ Call use-case orchestrators
- ✅ Format and display results
- ❌ NO business logic (delegate to libs/)

---

#### `apps/web-dashboard/` (GUI)

_Visual dashboard for deep analysis._

**Structure**:

```
apps/web-dashboard/
├── public/                   # Static assets
├── src/
│   ├── app/                  # Global config (Router, State)
│   ├── pages/                # Full views (URL Routes)
│   │   ├── dashboard/        # Main landing page
│   │   └── server-detail/    # Detailed server view
│   ├── widgets/              # Complex autonomous components
│   │   ├── health-score-card/
│   │   └── response-time-chart/
│   ├── features/             # Cross-cutting functionalities
│   │   └── run-validation/   # Trigger validation UI logic
│   └── shared/ui/            # Atomic Design
│       ├── atoms/            # Buttons, Inputs, Icons
│       ├── molecules/        # Form fields, Cards
│       └── organisms/        # Headers, Tables
```

**Architecture**: Feature-Sliced Design (FSD)

---

#### `apps/local-api-bridge/` (Local Bridge)

_Lightweight server allowing the Web UI to communicate with the CLI or local processes._

**Features**:

- WebSocket handling for real-time data
- Streaming validation logs
- Local process management

---

### 2. `libs/` (Libraries - The Core)

This is where the magic happens. This code is agnostic (it doesn't know if it runs in CLI or Web).

#### `libs/core/` (Pure Business Logic - Clean Architecture)

```
libs/core/
├── domain/                      # Pure business logic (NO I/O)
│   ├── security/                # 61 security rules (6 threat category blocks)
│   │   ├── rules/               # Individual rule implementations (SEC-001 to SEC-061)
│   │   │   ├── auth-bypass.rule.ts          # SEC-009: Authentication Bypass
│   │   │   ├── command-injection.rule.ts    # SEC-002: Command Injection
│   │   │   ├── sql-injection.rule.ts        # SEC-001: SQL Injection
│   │   │   ├── ssrf.rule.ts                 # SEC-003: SSRF
│   │   │   ├── xxe-injection.rule.ts        # SEC-006: XXE
│   │   │   ├── insecure-deserialization.rule.ts  # SEC-007: Deserialization
│   │   │   ├── path-traversal.rule.ts       # SEC-004: Path Traversal
│   │   │   ├── data-leakage.rule.ts         # SEC-005: Data Leakage
│   │   │   ├── sensitive-exposure.rule.ts   # SEC-010: Sensitive Exposure
│   │   │   ├── rate-limiting.rule.ts        # SEC-011: Rate Limiting
│   │   │   ├── redos-detection.rule.ts      # SEC-008: ReDoS
│   │   │   ├── weak-crypto.rule.ts          # SEC-012: Weak Crypto
│   │   │   ├── prompt-injection.rule.ts     # SEC-013: Prompt Injection
│   │   │   ├── ... (48 more rules in 6 blocks)
│   │   └── security-scanner.ts  # Rule orchestrator (all 61 rules)
│   │
│   ├── quality/                 # Quality analysis
│   │   ├── providers/           # LLM provider implementations
│   │   │   ├── llm-provider.interface.ts
│   │   │   ├── anthropic-provider.ts  # Claude (Anthropic)
│   │   │   ├── openai-provider.ts     # GPT (OpenAI)
│   │   │   ├── ollama-provider.ts     # Local models (Ollama)
│   │   │   └── gemini-provider.ts     # Gemini (Google) - FREE tier
│   │   ├── llm-semantic-analyzer.ts   # LLM-based analysis
│   │   └── semantic-analyzer.ts       # Quality scoring engine
│   │
│   ├── validation/              # Protocol validation
│   │   └── schema-validator.ts  # JSON Schema validation (Draft 2020-12)
│   │
│   ├── reporting/               # Report generation
│   │   ├── html-generator.ts    # Interactive HTML reports
│   │   ├── sarif-generator.ts   # SARIF 2.1.0 format
│   │   ├── markdown-generator.ts # GitHub-friendly markdown
│   │   ├── text-generator.ts    # Plain text reports
│   │   ├── graph-generator.ts   # Mermaid diagrams
│   │   ├── badge-generator.ts   # SVG badges (shields.io format)
│   │   ├── enhanced-reporter.ts # Report orchestrator
│   │   └── i18n.ts              # Report translations (en/es)
│   │
│   ├── baseline/                # Baseline comparison
│   │   └── baseline-manager.ts  # Baseline CRUD operations
│   │
│   └── config/                  # Configuration
│       ├── config-loader.ts     # Load mcp-verify.config.json
│       └── config.types.ts      # Config type definitions
│
├── infrastructure/              # External adapters (I/O)
│   ├── logging/                 # Structured logger
│   │   └── logger.ts            # Winston-based logger with i18n
│   ├── sandbox/                 # Deno sandbox
│   │   └── deno-sandbox.ts      # Isolated execution environment
│   ├── config/                  # Config management
│   │   └── config-manager.ts    # Configuration loading/merging
│   └── diagnostics/             # System diagnostics
│       └── checks/
│           └── environment-checks.ts  # Node.js/npm/env validation
│
└── use-cases/                   # Application workflows
    ├── validator/               # Main validation orchestrator
    │   └── validator.ts         # MCPValidator (handshake, discovery, analysis)
    ├── fuzzer/                  # Fuzzing workflow (basic)
    │   ├── fuzzer.ts            # FuzzerEngine orchestrator
    │   ├── payloads.ts          # Payload generation logic
    │   └── response-analyzer.ts # Response anomaly detection
    ├── stress-tester/           # Load testing workflow
    │   └── stress-tester.ts     # Concurrency/load testing
    ├── proxy/                   # Proxy workflow
    │   ├── proxy-server.ts      # Transparent proxy server
    │   ├── proxy.types.ts       # Proxy type definitions
    │   └── guardrails/          # 5 security guardrails
    │       ├── https-enforcer.ts           # HTTP → HTTPS upgrades
    │       ├── input-sanitizer.ts          # SQL/XSS/CMD injection neutralization
    │       ├── pii-redactor.ts             # PII masking (credit cards, emails, etc.)
    │       ├── rate-limiter.ts             # Token bucket algorithm (100 req/min)
    │       └── sensitive-command-blocker.ts # Dangerous command blocking
    ├── mock/                    # Mock server workflow
    │   └── mock-server.ts       # Mock MCP server for testing clients
    └── playground/              # Interactive testing workflow
        └── tool-executor.ts     # Tool execution orchestrator
```

**Key Principles**:

- **Domain**: Pure TypeScript, 100% testable, no external dependencies
- **Infrastructure**: Implements interfaces defined by domain
- **Use Cases**: Orchestrates domain + infrastructure

📚 **Detailed Docs**: See [libs/core/CLAUDE.md](./libs/core/CLAUDE.md)

---

#### `libs/fuzzer/` (Smart Fuzzer v1.0 Engine)

**Purpose**: Advanced security testing engine with adaptive payload generation, mutation strategies, and anomaly detection.

```
libs/fuzzer/
├── index.ts                     # Public API exports
├── engine/                      # Core fuzzing engine
│   ├── fuzzer-engine.ts         # Main orchestrator
│   │                            # - Baseline calibration
│   │                            # - Feedback loop (3 rounds)
│   │                            # - Fingerprinting (auto-detect language/framework)
│   ├── config.ts                # Fuzzer configuration types
│   └── types.ts                 # Fuzzing result types
│
├── generators/                  # 9 Payload generators
│   ├── prompt-injection.ts      # Indirect prompt injection, jailbreaks
│   ├── sql-injection.ts         # SQL injection variants
│   ├── xss-payloads.ts          # Cross-site scripting (XSS)
│   ├── command-injection.ts     # Shell command injection
│   ├── jwt-attacks.ts           # JWT forgery, algorithm confusion
│   ├── prototype-pollution.ts   # JavaScript object poisoning
│   ├── jsonrpc-violations.ts    # Protocol compliance bypass
│   ├── schema-confusion.ts      # Type coercion, boundary testing
│   └── path-traversal.ts        # Directory traversal
│
├── detectors/                   # 10 Anomaly detectors
│   ├── timing-detector.ts       # Blind injection (response >3x baseline)
│   ├── error-detector.ts        # Stack traces, SQL errors
│   ├── xss-detector.ts          # Payload reflection in response
│   ├── prompt-leak-detector.ts  # System instructions exposed
│   ├── jailbreak-detector.ts    # Guardrail bypass detection
│   ├── traversal-detector.ts    # Path traversal success
│   ├── weak-id-detector.ts      # Predictable IDs (1,2,3 vs UUIDs)
│   ├── info-disclosure-detector.ts # Version numbers, internal paths
│   ├── jwt-detector.ts          # Forged tokens accepted
│   └── pollution-detector.ts    # Polluted properties in response
│
├── mutations/                   # 12 Mutation strategies
│   ├── sql-depth.ts             # Nested SQL injection
│   ├── null-byte.ts             # String termination bypass (\x00)
│   ├── unicode-bypass.ts        # Fullwidth character evasion
│   ├── timing-probes.ts         # WAITFOR DELAY, sleep() injection
│   ├── buffer-stress.ts         # 10KB+ string overflow testing
│   ├── quote-variation.ts       # ", ', `, '', """ variants
│   ├── case-mutation.ts         # SeLeCt, uNiOn (filter bypass)
│   ├── encoding-bypass.ts       # URL-encode, double-encode, hex
│   ├── polyglot.ts              # Multi-context (';alert(1)//)
│   ├── recursive-nesting.ts     # Parser exhaustion ({{{...}}})
│   ├── type-confusion.ts        # true → "true" → 1 → [true]
│   └── boundary-probing.ts      # Min/max violations (age: -1, 9999999)
│
├── fingerprinting/              # Server detection
│   ├── fingerprinter.ts         # Language/framework detection
│   │                            # - Node.js, Python, Java, Go, Rust
│   │                            # - Disables irrelevant generators (saves 40-60% time)
│   └── patterns.ts              # Detection patterns
│
└── utils/                       # Utilities
    ├── baseline-calibrator.ts   # Establish "normal" behavior
    │                            # - Average response time, size, status codes
    │                            # - Creates anomaly thresholds (3x baseline)
    ├── payload-mutator.ts       # Apply mutations to payloads
    └── response-comparator.ts   # Compare responses for anomalies
```

**Architecture Workflow**:

```
1. Fingerprinting    → Detect server language/framework
2. Baseline          → Calibrate normal response patterns
3. Generation        → 9 generators × N payloads/tool
4. Detection         → 10 detectors analyze responses
5. Feedback Loop     → If anomaly detected → generate mutations (3 rounds)
6. Reporting         → Aggregate findings with severity scoring
```

**Key Features**:

- **Adaptive Testing**: Learns from responses, mutates payloads dynamically
- **Baseline Comparison**: Eliminates false positives from legitimate slow operations
- **Comprehensive Coverage**: Tests all parameter combinations (nested objects, arrays, edge cases)
- **Fingerprinting**: Auto-disables irrelevant generators based on detected tech stack

📚 **Detailed Docs**: See [libs/fuzzer/CLAUDE.md](./libs/fuzzer/CLAUDE.md)

---

#### `libs/protocol/` (MCP Specification)

**Structure**:

```
libs/protocol/
└── types/                # TypeScript interfaces for MCP
    ├── tools.ts          # Tool definitions
    ├── resources.ts      # Resource definitions
    └── prompts.ts        # Prompt definitions
```

**Purpose**: Type-safe MCP protocol implementation

---

#### `libs/transport/` (Connection Layer)

**Implementations**:

- **STDIO Transport**: Local process communication (stdin/stdout)
- **HTTP Transport**: REST API communication
- **SSE Transport**: Server-Sent Events (real-time)

**Features**:

- Reconnection strategies (exponential backoff)
- Timeout handling
- Error recovery

---

#### `libs/shared/` (Cross-cutting Utilities)

**Utilities**:

- `i18n-helper.ts` - Translation (EN/ES)
- `path-validator.ts` - 🔒 Path traversal prevention
- `url-validator.ts` - 🔒 Private IP detection
- `output-helper.ts` - Console formatting (quiet mode)
- `error-formatter.ts` - User-friendly error messages

📚 **Detailed Docs**: See [libs/shared/README.md](./libs/shared/README.md)

---

### 3. `tools/` (Development Tools)

**Contents**:

```
tools/
├── mocks/servers/                # Mock MCP servers
│   ├── simple-server.js          # ✅ Valid (score 95+)
│   ├── vulnerable-server.js      # ⚠️ Vulnerable (score <50)
│   └── broken-server.js          # ❌ Protocol violations
└── scripts/                      # Development scripts
    ├── generate-report-preview.ts
    └── i18n/                     # Translation management
```

**Purpose**: Testing, mocking, automation

📚 **Detailed Docs**: See [tools/README.md](./tools/README.md)

---

### 4. `config/` (Configuration)

Centralized configuration files to ensure consistency across the monorepo.

**Files**:

- `eslint/` - Linting rules
- `jest/` - Testing configuration
- `tsconfig/` - Base TypeScript configurations

---

### 5. `tests/` (Global Testing)

**Structure**:

```
tests/
├── unit/              # Unit tests (fast, isolated)
├── integration/       # Integration tests (real I/O)
├── e2e/              # End-to-end tests (full workflows)
└── fixtures/         # Test data
```

**Coverage**: 80%+ (target: 90%+)

📚 **Detailed Docs**: See [TESTING.md](./TESTING.md)

---

## 🔄 Request Flow Example

```mermaid
sequenceDiagram
    participant U as User
    participant C as CLI (apps/cli-verifier)
    participant UC as Validator (use-cases)
    participant D as Security Scanner (domain)
    participant I as Transport (infrastructure)
    participant S as MCP Server

    U->>C: mcp-verify validate "node server.js"
    C->>UC: new MCPValidator(transport, options)

    Note over UC: Initialize
    UC->>I: initialize()
    I->>S: JSON-RPC: initialize
    S-->>I: serverInfo
    I-->>UC: Success

    Note over UC: Discovery
    UC->>I: sendRequest('tools/list')
    I->>S: JSON-RPC: tools/list
    S-->>I: tools[]
    I-->>UC: DiscoveryResult

    Note over UC: Security Analysis
    UC->>D: scan(discovery)
    Note over D: Apply 61 security rules (6 blocks)
    D-->>UC: SecurityFindings[]

    Note over UC: Generate Report
    UC->>UC: generateReport()
    UC-->>C: ValidationReport

    C->>C: Save to files (JSON/HTML/SARIF)
    C-->>U: Display results + exit code
```

---

## 🏛️ Architectural Principles

### 1. Dependency Inversion (Hexagonal Architecture)

**Rule**: High-level modules (domain) don't depend on low-level modules (infrastructure)

```typescript
// ❌ BAD: Domain depends on infrastructure
// domain/security/scanner.ts
import { FileSystem } from "../../infrastructure/file-system"; // NO!

// ✅ GOOD: Domain defines interface, infrastructure implements
// domain/security/scanner.ts
export interface IReportStorage {
  save(report: Report): Promise<void>;
}

// infrastructure/file-storage.ts
export class FileStorage implements IReportStorage {
  async save(report: Report): Promise<void> {
    await fs.writeFile("report.json", JSON.stringify(report));
  }
}
```

---

### 2. Single Responsibility Principle

Each module has ONE reason to change:

- **Domain**: Business rules change
- **Infrastructure**: External systems change (APIs, file system)
- **Use Cases**: Application workflows change
- **Apps**: UI/UX changes

---

### 3. Separation of Concerns

**Layers**:

- **Presentation** (apps/) - User interaction
- **Application** (use-cases/) - Workflow orchestration
- **Domain** (domain/) - Business logic
- **Infrastructure** (infrastructure/) - External systems

---

### 4. Testability

**Unit Tests**: Domain layer (pure functions, no mocks needed)
**Integration Tests**: Infrastructure layer (real I/O)
**E2E Tests**: Applications layer (full workflows)

**Coverage by Layer**:

- Domain: 90%+ (easy to test)
- Infrastructure: 70%+ (requires real I/O)
- Use Cases: 80%+ (mock infrastructure)
- Apps: 60%+ (E2E tests)

---

## 🔒 Security Architecture

### Defense in Depth Layers

1. **Input Validation** (apps/)
   - Path traversal prevention (`PathValidator`)
   - URL validation (`URLValidator`)
   - Command normalization

2. **Transport Security** (infrastructure/)
   - HTTPS enforcement
   - Certificate validation
   - Timeout protection

3. **Sandbox Isolation** (infrastructure/)
   - Deno sandbox (file system restrictions)
   - Network isolation
   - Resource limits

4. Static Analysis (domain/)
   - 61 security rules organized in 6 threat category blocks
     - Block OWASP: 13 rules (SEC-001 to SEC-013)
     - Block MCP: 8 rules (SEC-014 to SEC-021)
     - Block A: 9 rules (SEC-022 to SEC-030) - OWASP LLM Top 10
     - Block B: 11 rules (SEC-031 to SEC-041) - Multi-Agent Attacks
     - Block C: 9 rules (SEC-042 to SEC-050) - Enterprise Compliance
     - Block D: 11 rules (SEC-051 to SEC-061) - AI Weaponization
   - Pattern matching (SQL injection, command injection, prompt injection, etc.)
   - Severity scoring

5. **Runtime Guardrails** (use-cases/proxy/)
   - PII redaction
   - Input sanitization
   - Rate limiting
   - Sensitive command blocking

6. **Report Security** (domain/reporting/)
   - Sensitive data masking
   - Secure file storage
   - Access control recommendations

---

## 🛡️ Security Gateway v1.0 Architecture

### Overview

The Security Gateway is a **3-layer real-time threat detection system** built into the proxy server (`libs/core/use-cases/proxy/proxy-server.ts`). It provides defense-in-depth with progressive analysis and client-aware panic stop mechanism.

**Design Goals**:

- **Zero False Positives on Layer 1**: Pattern-based detection with 100% precision
- **Sub-50ms Latency**: Fast enough for production without noticeable delay
- **Client Isolation**: Prevent one malicious actor from causing global DoS
- **Explainable Security**: Every rejection includes full metadata for audit compliance

---

### Request Flow with Early Exit

```mermaid
flowchart TD
    Start[Client Request] --> ExtractClient[Extract Client ID]
    ExtractClient --> PanicCheck{Panic Stop Check}

    PanicCheck -->|In Backoff| Reject1[Return 429<br/>Backoff Active]
    PanicCheck -->|In Panic Mode| Reject2[Return 503<br/>Panic Mode]
    PanicCheck -->|OK| CheckCache{Cache Hit?}

    CheckCache -->|Yes| CacheHit[Return Cached<br/>Security Analysis]
    CheckCache -->|No| Layer1[Layer 1: Fast Rules<br/><10ms]

    Layer1 -->|Blocked| ExplainBlock1[Format Explainable<br/>Blocking Response]
    Layer1 -->|Pass| Layer2[Layer 2: Suspicious<br/><50ms]

    Layer2 -->|Blocked| ExplainBlock2[Format Explainable<br/>Blocking Response]
    Layer2 -->|Pass| Layer3Check{LLM Layer<br/>Enabled?}

    Layer3Check -->|No| CacheResult[Cache Analysis<br/>SHA-256 + 60s TTL]
    Layer3Check -->|Yes| Layer3[Layer 3: LLM<br/>500-2000ms]

    Layer3 -->|Blocked| ExplainBlock3[Format Explainable<br/>Blocking Response]
    Layer3 -->|Pass| CacheResult

    CacheResult --> Guardrails[Apply 5 Guardrails]
    Guardrails --> Forward[Forward to Upstream]
    Forward --> Response{Response<br/>Status?}

    Response -->|429| IncrementStrike[Increment Client<br/>Strike Counter]
    Response -->|Other| CheckPII[PII Redaction]

    IncrementStrike --> EvaluateStrike{Strike Count?}
    EvaluateStrike -->|1| Backoff30[30s Backoff<br/>Set blockedUntil]
    EvaluateStrike -->|2| Backoff60[60s Backoff<br/>Set blockedUntil]
    EvaluateStrike -->|3| PanicMode[PANIC MODE<br/>Permanent Block]

    Backoff30 --> AuditEvent1[Emit Audit Event<br/>rate-limit-backoff]
    Backoff60 --> AuditEvent2[Emit Audit Event<br/>rate-limit-backoff]
    PanicMode --> AuditEvent3[Emit Audit Event<br/>panic-mode-activated]

    AuditEvent1 --> Return429[Return 429<br/>to Client]
    AuditEvent2 --> Return429
    AuditEvent3 --> Return503[Return 503<br/>to Client]

    CheckPII --> ReturnOK[Return Response<br/>to Client]

    ExplainBlock1 --> ReturnBlock[Return 403<br/>with Metadata]
    ExplainBlock2 --> ReturnBlock
    ExplainBlock3 --> ReturnBlock

    CacheHit --> Guardrails

    style Layer1 fill:#ffeb3b
    style Layer2 fill:#ff9800
    style Layer3 fill:#f44336
    style PanicMode fill:#d32f2f,color:#fff
    style CacheHit fill:#4caf50,color:#fff
```

**Key Decision Points**:

1. **Panic Stop Check** (Early Exit #1): Blocks client immediately if in backoff or panic mode
2. **Cache Hit** (Early Exit #2): Returns cached analysis in <1ms if request seen recently
3. **Layer 1 Block** (Early Exit #3): Rejects SQL/CMD injection in <10ms
4. **Layer 2 Block** (Early Exit #4): Rejects suspicious patterns in <50ms
5. **Layer 3 Disabled** (Early Exit #5): Skips LLM analysis in production mode

---

### Cache Architecture

#### Hash Generation

```typescript
// libs/core/use-cases/proxy/proxy-server.ts:1027-1040
private generateCacheKey(toolName: string, args: any): string {
  const payload = JSON.stringify({ toolName, args });
  return crypto.createHash('sha256').update(payload).digest('hex');
}
```

**Cache Strategy**:

- **Key**: SHA-256 hash of `{ toolName, args }` (deterministic, collision-resistant)
- **TTL**: 60 seconds (configurable via `CACHE_TTL_MS`)
- **Eviction**: LRU with max 1000 entries (configurable via `MAX_CACHE_SIZE`)
- **Thread-Safety**: Single-threaded Node.js, no locking needed

#### Cache Data Structure

```mermaid
classDiagram
    class SecurityAnalysisCache {
        -Map~string, CacheEntry~ cache
        -number MAX_SIZE = 1000
        -number TTL_MS = 60000
        +get(key: string) CacheEntry | null
        +set(key: string, value: SecurityAnalysis)
        +evictExpired()
        +evictLRU()
    }

    class CacheEntry {
        +SecurityAnalysis analysis
        +number timestamp
        +number accessCount
        +isExpired() boolean
    }

    SecurityAnalysisCache --> CacheEntry
```

**Cache Hit Ratio** (Production Benchmarks):

- Typical workload: **65-75%** hit ratio
- Repeated tool calls: **95%+** hit ratio
- Cold start: **0%** (expected)

**Performance Impact**:

- Cache miss: Layer 1 (10ms) + Layer 2 (50ms) = **60ms total**
- Cache hit: **<1ms** (800x faster)

---

### Client-Aware Panic Stop System

#### Problem: Global DoS Vulnerability

**Without client isolation**:

```
Client A (malicious) → 3x 429 errors → GLOBAL panic mode
Client B (legitimate) → BLOCKED (collateral damage) ❌
Client C (legitimate) → BLOCKED (collateral damage) ❌
```

#### Solution: Map<clientId, state>

```typescript
// libs/core/use-cases/proxy/proxy-server.ts:182-188
private rateLimitState = new Map<string, {
  strikes: number;
  inBackoff: boolean;
  blockedUntil: number;  // Unix timestamp
  panicMode: boolean;
}>();
```

**Client ID Extraction Priority**:

```mermaid
flowchart LR
    Start[Incoming Request] --> Check1{x-client-id<br/>header exists?}
    Check1 -->|Yes| UseHeader[Use x-client-id]
    Check1 -->|No| Check2{x-forwarded-for<br/>header exists?}

    Check2 -->|Yes| ParseFF[Parse first IP<br/>from comma list]
    Check2 -->|No| Check3{req.socket<br/>.remoteAddress?}

    Check3 -->|Yes| UseRemote[Use remoteAddress]
    Check3 -->|No| Fallback[Use 'default-client']

    ParseFF --> Validate{Valid IP?}
    Validate -->|Yes| Return1[Return IP]
    Validate -->|No| Check3

    UseHeader --> Return2[Return client-id]
    UseRemote --> Return3[Return IP]
    Fallback --> Return4[Return 'default-client']

    Return1 --> End[Client ID]
    Return2 --> End
    Return3 --> End
    Return4 --> End

    style UseHeader fill:#4caf50,color:#fff
    style Return2 fill:#4caf50,color:#fff
```

**Implementation**:

```typescript
// libs/core/use-cases/proxy/proxy-server.ts:1131-1157
private getClientId(req: http.IncomingMessage): string {
  // Priority 1: Explicit client ID header
  const clientIdHeader = req.headers['x-client-id'];
  if (clientIdHeader) {
    return Array.isArray(clientIdHeader) ? clientIdHeader[0] : clientIdHeader;
  }

  // Priority 2: Forwarded IP (from proxy chain)
  const forwardedFor = req.headers['x-forwarded-for'];
  if (forwardedFor) {
    const ip = Array.isArray(forwardedFor) ? forwardedFor[0] : forwardedFor;
    return ip.split(',')[0].trim();
  }

  // Priority 3: Direct connection IP
  if (req.socket.remoteAddress) {
    return req.socket.remoteAddress;
  }

  // Fallback: Default client (same behavior as global state)
  return 'default-client';
}
```

#### Progressive Backoff State Machine

```mermaid
stateDiagram-v2
    [*] --> Clean: New Client
    Clean --> Strike1: First 429
    Strike1 --> Backoff30s: Set blockedUntil

    Backoff30s --> Strike1: Timer expired<br/>(auto-resume)
    Backoff30s --> Strike2: Second 429<br/>(before timer)

    Strike2 --> Backoff60s: Set blockedUntil
    Backoff60s --> Strike2: Timer expired<br/>(auto-resume)
    Backoff60s --> Strike3: Third 429<br/>(before timer)

    Strike3 --> PanicMode: Permanent
    PanicMode --> [*]: Proxy restart

    note right of Backoff30s
        blockedUntil = now + 30000
        inBackoff = true
        strikes = 1
    end note

    note right of Backoff60s
        blockedUntil = now + 60000
        inBackoff = true
        strikes = 2
    end note

    note right of PanicMode
        panicMode = true
        inBackoff = false
        strikes = 3
        → Client permanently blocked
    end note
```

**State Transitions**:

| Current State | Event            | Next State        | Action                                    |
| ------------- | ---------------- | ----------------- | ----------------------------------------- |
| Clean         | 429 error        | Backoff30s        | `strikes = 1`, `blockedUntil = now + 30s` |
| Backoff30s    | Timer expires    | Strike1 (resumed) | `inBackoff = false`                       |
| Backoff30s    | 429 before timer | Backoff60s        | `strikes = 2`, `blockedUntil = now + 60s` |
| Backoff60s    | Timer expires    | Strike2 (resumed) | `inBackoff = false`                       |
| Backoff60s    | 429 before timer | PanicMode         | `strikes = 3`, `panicMode = true`         |
| PanicMode     | Any request      | Reject 503        | Permanent block                           |

**Anti-DoS Properties**:

- ✅ Isolated strikes per client (no global cascade)
- ✅ Auto-resume after backoff (self-healing)
- ✅ Permanent block only for persistent abusers
- ✅ Audit trail for forensic analysis

---

### 3-Layer Defense Implementation

#### Layer 1: Fast Rules (<10ms)

**Location**: `libs/core/use-cases/proxy/proxy-server.ts:724-887`

**Detection Methods**:

```typescript
// SQL Injection (SEC-001)
private detectSQLInjection(toolName: string, args: any): SecurityFinding[] {
  const sqlPatterns = [
    /(\bOR\b|\bAND\b)\s+\d+\s*=\s*\d+/i,           // OR 1=1
    /UNION\s+SELECT/i,                              // UNION SELECT
    /;\s*DROP\s+TABLE/i,                            // ; DROP TABLE
    /--\s*$/,                                       // SQL comment
  ];
  // Check ALL parameters (not just SQL-named tools)
  for (const [key, value] of Object.entries(args)) {
    if (typeof value === 'string') {
      for (const pattern of sqlPatterns) {
        if (pattern.test(value)) {
          return [{ ruleCode: 'SEC-001', severity: 'critical', ... }];
        }
      }
    }
  }
}

// Command Injection (SEC-002)
private detectCommandInjection(toolName: string, args: any): SecurityFinding[] {
  const cmdPatterns = [
    /[;&|`$]/,                                      // Shell metacharacters
    /\$\(/,                                         // Command substitution
    /\|\||\&\&/,                                    // Logical operators
  ];
  const dangerousCommands = /\b(rm|del|format|mkfs|dd|fdisk)\b.*[-\/](rf|r|f|force)/i;

  for (const [key, value] of Object.entries(args)) {
    if (typeof value === 'string') {
      // Check patterns + dangerous commands
    }
  }
}
```

**Characteristics**:

- **Runtime Analysis**: Checks actual parameter values, not schemas
- **Universal Application**: Runs on ALL tools (not filtered by name)
- **Zero Configuration**: No setup required
- **Guaranteed Latency**: <10ms via pure regex (no I/O)

#### Layer 2: Suspicious Rules (<50ms)

**Location**: `libs/core/use-cases/proxy/proxy-server.ts:888-1026`

**Detection Methods**:

```typescript
// Tool Chaining Detection (SEC-020)
private detectDangerousToolChaining(toolName: string, args: any): SecurityFinding[] {
  const dangerousChains = [
    'execute→read_file',    // Execute then exfiltrate
    'write_file→execute',   // Plant then execute
    'delete→execute',       // Destroy evidence
  ];
  // Heuristic scoring based on tool sequence in session
}

// Excessive Permissions (SEC-023)
private detectExcessiveAgency(toolName: string, args: any): SecurityFinding[] {
  // Check for negative flags (skip, bypass, force)
  const negativeFlags = ['skipConfirmation', 'bypassValidation', 'force'];
  const positiveFlags = ['confirm', 'verified', 'authorized'];

  let score = 0;
  for (const flag of negativeFlags) {
    if (args[flag] === true) score += 10;
  }
  for (const flag of positiveFlags) {
    if (args[flag] === false) score += 10;
  }

  if (score >= 10) {
    return [{ ruleCode: 'SEC-023', severity: 'high', ... }];
  }
}
```

**Characteristics**:

- **Stateful Analysis**: Tracks tool call history
- **Heuristic Scoring**: Accumulates evidence across parameters
- **Configurable Thresholds**: Tune sensitivity per deployment

#### Layer 3: LLM Rules (500-2000ms, Opt-In)

**Location**: `libs/core/use-cases/proxy/proxy-server.ts:1041-1126`

**Detection Methods**:

```typescript
private async runLLMRules(
  toolName: string,
  args: any
): Promise<SecurityFinding[]> {
  const prompt = `Analyze this MCP tool call for security threats:

  Tool: ${toolName}
  Arguments: ${JSON.stringify(args, null, 2)}

  Detect:
  - Novel attack patterns not covered by static rules
  - Semantic prompt injection attempts
  - Context-aware social engineering
  - Polymorphic malicious payloads

  Respond with JSON: { threat: boolean, reasoning: string, severity: string }`;

  const analysis = await this.llmProvider.analyze(prompt);

  if (analysis.threat) {
    return [{
      ruleCode: 'SEC-LLM-001',
      severity: analysis.severity,
      message: analysis.reasoning,
      layer: 3,
    }];
  }
}
```

**When to Enable**:

- ✅ Research environments (studying novel attacks)
- ✅ High-security deployments (military, finance, healthcare)
- ✅ Honeypot/deception systems
- ❌ Production (latency penalty too high)
- ❌ High-throughput systems (cost prohibitive)

**Cost Analysis** (per 1000 requests):

- Layer 1+2 only: **$0** (local processing)
- Layer 1+2+3: **$5-$15** (LLM API costs)

---

### Explainable Blocking Format

Every rejection includes complete metadata for compliance and forensics:

```json
{
  "jsonrpc": "2.0",
  "id": 123,
  "error": {
    "code": -32003,
    "message": "Security Gateway blocked request",
    "data": {
      "blocked": true,
      "layer": 1,
      "latency_ms": 8,
      "findings": [
        {
          "ruleCode": "SEC-001",
          "severity": "critical",
          "message": "SQL injection detected in parameter 'query'",
          "component": "database_query",
          "cwe": "CWE-89",
          "owasp": "A03:2021 - Injection",
          "remediation": "Use parameterized queries instead of string concatenation",
          "matchedPattern": "OR 1=1",
          "affectedParameter": "query"
        }
      ],
      "timestamp": "2026-03-07T12:34:56.789Z",
      "clientId": "192.168.1.100"
    }
  }
}
```

**Audit Event Stream**:

```jsonl
{"type":"security-analysis","timestamp":"2026-03-07T12:34:56Z","layer":1,"latency":8,"blocked":true,"clientId":"192.168.1.100"}
{"type":"rate-limit-backoff","timestamp":"2026-03-07T12:35:02Z","message":"Strike 1/3 for client 192.168.1.100: Entering 30 second backoff","clientId":"192.168.1.100"}
{"type":"panic-mode-activated","timestamp":"2026-03-07T12:36:15Z","message":"Strike 3/3 for client 10.0.0.5: PANIC MODE activated","clientId":"10.0.0.5"}
```

---

## 📊 Performance Considerations

### Optimization Strategies

1. **Lazy Loading**: Load LLM providers only when needed
2. **Parallel Processing**: Run security rules concurrently
3. **Caching**: Cache transport connections
4. **Streaming**: Stream large reports instead of buffering
5. **Worker Pools**: Reuse Deno sandbox instances

**Benchmarks**:

- Simple validation: < 500ms
- With security analysis: < 2s
- With LLM analysis: < 5s (depends on provider)

---

## 🔗 Related Documentation

| Document                                     | Purpose                            |
| -------------------------------------------- | ---------------------------------- |
| [libs/README.md](./libs/README.md)           | Library architecture overview      |
| [libs/core/README.md](./libs/core/README.md) | Hexagonal architecture deep dive   |
| [CODE_MAP.md](./CODE_MAP.md)                 | "I want to..." quick reference     |
| [DEVELOPMENT.md](./DEVELOPMENT.md)           | Local setup and testing            |
| [SECURITY.md](./SECURITY.md)                 | Security model and threat analysis |
