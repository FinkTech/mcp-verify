# Libs - Shared Libraries Overview

> Framework-agnostic business logic and utilities
> Clean architecture: Domain → Infrastructure → Use Cases

---

## Quick Start (5 Minutes)

1. Read this file (libs layer overview)
2. Identify which library to modify:
   - Security rules, validation logic → `core/AGENTS.md`
   - Fuzzing engine, generators, detectors → `fuzzer/AGENTS.md`
   - Utilities, i18n, logging → `shared/`
   - MCP protocol types → `protocol/`
   - Transports (stdio, HTTP, SSE) → `transport/`
3. Read that specific library's AGENTS.md for detailed architecture
4. Make your changes following dependency rules

---

## Four Libraries, Clear Responsibilities

### 1. Core (`core/`)

**Purpose**: Framework-agnostic business logic (hexagonal architecture).

**Contains**:

- **60 security rules** across 6 threat categories (OWASP, MCP, LLM, Multi-Agent, Compliance, Weaponization)
- **5 report formats** (HTML, Markdown, SARIF, JSON, Text)
- **3 transports** (stdio, HTTP, SSE)
- **4 LLM providers** (Anthropic, OpenAI, Ollama, Gemini)
- **Validation engine** (MCP protocol compliance, schema validation)
- **Quality analyzer** (semantic analysis, naming conventions)

**Architecture**: 3 layers (Domain → Infrastructure → Use Cases)

**Dependency rule**: Domain layer has ZERO framework dependencies.

**Modify this when**:

- Adding new security rule
- Adding new report format
- Adding new LLM provider
- Changing validation logic

**See**: `core/AGENTS.md` for complete architecture and 60 security rules catalog.

---

### 2. Fuzzer (`fuzzer/`)

**Purpose**: Intelligent payload generation with feedback loops.

**Contains**:

- **9 generators**: Prompt injection, JWT attacks, SQL/XSS, schema confusion, prototype pollution, time-based, protocol violations, custom
- **10 detectors**: Timing anomalies, error disclosure, XSS, prompt leaks, jailbreak, path traversal, weak IDs, info disclosure, protocol violations, custom
- **12 mutation strategies**: Bit flip, case mutation, encoding, repeat, truncate, insert, replace, delimiter swap, nesting, type coercion, boundary testing, hybrid
- **Feedback loop**: Baseline → Execute → Detect anomalies → Mutate → Repeat

**Modify this when**:

- Adding new payload generator
- Adding new vulnerability detector
- Changing mutation algorithms
- Tuning anomaly detection thresholds

**See**: `fuzzer/AGENTS.md` for generator/detector implementation patterns.

---

### 3. Shared (`shared/`)

**Purpose**: Common utilities used across ALL apps and libraries.

**Contains**:

- **i18n helper** (`t()` function for 30+ languages)
- **Logging** (scoped loggers with secret redaction)
- **Output formatters** (CLI colors, tables, spinners)
- **Error formatters** (user-friendly error messages)
- **Path validators** (security checks for traversal)
- **Git info** (commit hash, branch, dirty status)
- **User agent** (version strings for API calls)

**Dependency rule**: ZERO dependencies on other libs (most stable layer).

**Modify this when**:

- Adding utility used by 2+ apps/libs
- Adding i18n translation
- Changing logging format

**No AGENTS.md**: See `shared/README.md` for utilities catalog.

---

### 4. Protocol (`protocol/`)

**Purpose**: Type definitions for Model Context Protocol.

**Contains**:

- JSON-RPC types
- MCP message types (tools, resources, prompts)
- Protocol constants

**Dependency rule**: NO implementation logic (just types).

**Modify this when**:

- MCP specification updates
- Need new protocol types

**No AGENTS.md**: Types only, no complex architecture.

---

### 5. Transport (`transport/`)

**Purpose**: Communication layer implementations for MCP servers.

**Contains**:

- **StdioTransport**: Node.js child processes (stdin/stdout)
- **HttpTransport**: REST API (HTTP/HTTPS)
- **SSETransport**: Server-Sent Events (real-time streaming)

**Interface**: All implement `ITransport` from `core/domain/transport.ts`

**Modify this when**:

- Adding new transport protocol
- Changing connection logic

**No AGENTS.md**: See `core/domain/transport.ts` for interface.

---

## Clean Architecture Dependency Rules (CRITICAL)

**Dependency flow** (can only import from layers below):

```
Apps (cli-verifier, mcp-server, vscode-extension)
  ↓ imports
libs/core/use-cases/
  ↓ imports
libs/core/infrastructure/
  ↓ imports
libs/core/domain/
  ↓ imports
libs/shared/  (ZERO dependencies, most stable)
```

**Strict rules**:

| Library                  | Can Import                                        | CANNOT Import                                                           |
| ------------------------ | ------------------------------------------------- | ----------------------------------------------------------------------- |
| **core/domain/**         | `shared/` only                                    | `core/infrastructure/`, `core/use-cases/`, `apps/`, external frameworks |
| **core/infrastructure/** | `core/domain/`, `shared/`                         | `core/use-cases/`, `apps/`                                              |
| **core/use-cases/**      | `core/domain/`, `core/infrastructure/`, `shared/` | `apps/`                                                                 |
| **shared/**              | Nothing (except Node.js built-ins)                | `core/`, `fuzzer/`, `apps/`                                             |
| **apps/**                | All `libs/`                                       | Other `apps/`                                                           |

**Why this matters**:

- ✅ Domain logic is pure (100% unit testable without mocks)
- ✅ Infrastructure is pluggable (swap implementations easily)
- ✅ Use cases are framework-agnostic (portable across runtimes)
- ✅ Shared utilities are truly shared (no circular dependencies)

---

## Common Tasks

### Task 1: Add New Security Rule

**Location**: `libs/core/domain/security/rules/my-rule.rule.ts`

**Steps**:

1. Create rule file implementing `ISecurityRule` interface
2. Export from `domain/security/rules/index.ts`
3. Add to `rules` array in `security-scanner.ts` constructor
4. Write tests in `domain/security/rules/__tests__/my-rule.spec.ts`
5. Current count: 60 rules (assign SEC-061, SEC-062, etc.)

**See**: `core/AGENTS.md` for security rules architecture.

---

### Task 2: Add New Fuzzing Generator

**Location**: `libs/fuzzer/generators/my-generator.ts`

**Steps**:

1. Create generator implementing `IPayloadGenerator` interface
2. Export from `generators/index.ts`
3. Register in `FuzzerEngine` constructor
4. Write tests in `generators/__tests__/my-generator.spec.ts`
5. Current count: 9 generators

**See**: `fuzzer/AGENTS.md` for generator patterns.

---

### Task 3: Add New Report Format

**Location**: `libs/core/domain/reporting/my-format-generator.ts`

**Steps**:

1. Create generator implementing `generate(report): Promise<string>`
2. Export from `domain/reporting/index.ts`
3. Add to `EnhancedReporter.generateReport()` switch case
4. Add i18n translations if needed
5. Write tests validating output structure

**See**: `core/AGENTS.md` for reporting architecture.

---

### Task 4: Add New LLM Provider

**Location**: `libs/core/domain/quality/providers/my-provider.ts`

**Steps**:

1. Create provider implementing `ILLMProvider` interface
2. Export from `domain/quality/providers/index.ts`
3. Add to `LLMSemanticAnalyzer.getProvider()` switch case
4. Add environment variable docs (e.g., `MY_PROVIDER_API_KEY`)
5. Write tests mocking API calls

**See**: `core/AGENTS.md` for LLM provider patterns.

---

### Task 5: Add i18n Translation

**Location**: `libs/core/domain/reporting/i18n.ts`

**Steps**:

1. Add new language code to `translations` object
2. Copy `en` translations as template
3. Translate all keys to new language
4. Export from `Language` type
5. Test with `MCP_VERIFY_LANG=<new-lang> npx mcp-verify validate`

**Current languages**: 30+ (en, es, fr, de, ja, zh, pt, ru, etc.)

---

## Import Conventions

**From apps to libs** (use package names):

```typescript
// ✅ CORRECT
import { MCPValidator } from "@mcp-verify/core";
import { t, setLanguage } from "@mcp-verify/shared";
import { FuzzerEngine } from "@mcp-verify/fuzzer";
```

**Within libs** (use relative imports):

```typescript
// ✅ CORRECT
import { ISecurityRule } from "../rules/rule.interface";
import { Logger } from "../../infrastructure/logging/logger";
```

**Type-only imports**:

```typescript
// ✅ CORRECT
import type { ValidationResult } from "@mcp-verify/core";
import type { ServerContext } from "../security/types";
```

**Barrel exports** (index.ts):

```typescript
// libs/core/domain/index.ts
export * from "./security";
export * from "./reporting";

// Usage
import { SecurityScanner, EnhancedReporter } from "@mcp-verify/core/domain";
```

---

## Testing

```bash
# Unit tests (specific library)
cd libs/core && npm test
cd libs/fuzzer && npm test

# Integration tests (cross-library)
npm test -- tests/integration/

# Coverage (monorepo-wide)
npm test -- --coverage
```

**Coverage targets**:

- **Domain layer** (`core/domain/`): 80%+ (pure logic, no mocks)
- **Use cases** (`core/use-cases/`): 60%+ (mocked transports, LLMs)
- **Infrastructure** (`core/infrastructure/`): 50%+ (real I/O when safe)
- **Security rules**: 100% (critical for correctness)
- **Fuzzer**: 70%+ (generators, detectors, mutation engine)
- **Shared**: 60%+ (utilities, i18n, formatters)

---

## Troubleshooting

### Cross-package imports not working

- **Check**: Are you using `@mcp-verify/*` package names? (not relative paths)
- **Check**: Did you run `npm install` in monorepo root?
- **Check**: Is package exported in `libs/*/package.json`?
- **Fix**: Rebuild workspace: `npm run build`
- **Debug**: Check `node_modules/@mcp-verify/` symlinks

### Circular dependency detected

- **Check**: Are you importing from apps/ in libs/?
- **Check**: Are you importing from use-cases/ in domain/?
- **Fix**: Follow dependency rules (domain → shared only)
- **Debug**: Use `madge --circular --extensions ts ./libs/`

### Business logic in shared/

- **Check**: Is this logic reusable across ALL apps?
- **Check**: Is this truly a utility, not a business rule?
- **Fix**: Move to `core/domain/` if it's business logic
- **Rule**: shared/ = generic utilities, core/ = business logic

### Framework dependency in domain/

- **Check**: Are you importing Express, Commander, VSCode API in domain/?
- **Fix**: Move framework setup to apps/ or core/infrastructure/
- **Why**: Domain must be framework-agnostic for portability

---

## Further Reading

### Library-Specific Documentation

- **`core/AGENTS.md`** - Domain logic, 60 security rules, 5 report formats, 3 transports, 4 LLM providers
- **`fuzzer/AGENTS.md`** - Smart Fuzzer engine, 9 generators, 10 detectors, mutation strategies
- **`shared/README.md`** - Utilities catalog, i18n, logging, formatters

### App Documentation

- **`apps/AGENTS.md`** - Which app to modify? CLI vs MCP Server vs VSCode Extension
- **`apps/cli-verifier/AGENTS.md`** - Interactive shell, commands, multi-context workspace
- **`apps/mcp-server/AGENTS.md`** - 7 MCP tools, LLM formatting, integration

### Other Documentation

- **`TESTING.md`** - Test strategy, coverage requirements
- **`ARCHITECTURE.md`** - System design philosophy
- **`CONTRIBUTING.md`** - Contributing guidelines

---

**Last Updated**: 2026-03-26
