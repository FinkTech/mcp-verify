# MCP Verify - Agent Context Index

> Enterprise-grade security validation and fuzzing for MCP servers
> Version: 1.0.0 | License: Apache 2.0 | Monorepo: pnpm workspaces

---

## ALWAYS FOLLOW - Critical Rules

### 1. Zero Any Standard
```typescript
// ❌ NEVER: function process(data: any)
// ✅ ALWAYS: function process(data: unknown) { /* type guard */ }
```

### 2. i18n for User-Facing Strings
```typescript
// ❌ NEVER: console.log('Validation complete')
// ✅ ALWAYS: console.log(t('validation_complete'))
```

### 3. Read Before Write
```typescript
// ❌ NEVER: Write tool will fail on existing files
// ✅ ALWAYS: Read existing file → Edit with old/new strings
```

### 4. Atomic Operations for File Writes
```typescript
// Write to tmpPath → rename (atomic) → prevents corruption on crash
```

### 5. Timeout All Async Operations
```typescript
// NEVER: await fetch(url)
// ALWAYS: AbortController with setTimeout for network/subprocess calls
```

---

## When Starting a Task

1. **Read context progressively**:
   - Start here (project overview)
   - Read `apps/*/AGENTS.md` OR `libs/*/AGENTS.md` for the area you're modifying
   - Use git log for architectural decisions: `git log --oneline --grep="feat|refactor" -20`

2. **Validate before committing**:
   ```bash
   npm test              # Run tests
   npx tsc --noEmit      # Type check
   ```

3. **Common pitfalls**:
   - ❌ Using `any` → Use `unknown` + type guards
   - ❌ Hardcoding strings → Use `t()` from `@mcp-verify/shared`
   - ❌ Writing without reading → Always Read before Edit/Write
   - ❌ Ignoring timeouts → All async ops need timeouts

---

## Project Structure (High-Level)

```
mcp-verify/
├── apps/                    # 3 entry points
│   ├── cli-verifier/       # Interactive CLI + validation commands
│   ├── mcp-server/         # MCP server that validates other MCP servers
│   └── vscode-extension/   # VS Code extension for real-time scanning
├── libs/                    # Shared libraries
│   ├── core/               # Main: security, validation, reporting, transport
│   ├── fuzzer/             # Advanced fuzzing engine with detectors
│   ├── protocol/           # MCP protocol types (auto-generated)
│   ├── shared/             # Common: i18n, logging, git-info, user-agent
│   └── transport/          # Transport layer (stdio, http, sse)
├── tests/                   # Integration tests
└── tools/mocks/            # Mock MCP servers for testing
```

**Architecture**: Clean Architecture (3 layers: Use Cases → Domain → Infrastructure)

---

## Context Loading Strategy (Progressive Disclosure)

Load context on-demand, not all upfront:

1. **Apps layer**: Read `apps/cli-verifier/AGENTS.md` (~200 lines) if modifying CLI
2. **MCP Server**: Read `apps/mcp-server/AGENTS.md` (~150 lines) if modifying tools
3. **Core library**: Read `libs/core/AGENTS.md` (~150 lines) if modifying domain logic
4. **Git history**: `git log --stat` for architecture understanding (code is truth)

**Why?** 3,500+ lines of context = 20% worse agent performance (research-backed). Load what you need when you need it.

---

## Tech Stack Essentials

- **Runtime**: Node.js 18+, TypeScript 5.x (strict mode)
- **Monorepo**: pnpm workspaces
- **CLI/UI**: chalk, ora, inquirer, blessed
- **Testing**: Jest + ts-jest
- **Validation**: Zod schemas
- **LLM**: @anthropic-ai/sdk, openai, ollama

**Security**: Zero trust input (validate with Zod), path traversal protection, timeout enforcement (2-120s), secret redaction in logs.

---

## Git is Truth

Architecture decisions, refactoring rationale, and historical context are in commit history:

```bash
git log --oneline --grep="feat|refactor|breaking" -30
git log --stat libs/core/domain/security/  # See file evolution
```

Documentation can drift. Code and commits cannot.

---

## CLAUDE.md vs AGENTS.md

**Purpose of dual documentation:**

- **CLAUDE.md**: Minimal pointer file (< 30 lines) optimized for Claude Code. Contains brief summary + link to AGENTS.md.
- **AGENTS.md**: Complete technical documentation for all AI coding agents (Cursor, Codex, Antigravity, Windsurf, GitHub Copilot, etc.).

**Rule**: Keep CLAUDE.md under 30 lines. All technical detail lives in AGENTS.md.

**File structure:**
```
/
├── claude.md → Points to AGENTS.md
├── AGENTS.md → Complete docs (this file)
├── apps/
│   ├── cli-verifier/
│   │   ├── claude.md → Points to AGENTS.md
│   │   └── AGENTS.md → CLI technical docs
│   ├── mcp-server/
│   │   ├── claude.md → Points to AGENTS.md
│   │   └── AGENTS.md → MCP Server technical docs
│   └── vscode-extension/
│       ├── claude.md → Points to AGENTS.md
│       └── AGENTS.md → VSCode extension docs
└── libs/
    ├── core/
    │   ├── claude.md → Points to AGENTS.md
    │   └── AGENTS.md → Core domain docs
    └── fuzzer/
        ├── claude.md → Points to AGENTS.md
        └── AGENTS.md → Fuzzer engine docs
```

---

## Environment Variables (Quick Reference)

| Variable | Purpose | Default | Required |
|----------|---------|---------|----------|
| `ANTHROPIC_API_KEY` | LLM analysis (Anthropic Claude) | - | Optional* |
| `OPENAI_API_KEY` | LLM analysis (OpenAI GPT) | - | Optional* |
| `GOOGLE_API_KEY` | LLM analysis (Google Gemini) | - | Optional* |
| `MCP_VERIFY_LANG` | i18n language (`en`, `es`, `fr`, etc.) | `en` | No |
| `DEBUG` | Debug logging (`mcp-verify:*`) | - | No |
| `NODE_ENV` | Environment (`development`, `production`) | `development` | No |

**\*Optional but required for semantic analysis features.**

**Example `.env` file:**
```bash
# LLM Providers (pick one or more)
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
GOOGLE_API_KEY=AIza...

# Localization
MCP_VERIFY_LANG=es

# Debug logging
DEBUG=mcp-verify:*
```

---

## Import Conventions

**From apps to libs (use package names):**
```typescript
// ✅ CORRECT: Use @mcp-verify/* for cross-package imports
import { MCPValidator } from '@mcp-verify/core';
import { t, setLanguage } from '@mcp-verify/shared';
import { FuzzerEngine } from '@mcp-verify/fuzzer';
```

**Within libs (use relative imports):**
```typescript
// ✅ CORRECT: Use relative imports within same package
import { SecurityRule } from '../rules/rule.interface';
import { Logger } from '../../infrastructure/logging/logger';
```

**Type-only imports:**
```typescript
// ✅ CORRECT: Use 'import type' for types
import type { ValidationResult } from '@mcp-verify/core';
import type { ServerContext } from '../security/types';
```

**Barrel exports (index.ts):**
```typescript
// libs/core/domain/index.ts
export * from './security';
export * from './reporting';
export * from './validation';

// Import from barrel
import { SecurityScanner, EnhancedReporter } from '@mcp-verify/core/domain';
```

---

## Error Handling Pattern

**Standard pattern for all use cases:**

```typescript
import { Logger } from '@mcp-verify/core/infrastructure';
import { t } from '@mcp-verify/shared';

const logger = Logger.getInstance();

export async function myFunction(): Promise<Result> {
  try {
    // Business logic
    const result = await validator.validate();
    return { success: true, data: result };

  } catch (error) {
    // Known error types (graceful handling)
    if (error instanceof ValidationError) {
      logger.warn(t('validation_failed'), { error });
      return { success: false, error: error.message };
    }

    if (error instanceof NetworkError) {
      logger.error(t('network_error'), { error });
      return { success: false, error: t('network_unreachable') };
    }

    if (error instanceof TimeoutError) {
      logger.error(t('timeout_error'), { error });
      return { success: false, error: t('operation_timeout') };
    }

    // Unknown errors (log and re-throw)
    logger.error(t('unexpected_error'), error as Error);
    throw error;
  }
}
```

**CLI-specific error handling:**
```typescript
import chalk from 'chalk';

try {
  await runCommand();
} catch (error) {
  console.error(chalk.red(`✗ ${t('command_failed')}: ${error.message}`));
  process.exit(1);
}
```

**MCP Server error handling:**
```typescript
export async function myToolTool(args: unknown): Promise<ToolResult> {
  try {
    const parsed = MyArgsSchema.parse(args);
    const result = await performAction(parsed);

    return {
      content: [{ type: 'text', text: JSON.stringify(result) }]
    };
  } catch (error) {
    return {
      content: [{ type: 'text', text: JSON.stringify({
        error: error instanceof Error ? error.message : 'Unknown error',
        code: 'TOOL_EXECUTION_FAILED'
      })}],
      isError: true
    };
  }
}
```

---

## Testing Strategy

**Test pyramid approach**: Unit tests (domain) → Integration tests (use cases) → E2E tests (apps).

```bash
# Run all tests (monorepo-wide)
npm test

# Test specific package
npm test -- libs/core
npm test -- apps/cli-verifier

# Coverage report (monorepo-wide)
npm test -- --coverage

# Watch mode for development
npm test -- --watch

# CI/CD pipeline
npm run test:ci  # Optimized for CI (max 2 workers, coverage enabled)
```

**Coverage targets**:
- **Domain layer** (`libs/core/domain/`): 80%+ (pure business logic, no mocks)
- **Use cases** (`libs/core/use-cases/`): 60%+ (mocked transports, LLMs)
- **Infrastructure** (`libs/core/infrastructure/`): 50%+ (real I/O when safe)
- **Security rules**: 100% (critical for validation correctness)
- **Apps**: 40%+ (integration tests, not exhaustive unit tests)

**Test organization**:
```
tests/
├── unit/           # Fast, isolated tests (< 100ms each)
├── integration/    # Cross-component tests (< 1s each)
└── e2e/            # Full workflow tests (< 10s each)
```

**Key testing patterns**:
1. **Security rules**: Test both vulnerable and safe code paths
2. **Transports**: Mock for unit, real subprocess for integration
3. **LLM providers**: Mock API calls, test retry logic and timeout handling
4. **Report generators**: Validate output structure, i18n, edge cases
5. **CLI commands**: Test flag parsing, error messages, output formats

**Example unit test (domain)**:
```typescript
import { PathTraversalRule } from '@mcp-verify/core/domain/security/rules';

describe('PathTraversalRule', () => {
  it('should detect path traversal in tool schema', async () => {
    const context = {
      tools: [{
        inputSchema: {
          properties: { path: { type: 'string', default: '../../../etc/passwd' } }
        }
      }]
    };

    const findings = await new PathTraversalRule().check(context);
    expect(findings[0].severity).toBe('critical');
  });
});
```

**Example integration test**:
```typescript
import { MCPValidator } from '@mcp-verify/core';
import { StdioTransport } from '@mcp-verify/core/domain/transport';

describe('MCPValidator Integration', () => {
  it('should validate a real MCP server', async () => {
    const transport = new StdioTransport('node', ['tools/mocks/servers/simple-server.js']);
    const validator = new MCPValidator(transport);

    const report = await validator.validate();

    expect(report.securityScore).toBeGreaterThan(70);
    expect(report.protocolCompliant).toBe(true);

    validator.cleanup();
  }, 30000);
});
```

**See also**: `TESTING.md` for detailed test strategy and CI/CD integration.

---

## Further Reading (Context Files)

### Apps Layer
- **`apps/AGENTS.md`** - Overview: which app to modify?
- **`apps/cli-verifier/AGENTS.md`** - Interactive shell, 13 commands, multi-context workspace
- **`apps/mcp-server/AGENTS.md`** - 7 MCP tools, LLM formatting, integration patterns
- **`apps/vscode-extension/AGENTS.md`** - Extension architecture, diagnostics, tree views

### Libs Layer
- **`libs/AGENTS.md`** - Overview: dependency rules, monorepo structure
- **`libs/core/AGENTS.md`** - Domain logic, 60 security rules, 5 report formats
- **`libs/fuzzer/AGENTS.md`** - Smart Fuzzer engine, 9 generators, 10 detectors

### Other Documentation
- **`TESTING.md`** - Test strategy, coverage requirements
- **`SECURITY.md`** - Security policy, vulnerability reporting
- **`CONTRIBUTING.md`** - Contributing guidelines, code review process

---

**Last Updated**: 2026-03-26 | **Maintained by**: @FinkTech via Claude Code
