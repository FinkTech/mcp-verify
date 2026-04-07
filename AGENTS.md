# MCP Verify — Agent Context Index

> Enterprise-grade security validation and fuzzing for MCP servers
> Version: 1.0.0 | License: AGPL-3.0 | Monorepo: pnpm workspaces

---

## ALWAYS FOLLOW — Critical Rules

```typescript
// 1. Zero Any Standard
function process(data: unknown) {
  /* use type guards */
} // ❌ never: data: any

// 2. i18n for all user-facing strings
console.log(t("validation_complete")); // ❌ never: 'Validation complete'

// 3. Read Before Write — always Read existing file first, then Edit with old/new strings

// 4. Atomic file writes — write to tmpPath → rename → prevents corruption on crash

// 5. Timeout all async ops
const controller = new AbortController(); // ❌ never: bare await fetch(url)
setTimeout(() => controller.abort(), timeout);
```

---

## When Starting a Task

1. Read this file → read `apps/*/AGENTS.md` or `libs/*/AGENTS.md` for the area you're modifying
2. Check git for architectural decisions: `git log --oneline --grep="feat|refactor" -20`
3. Before committing: `npm test && npx tsc --noEmit`

**Load context on-demand, not all upfront** — 3,500+ lines of context = 20% worse agent performance.

---

## Project Structure

```
mcp-verify/
├── apps/
│   ├── cli-verifier/       # Interactive CLI + 13 validation commands
│   ├── mcp-server/         # MCP server that validates other MCP servers
│   └── vscode-extension/   # VS Code extension for real-time scanning
├── libs/
│   ├── core/               # Security (60 rules), validation, reporting, transport
│   ├── fuzzer/             # Fuzzing engine (9 generators, 10 detectors)
│   ├── protocol/           # MCP protocol types (auto-generated)
│   ├── shared/             # i18n, logging, path/url/regex guards, user-agent
│   └── transport/          # stdio, http, sse
├── tests/                  # Integration tests
└── tools/mocks/            # Mock MCP servers for testing
```

**Architecture**: Clean Architecture — Use Cases → Domain → Infrastructure.

---

## Tech Stack

| Area       | Stack                              |
| ---------- | ---------------------------------- |
| Runtime    | Node.js 20+, TypeScript 5.x strict |
| Monorepo   | pnpm workspaces                    |
| CLI/UI     | chalk, ora, inquirer, blessed      |
| Testing    | Jest + ts-jest                     |
| Validation | Zod schemas                        |
| LLM        | @anthropic-ai/sdk, openai, ollama  |

**Security invariants**: Zod on all external input · path traversal protection via `@mcp-verify/shared` · timeout 2–120s · secret redaction in logs.

---

## Environment Variables

| Variable            | Purpose                           | Default       |
| ------------------- | --------------------------------- | ------------- |
| `ANTHROPIC_API_KEY` | LLM analysis (Claude)             | —             |
| `OPENAI_API_KEY`    | LLM analysis (GPT)                | —             |
| `GOOGLE_API_KEY`    | LLM analysis (Gemini)             | —             |
| `MCP_VERIFY_LANG`   | i18n language (`en`, `es`, `fr`…) | `en`          |
| `DEBUG`             | Debug logging (`mcp-verify:*`)    | —             |
| `NODE_ENV`          | `development` / `production`      | `development` |

LLM keys are optional but required for semantic analysis features.

---

## Import Conventions

```typescript
// Cross-package → always use package names
import { MCPValidator } from "@mcp-verify/core";
import { t } from "@mcp-verify/shared";

// Within a package → relative imports only
import { ISecurityRule } from "../rules/rule.interface";

// Types → import type
import type { ValidationResult } from "@mcp-verify/core";
```

---

## Testing (Monorepo-Wide)

```bash
npm test                  # all packages
npm test -- libs/core     # single package
npm test -- --coverage
npm run test:ci           # CI mode (max 2 workers)
```

| Layer          | Min coverage |
| -------------- | ------------ |
| Security rules | 100%         |
| Domain layer   | 80%          |
| Use cases      | 60%          |
| Infrastructure | 50%          |
| Apps           | 40%          |

See `TESTING.md` for full strategy and CI/CD integration.

---

## Context Files (load when needed)

- `apps/cli-verifier/AGENTS.md` — 13 commands, interactive shell, workspace
- `apps/mcp-server/AGENTS.md` — 7 MCP tools, LLM formatting
- `libs/core/AGENTS.md` — 60 security rules, 5 report formats, 4 LLM providers
- `libs/fuzzer/AGENTS.md` — 9 generators, 10 detectors, mutation engine
- `libs/shared/AGENTS.md` — security perimeter, Tier-S guards, Zero Internal Imports

---

**Last Updated**: 2026-03-31 | Maintainer: @FinkTech via Claude Code
