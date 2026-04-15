# Apps - Entry Points Overview

> Three complementary applications for MCP server validation
> CLI tool, MCP server, VS Code extension

---

## Quick Start (5 Minutes)

1. Read this file (apps layer overview)
2. Identify which app to modify:
   - Interactive CLI → `cli-verifier/AGENTS.md`
   - MCP server tools → `mcp-server/AGENTS.md`
   - VSCode extension → `vscode-extension/AGENTS.md`
3. Read that specific app's AGENTS.md for detailed architecture
4. Make your changes following existing patterns

---

## Three Apps, Three Audiences

### 1. CLI Verifier (`cli-verifier/`)

**Target audience**: Developers and security teams using command line.

**When to modify**:

- Adding new security commands (validate, fuzz, stress, etc.)
- Changing interactive shell behavior (multi-context workspace)
- Updating security profiles (light/balanced/aggressive)
- Modifying report generation or dashboard UI

**Key files**:

- `src/bin/index.ts` - Commander.js setup (one-shot commands)
- `src/commands/interactive/index.ts` - Interactive REPL entry point
- `src/commands/*.ts` - 13 command handlers
- `src/commands/interactive/` - 26 modular shell components

**Core dependencies**: @mcp-verify/core, chalk, commander, ora, inquirer

**Architecture**: Modular shell with persistent state, multi-context workspace, atomic file I/O.

**See**: `cli-verifier/AGENTS.md` for complete documentation.

---

### 2. MCP Server (`mcp-server/`)

**Target audience**: AI agents (Claude, GPT, etc.) via MCP protocol.

**When to modify**:

- Adding/modifying the 7 MCP tools (validateServer, scanSecurity, etc.)
- Changing LLM formatting for tool outputs
- Updating config discovery logic (auto-detect MCP servers)
- Modifying stdio transport or error handling

**Key files**:

- `src/index.ts` - Shebang entry point
- `src/server.ts` - StdioServerTransport setup, request handlers
- `src/tools/*.ts` - 7 tool implementations
- `src/utils/llm-formatter.ts` - AI-optimized output formatting
- `src/utils/config-discovery.ts` - Auto-detect MCP configs

**Core dependencies**: @modelcontextprotocol/sdk, @mcp-verify/core

**Architecture**: Stdio-based MCP server exposing validation as tools.

**Claude Desktop integration**:

```json
{
  "mcpServers": {
    "mcp-verify": {
      "command": "node",
      "args": ["/path/to/apps/mcp-server/dist/index.js"]
    }
  }
}
```

**See**: `mcp-server/AGENTS.md` for tool specifications and LLM formatting strategy.

---

### 3. VS Code Extension (`vscode-extension/`)

**Target audience**: Developers using VS Code IDE.

**When to modify**:

- Adding new commands (palette or keyboard shortcuts)
- Updating diagnostics provider (LSP integration)
- Changing tree views (Servers, Findings, Tools, History)
- Modifying report panel webview or code actions

**Key files**:

- `src/extension.ts` - activate/deactivate lifecycle
- `src/commands/*.ts` - 14 command handlers
- `src/providers/diagnostics.ts` - Real-time scanning, squiggly lines
- `src/providers/code-actions.ts` - Quick fixes (💡)
- `src/providers/report-panel.ts` - HTML webview reports
- `src/views/*.ts` - 4 tree view providers

**Core dependencies**: vscode API, @mcp-verify/core

**Architecture**: LSP-style diagnostics + webview reports + tree views.

**Package**: `npm run package` creates .vsix file for distribution.

**See**: `vscode-extension/AGENTS.md` for extension architecture and providers.

---

## Build Commands (Quick Reference)

```bash
# From root (build all apps)
npm run build

# From app directory (build specific app)
cd apps/cli-verifier && npm run build
cd apps/mcp-server && npm run build
cd apps/vscode-extension && npm run compile

# Development mode (watch + rebuild on changes)
cd apps/cli-verifier && npm run dev
cd apps/mcp-server && npm run dev
cd apps/vscode-extension && npm run watch

# Package for distribution
cd apps/cli-verifier && npm run compile  # Creates standalone binaries
cd apps/vscode-extension && npm run package  # Creates .vsix
```

---

## Decision Guide: Which App to Modify?

| Task                  | App                        | File                                 |
| --------------------- | -------------------------- | ------------------------------------ |
| Add new security rule | **libs/core** (not apps)   | `libs/core/domain/security/rules/`   |
| Add CLI command       | **cli-verifier**           | `src/commands/my-command.ts`         |
| Add MCP tool          | **mcp-server**             | `src/tools/my-tool.ts`               |
| Add VSCode command    | **vscode-extension**       | `src/commands/my-command.ts`         |
| Change fuzzing logic  | **libs/fuzzer** (not apps) | `libs/fuzzer/engine/`                |
| Change report format  | **libs/core** (not apps)   | `libs/core/domain/reporting/`        |
| Add i18n translation  | **libs/core** (not apps)   | `libs/core/domain/reporting/i18n.ts` |

**Key insight**: Apps are thin wrappers around `@mcp-verify/core`. Most business logic lives in libs.

---

## Integration Points

### CLI ↔ Core

- **TransportFactory** creates stdio/http transports based on target
- **Validator** orchestrates full security scanning workflow
- **EnhancedReporter** generates multi-format reports (html, md, json, sarif, text)
- **ShellSession** manages multi-context workspace with atomic persistence
- **SecurityProfiles** apply pre-configured scanning rules (light/balanced/aggressive)

### MCP Server ↔ Core

- **formatForLLM()** wraps Core outputs for optimal AI agent consumption
- **discoverMcpConfig()** auto-detects server configurations from client configs
- Tool schemas mirror CLI command options for consistency
- English-only by default (override with `MCP_VERIFY_LANG=es`)
- Stdio transport for Claude Desktop / Gemini CLI / Cursor integration

### VSCode Extension ↔ Core

- **DiagnosticsProvider** maps security findings to LSP diagnostics (squiggly lines)
- **ReportPanel** renders HTML reports in webview with CSP protection
- **GlobalState** persists scan history and server configurations
- Commands are thin wrappers around Core use cases (Validator, Fuzzer, etc.)
- Real-time scanning on file save (debounced for performance)

---

## Common Patterns Across Apps

### Error Handling

All apps follow the same error handling pattern:

1. **Try/catch** at command/tool/handler level
2. **User-facing errors**: Use `chalk.red()` + `t()` i18n in CLI, JSON error responses in MCP server
3. **Technical errors**: Go to logger with context for debugging
4. **Exit codes** (CLI only): 0 (success), 1 (validation failed), 2 (error)

**Example (CLI)**:

```typescript
try {
  await runCommand();
} catch (error) {
  console.error(chalk.red(`✗ ${t("command_failed")}: ${error.message}`));
  process.exit(1);
}
```

**Example (MCP Server)**:

```typescript
try {
  const result = await performAction(parsed);
  return { content: [{ type: "text", text: JSON.stringify(result) }] };
} catch (error) {
  return {
    content: [{ type: "text", text: JSON.stringify({ error: error.message }) }],
    isError: true,
  };
}
```

---

### Configuration Loading

All apps use `ConfigManager` from `libs/core/infrastructure/config/`:

1. Load from `mcp-verify.config.json` (cwd or ancestors)
2. Merge with CLI flags or tool inputs
3. Validate with Zod schema
4. Fallback to sensible defaults

**Priority**: CLI flags > environment variables > config file > defaults

---

### Logging

All apps use `libs/core/infrastructure/logging/logger.ts`:

- **CLI**: spinner + logger (file logs in `.mcp-verify/logs/`)
- **MCP Server**: silent by default (logs to stderr, not stdout)
- **VSCode**: output channel + file logs

**Pattern**:

```typescript
import { createScopedLogger } from "@mcp-verify/core";
const logger = createScopedLogger("my-feature");

logger.info("Operation started");
logger.warn("Potential issue detected", { context });
logger.error("Operation failed", error);
```

---

### i18n Support

All apps support internationalization via `libs/core/domain/reporting/i18n.ts`:

- **30+ languages**: en, es, fr, de, ja, zh, pt, ru, etc.
- **Environment variable**: `MCP_VERIFY_LANG=es`
- **Usage**: `import { t } from '@mcp-verify/shared';`
- **Pattern**: `console.log(t('validation_complete'))` instead of hardcoded strings

---

## Testing

```bash
# Unit tests (each app has its own)
cd apps/cli-verifier && npm test
cd apps/mcp-server && npm test
cd apps/vscode-extension && npm test

# Integration tests (root level)
npm test -- tests/integration/

# E2E tests (full app workflows)
npm test -- tests/e2e/

# Coverage (monorepo-wide)
npm test -- --coverage
```

**Test targets**:

- CLI: 40%+ coverage (command handlers, interactive shell components)
- MCP Server: 50%+ coverage (tool handlers, LLM formatting, config discovery)
- VSCode Extension: 40%+ coverage (commands, providers, tree views)

---

## Troubleshooting

### App not building

- **Check**: Are dependencies installed? (`npm install` in root)
- **Check**: Is TypeScript compiler working? (`npx tsc --version`)
- **Fix**: Delete `node_modules/` and `dist/`, then `npm install && npm run build`

### Cross-package imports failing

- **Check**: Are you using `@mcp-verify/*` package names? (not relative paths)
- **Check**: Are packages built? (`npm run build`)
- **Fix**: Rebuild workspace from root: `npm run build`

### App crashes on startup

- **Check**: Are environment variables set? (LLM API keys if using semantic analysis)
- **Check**: Are config files valid JSON?
- **Debug**: Run with `DEBUG=mcp-verify:* <app-command>`

---

## Further Reading

### App-Specific Documentation

- **`cli-verifier/AGENTS.md`** - Interactive shell architecture, commands, multi-context workspace
- **`mcp-server/AGENTS.md`** - Tool specifications, LLM formatting, Claude Desktop integration
- **`vscode-extension/AGENTS.md`** - Extension architecture, diagnostics, tree views, webview panels

### Libs Documentation

- **`libs/core/AGENTS.md`** - Domain logic, 61 security rules, 5 report formats, 3 transports
- **`libs/fuzzer/AGENTS.md`** - Smart Fuzzer engine, 9 generators, 10 detectors, mutation strategies

### Other Documentation

- **`TESTING.md`** - Test strategy, coverage requirements, CI/CD integration
- **`SECURITY.md`** - Security policy, vulnerability reporting
- **`CONTRIBUTING.md`** - Contributing guidelines, code review process

---

**Last Updated**: 2026-04-08

