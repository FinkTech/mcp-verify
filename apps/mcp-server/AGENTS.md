# MCP Server - Validation Tools for AI Agents

> First MCP tool that enables AI agents to validate other MCP servers
> Stdio transport, LLM-optimized outputs, English by default
> **10 specialized tools** for security, quality, and architecture analysis

---

## Quick Start (5 Minutes)

1. Read this file (MCP server architecture overview)
2. Identify which component to modify:
   - Tools → `src/tools/*.ts` (10 tool implementations)
   - LLM formatting → `src/utils/llm-formatter.ts`
   - Config discovery → `src/utils/config-discovery.ts`
3. Follow tool implementation pattern (Zod validation, error handling, formatForLLM)
4. Test: `npx @modelcontextprotocol/inspector node dist/index.js`

---

## Market Differentiator

This is the **first MCP server** that allows AI agents (Claude, GPT, etc.) to:

- Validate MCP servers before deployment
- Scan for security vulnerabilities (60 rules across 6 threat categories)
- **Deep Fuzzing**: Target individual tools with smart attack payloads
- **Semantic Intent Analysis**: Detect malicious tools using advanced LLM reasoning
- **Automatic Hardening**: Suggest secure JSON schemas using the "Shield Pattern"
- Analyze quality metrics (naming, documentation, semantic clarity)
- Generate multi-format reports (JSON, SARIF, Markdown, Text)
- Compare multiple servers side-by-side
- Audit entire MCP ecosystem health

**Key value**: Production-ready security scanning exposed via MCP protocol.

---

## 10 MCP Tools (Quick Reference)

### 1. validateServer

Comprehensive validation (handshake, discovery, schema, security, quality, protocol).

**Input**: `{ command: string; args?: string[]; configPath?: string }`

**Outputs**: LLM-friendly JSON with security/quality scores, recommendations, and actionable next steps.

---

### 2. scanSecurity

Security-focused scan with 60 rules across 6 threat categories: OWASP Top 10 (13 rules), MCP-specific (8 rules), OWASP LLM Top 10 (9 rules), Multi-Agent Attacks (11 rules), Enterprise Compliance (9 rules), and AI Weaponization (10 rules).

**Input**: `{ command: string; args?: string[]; rules?: string[] }`

**Outputs**: Security score, prioritized findings (critical → high → medium → low).

---

### 3. analyzeQuality

Quality analysis (documentation, naming, descriptions, semantic clarity).

**Input**: `{ command: string; args?: string[] }`

**Outputs**: Quality score, improvement suggestions, best practices vs. anti-patterns.

---

### 4. generateReport

Generate detailed reports in multiple formats (json, sarif, text, markdown).

**Input**: `{ command: string; args?: string[]; format?: string; outputPath?: string }`

**Outputs**: Success message + file path. Saves to `./reports/{format}/` by default.

---

### 5. listInstalledServers

Discover all MCP servers from config files (Claude Desktop, Gemini CLI, Cursor, Zed).

**Input**: `{ configPath?: string }`

**Outputs**: Unified list of servers with source file and precedence status (ACTIVE/SHADOWED).

---

### 6. selfAudit

Environment health check (Node.js, Git, Python, Deno, config discovery, live server tests).

**Input**: `{ configPath?: string; skipServerValidation?: boolean }`

**Outputs**: 5-phase diagnostic report (environment, config, dependencies, live tests, recommendations).

---

### 7. compareServers

Multi-server comparison (security, quality, protocol compliance, capability counts).

**Input**: `{ serverNames?: string[]; servers?: Array<{name, command, args}> }`

**Outputs**: Side-by-side comparison matrix with rankings (most/least secure, highest/lowest quality).

---

### 8. fuzzTool (Tier S)

Execute selective fuzzing on a specific MCP tool to identify security vulnerabilities. Supports light, balanced, and aggressive profiles.

**Input**: `{ command, args?, toolName, profile?, maxDuration? }`

**Example**:

```json
{
  "command": "node",
  "args": ["suspicious-server.js"],
  "toolName": "execute_command",
  "profile": "balanced"
}
```

---

### 9. inspectToolSemantics (Tier S)

Analyze an MCP tool for malicious intent using strict LLM analysis. Detects discrepancies between claimed function and actual capabilities.

**Input**: `{ command?, args?, toolName?, toolDefinition?, llmProvider?, llmModel? }`

**Example**:

```json
{
  "command": "node",
  "toolName": "read_file",
  "llmProvider": "anthropic"
}
```

---

### 10. suggestSecureSchema (Tier S)

Analyze MCP tool input schema and suggest security-hardened version with constraints (maxLength, patterns, bounds, enums).

**Input**: `{ command?, args?, toolName?, toolDefinition?, strictness? }`

**Example**:

```json
{
  "command": "node",
  "toolName": "send_email",
  "strictness": "balanced"
}
```

---

## LLM Formatting Strategy (Critical)

**File**: `src/utils/llm-formatter.ts`

Raw validation reports are detailed but unwieldy for AI agents. The `formatForLLM()` function transforms them into **AI-optimized responses** with:

- **High-level status**: valid/invalid/error
- **Actionable recommendations**: safe_to_deploy / review_required / blocking_issues
- **Weighted scores**: security 50%, quality 30%, protocol 20%
- **Prioritized findings**: critical → high → medium → low
- **Human-readable summaries** with emoji indicators (✅ ⚠️ ❌)
- **Next steps**: specific, executable actions

**Example output structure**:

```typescript
{
  status: 'valid',
  recommendation: 'safe_to_deploy',
  overallScore: 85,
  summary: '✅ Server passed all checks',
  scores: { security: 90, quality: 80, protocol: 100 },
  findings: [{ severity: 'medium', message: '...', recommendation: '...' }],
  nextSteps: ['Review medium-severity findings', 'Update descriptions']
}
```

**Why it matters**: Claude consumes this format 20% faster and generates better recommendations than raw JSON.

---

## Config Discovery

**File**: `src/utils/config-discovery.ts`

Auto-detects MCP servers from standard config locations:

| Client              | Config Path                            |
| ------------------- | -------------------------------------- |
| Claude Desktop      | `~/.claude/claude_desktop_config.json` |
| Gemini CLI (global) | `~/.gemini/settings.json`              |
| Gemini CLI (local)  | `./.gemini/settings.json`              |
| Cursor              | `~/.cursor/mcp.json`                   |
| Zed                 | `~/.config/zed/settings.json`          |

**Precedence**: Local configs override global (e.g., `./.gemini/settings.json` shadows `~/.gemini/settings.json`).

**Usage**: `listInstalledServers()` tool uses this to discover all configured servers.

---

## Claude Desktop Integration

**Setup**:

1. Build the server: `cd apps/mcp-server && npm run build`
2. Add to `~/.claude/claude_desktop_config.json`:
   ```json
   {
     "mcpServers": {
       "mcp-verify": {
         "command": "npx",
         "args": ["-y", "-p", "@finktech/mcp-verify", "mcp-verify-server"]
       }
     }
   }
   ```
3. Restart Claude Desktop
4. Verify with: "List available MCP tools" in Claude

**Environment variables**:

- `MCP_VERIFY_LANG=es` - Change language (default: en)
- `DEBUG=mcp-verify:*` - Enable debug logging

---

## Tool Implementation Pattern

All tools follow this structure:

```typescript
// 1. Import dependencies
import { MCPValidator, createScopedLogger } from "@mcp-verify/core";
import { formatForLLM } from "../utils/llm-formatter.js";

// 2. Setup logger + i18n
const logger = createScopedLogger("myToolTool");
const lang = (process.env.MCP_VERIFY_LANG as Language) || "en";

// 3. Export tool function
export async function myToolTool(args: unknown): Promise<ToolResult> {
  try {
    // 4. Validate input (Zod schema)
    const parsed = MyToolArgsSchema.parse(args);

    // 5. Create transport + validator
    const transport = new StdioTransport(parsed.command, parsed.args);
    const validator = new MCPValidator(transport);

    // 6. Execute validation logic
    const result = await validator.validate();

    // 7. Cleanup resources
    validator.cleanup();

    // 8. Format for LLM
    const llmOutput = formatForLLM(result);

    // 9. Return MCP-compliant response
    return {
      content: [{ type: "text", text: JSON.stringify(llmOutput) }],
    };
  } catch (error) {
    logger.error("Tool failed", error as Error);
    return {
      content: [{ type: "text", text: JSON.stringify({ error: "..." }) }],
      isError: true,
    };
  }
}
```

---

## Modifying the MCP Server

**Add new tool**:

1. Create `src/tools/my-tool.ts` (follow pattern above)
2. Export tool function: `export async function myToolTool(args): Promise<ToolResult>`
3. Register in `src/server.ts`:
   ```typescript
   server.setRequestHandler(CallToolRequestSchema, async (request) => {
     switch (request.params.name) {
       case "myTool":
         return await myToolTool(request.params.arguments);
       // ...
     }
   });
   ```
4. Add tool schema to `src/server.ts`:
   ```typescript
   server.setRequestHandler(ListToolsRequestSchema, async () => ({
     tools: [
       { name: 'myTool', description: '...', inputSchema: {...} },
       // ...
     ]
   }));
   ```
5. Rebuild: `npm run build`

**Update LLM formatting**:

- Edit `src/utils/llm-formatter.ts`
- Adjust weighted scores, emoji indicators, or next steps
- Test with Claude to validate improvements

**Change language**:

- Translations live in `libs/core/domain/reporting/i18n.ts`
- Set `MCP_VERIFY_LANG=es` environment variable
- English is default (hardcoded fallback)

---

## Troubleshooting

### Server not appearing in Claude Desktop

- **Check**: Is path in `claude_desktop_config.json` correct and absolute?
- **Check**: Did you rebuild after code changes? (`npm run build`)
- **Check**: Did you restart Claude Desktop after config change?
- **Fix**: Check Claude Desktop logs (`~/.claude/logs/`)
- **Debug**: Run manually: `node dist/index.js` and look for errors

### Tools not listing in Claude

- **Check**: Is server connected? (green indicator in Claude)
- **Check**: Is `ListToolsRequestSchema` handler registered?
- **Check**: Are tool schemas valid JSON Schema?
- **Fix**: Restart Claude Desktop
- **Debug**: Run with `DEBUG=mcp-verify:* node dist/index.js`

### Tool execution returns error

- **Check**: Are arguments matching tool's `inputSchema`?
- **Check**: Is target server running and accessible?
- **Check**: Are timeouts sufficient for slow validation tasks?
- **Fix**: Check error message in tool response JSON
- **Debug**: Add `console.error(JSON.stringify(error))` in tool handler

### LLM formatting not working

- **Check**: Is `formatForLLM()` called before returning result?
- **Check**: Is raw validation report structure valid?
- **Check**: Are all required fields present in output?
- **Debug**: Compare raw report vs formatted output
- **Debug**: Add `console.log(JSON.stringify(llmOutput))` before return

### Config discovery not finding servers

- **Check**: Are config files in standard locations?
  - `~/.claude/claude_desktop_config.json`
  - `~/.gemini/settings.json`
  - `~/.cursor/mcp.json`
- **Check**: Are config files valid JSON?
- **Check**: Do configs have `mcpServers` or `mcp_servers` key?
- **Fix**: Run `selfAudit` tool to diagnose config issues
- **Debug**: Add `console.log` in `discoverMcpConfig()`

### Server crashes on tool execution

- **Check**: Is error handling present in all tool handlers?
- **Check**: Is cleanup (e.g., `validator.cleanup()`) called on success AND error?
- **Check**: Are there uncaught promise rejections?
- **Fix**: Wrap all async code in try/catch
- **Debug**: Check stderr logs for stack traces

### Environment variables not loading

- **Check**: Are env vars set before starting server?
- **Check**: Is `.env` file in correct directory (if using dotenv)?
- **Check**: Are variable names exact? (`MCP_VERIFY_LANG`, not `MCP_LANG`)
- **Debug**: Add `console.log(process.env)` at server startup

### Stdio communication errors

- **Check**: Is server using stdio transport correctly?
- **Check**: Are messages JSON-RPC 2.0 compliant?
- **Check**: Is stderr used ONLY for logs (not JSON-RPC messages)?
- **Fix**: Ensure all JSON-RPC goes to stdout, logs to stderr
- **Debug**: Use MCP Inspector to test protocol compliance

---

## Testing

```bash
# Unit tests (tool handlers, LLM formatting, config discovery)
cd apps/mcp-server && npm test

# Test specific tool
npm test -- src/tools/validate-server.spec.ts

# Test LLM formatter
npm test -- src/utils/llm-formatter.spec.ts

# Integration tests (full tool execution via MCP protocol)
npm test -- --testPathPattern=integration

# Manual testing with MCP Inspector
npx @modelcontextprotocol/inspector node dist/index.js

# Watch mode
npm test -- --watch

# Coverage report
npm test -- --coverage
```

**Test scenarios**:

1. **Tool Handlers**: Each tool with valid/invalid inputs, error cases
2. **LLM Formatter**: Verify formatting adheres to AI-optimized structure
3. **Config Discovery**: Test all client config paths (Claude, Gemini, Cursor, Zed)
4. **MCP Protocol**: Handshake, tool listing, tool execution, error responses
5. **Timeout Handling**: Tool execution timeouts, cleanup on abort

**Example test**:

```typescript
import { validateServerTool } from "../tools/validate-server";

describe("validateServerTool", () => {
  it("should return LLM-formatted output for valid server", async () => {
    const result = await validateServerTool({
      command: "node",
      args: ["test-server.js"],
    });

    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();

    const output = JSON.parse(result.content[0].text);
    expect(output.status).toBe("valid");
    expect(output.overallScore).toBeGreaterThan(0);
    expect(output.nextSteps).toBeInstanceOf(Array);
  });

  it("should handle missing command gracefully", async () => {
    const result = await validateServerTool({});

    expect(result.isError).toBe(true);
    const output = JSON.parse(result.content[0].text);
    expect(output.error).toContain("command");
  });
});
```

**MCP Inspector Testing**:

```bash
# Start Inspector UI
npx @modelcontextprotocol/inspector node dist/index.js

# Then in UI:
# 1. Connect to server
# 2. List tools (should see all 7 tools)
# 3. Execute validateServer with test params
# 4. Verify JSON output structure
```

---

**Last Updated**: 2026-03-26
