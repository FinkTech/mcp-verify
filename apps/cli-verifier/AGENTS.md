# CLI Verifier - Interactive Shell

> Multi-context workspace with persistent state and security profiles
> Primary user-facing tool for MCP server validation

---

## Quick Start (5 Minutes)

1. Read this file (CLI architecture overview)
2. Identify which component to modify:
   - Commands → `src/commands/*.ts` (13 command handlers)
   - Interactive shell → `src/commands/interactive/` (26 modular files)
   - Security profiles → `src/commands/profiles/security-profiles.ts`
3. Follow existing patterns (modular architecture, atomic persistence)
4. Test: `npm run dev` (watch mode) or `npm test`

---

## Two Modes of Operation

### 1. Interactive Shell (Default)
Persistent REPL with multi-context workspace:
- Multi-context management (dev, staging, prod, etc.)
- Command history across sessions
- Security profiles (light/balanced/aggressive)
- Tab-completion (3 levels: commands, flags, paths)
- Output redirection (`>`, `>>`)
- State persistence (atomic writes)

**Start**: `npx mcp-verify` (no args) → `src/commands/interactive/index.ts`

### 2. One-Shot Commands
Traditional CLI for scripting and CI/CD:
```bash
npx mcp-verify validate <target>
npx mcp-verify fuzz <target> --tool Echo
npx mcp-verify stress <target> --rps 10
npx mcp-verify doctor
```

**Entry**: `src/bin/index.ts` → Commander.js command handlers

---

## Architecture (Data Flow)

```
User Input → ShellParser → ContextCompleter → ShellSession
                ↓                                 ↓
          Extract tokens              Merge defaults + flags
          Detect redirection          Apply security profile
                ↓                                 ↓
          dispatch() ─────────→ Command Handler (validate, fuzz, etc.)
                                        ↓
                              withRedirect() → Output capture
                                        ↓
                              PersistenceManager → Atomic writes
                                        ↓
                              User Output (stdout/file)
```

---

## Core Components (Modular Architecture)

**Location**: `src/commands/interactive/` (26 modular files)

### 1. ShellParser
**File**: `src/commands/interactive/parser.ts`

Tokenizes shell input with minimal POSIX compliance.

**Key methods**:
- `parse(input: string): ParseResult` - Main entry point
- `tokenise(input: string): string[]` - Respects quotes
- `extractFlags(tokens): Record<string, string | true>` - Strict flag parsing
- `extractPositionals(tokens): string[]` - Non-flag args

**Features**:
- Single/double quotes with escaping
- Output redirection: `> file.txt` (overwrite), `>> file.txt` (append)
- No pipes, input redirection, or variable expansion (by design)

---

### 2. PersistenceManager
**File**: `src/commands/interactive/persistence.ts`

Atomic file I/O with secret redaction.

**Paths**:
- History: `~/.mcp-verify/history.json` (global, all workspaces)
- Session: `.mcp-verify/session.json` (local, current workspace)
- Config: `~/.mcp-verify/config.json` (global user settings)

**Key methods**:
- `loadHistory()` / `appendHistory(entry)`
- `loadWorkspaceData()` / `saveWorkspaceContexts(contexts)`
- `writeOutput(filePath, content, append)` - Output redirection

**Atomic Write Pattern**:
1. Write to `target.json.tmp`
2. Atomically rename tmp → target (filesystem operation)
3. On error, cleanup temp file

Guarantees no partial writes even if process crashes.

---

### 3. ContextCompleter
**File**: `src/commands/interactive/completer.ts`

Three-level contextual autocomplete for readline.

**Levels**:
1. **Commands**: `val[TAB]` → `validate`, `validator`
2. **Flags**: `validate --[TAB]` → `--output`, `--format`, `--tool`
3. **Paths**: `validate /ho[TAB]` → `/home/user/...`

**Command Aliases**:
- `v` → validate, `f` → fuzz, `d` → doctor, `s` → stress
- `m` → mock, `ex` → examples, `cfg` → config
- `h` → help, `q` → exit

---

### 4. ShellSession
**File**: `src/commands/interactive/session.ts`

Single source of truth for all mutable state.

**Key methods**:
- `getActiveContext()` / `switchContext(name)` / `createContext(name)`
- `setProfile(profileName)` / `saveCustomProfile(name)`
- `setTarget(value)` / `setLang(lang)` / `setConfig(key, value)`
- `recordCommand(cmd)` / `redactSecrets(text)` / `redactConfig(config)`
- `fetchAvailableTools()` - Dynamic tool discovery from server

**State Structure**:
```typescript
{
  activeContextName: 'dev',
  contexts: { dev: {...}, staging: {...} },
  globalConfig: { lang: 'en', reportFormat: 'html' },
  target: 'node server.js',
  lang: 'en',
  history: ['validate node s.js', ...],
  startedAt: Date,
  availableTools: ['Echo', 'Add', ...]
}
```

**Critical**: All mutations call `persistContext()` for atomic writes.

---

### 5. Router & Dispatcher
**File**: `src/commands/interactive/router.ts`

Routes commands to handlers with intelligent default resolution.

**Flow**:
1. Validate target availability (if command requires it)
2. Merge session defaults with CLI flags
3. Apply security profile settings
4. Call command handler (validate, fuzz, stress, etc.)
5. Handle output redirection via `withRedirect()`

**Special commands**:
- `ctx`, `use`, `create`, `delete` - Multi-context workspace management
- `profile` - Security profile switching
- `help`, `exit`, `clear` - Shell utilities

**Handlers**: `src/commands/interactive/handlers/*.ts` (17 handler files)

---

## Security Profiles

**File**: `src/commands/profiles/security-profiles.ts`

Three built-in presets + custom profile support:

| Profile | Payloads | Mutations | Detection | Score Threshold | Fail On |
|---------|----------|-----------|-----------|-----------------|---------|
| **light** | 25 | 0 | Basic errors | 60 | Critical |
| **balanced** | 50 | 3 | Errors + timing | 70 | Critical |
| **aggressive** | 100 | 5 | Full detection | 90 | Critical + High |

**Usage in shell**:
```bash
> profile balanced      # Switch profile
> profile save my-custom  # Save current config as custom profile
```

**Hardcoded in**: `SECURITY_PROFILES` const (cannot be changed at runtime, only custom profiles can be saved)

---

## Multi-Context Workspace

**Motivation**: Manage multiple MCP servers (dev, staging, prod) in a single session.

**Commands**:
```bash
> ctx                    # List all contexts
> use staging            # Switch to 'staging' context
> create prod            # Create new context 'prod'
> create prod --from dev # Clone 'dev' config to 'prod'
> delete old-ctx         # Remove 'old-ctx'
```

**State isolation**:
- Each context has its own: target, config, tool cache
- Global settings shared: language, report format
- History shared across all contexts

**Persistence**: `.mcp-verify/session.json` (atomic writes)

---

## Critical Patterns

### Secret Redaction
Before persisting history or config:
```typescript
redactSecrets(text: string): string {
  // Redacts: API keys, tokens, passwords in --api-key, --token, --password flags
  // Pattern: --secret-flag [REDACTED]
}
```

### Atomic Writes
All persistence uses:
1. Write to `.tmp` file
2. `fs.renameSync(tmpPath, targetPath)` (atomic at OS level)
3. On error, cleanup `.tmp` file

### Timeout Enforcement
All commands have strict timeouts (default 120s):
- `validate`: 120s
- `fuzz`: 300s (5 min)
- `stress`: 600s (10 min)

---

## Top 5 Commands (Quick Reference)

### 1. validate
```bash
validate <target> [--tool Tool1,Tool2] [--format html] [--output report.html]
```
Security validation with 60 rules (13 OWASP + 8 MCP + 39 advanced threats).

### 2. fuzz
```bash
fuzz <target> --tool Echo [--payloads 50] [--mutations 3]
```
Intelligent payload generation with feedback loops.

### 3. stress
```bash
stress <target> [--duration 30] [--rps 10] [--concurrency 5]
```
Load and concurrency testing.

### 4. doctor
```bash
doctor [<target>]
```
Environment diagnostics (Node.js, npm, MCP SDK, etc.).

### 5. interactive
```bash
# Just run without args
npx mcp-verify
```
Start interactive shell with multi-context workspace.

**Full command list**: See `src/commands/*.ts` or type `help` in shell.

---

## Modifying the CLI

**Add new command**:
1. Create `src/commands/my-command.ts`
2. Implement handler function
3. Register in `src/bin/index.ts` (Commander.js)
4. Add to dispatcher in `src/commands/interactive/router.ts` (for shell mode)
5. Add to `ContextCompleter` for autocomplete

**Add new security profile**:
1. Edit `src/commands/profiles/security-profiles.ts`
2. Add to `SECURITY_PROFILES` const
3. No restart needed (profiles loaded at runtime)

**Change persistence paths**:
- Edit constants in `PersistenceManager` class
- Ensure atomic write pattern is preserved

---

## Troubleshooting

### Interactive shell not starting
- **Check**: Is Node.js 20+ installed? (`node --version`)
- **Check**: Are dependencies installed? (`npm install`)
- **Check**: Is `.mcp-verify/` directory writable? (permissions issue)
- **Fix**: Delete `.mcp-verify/session.json` if corrupted
- **Debug**: Run with `DEBUG=mcp-verify:* npx mcp-verify`

### Command not found in shell
- **Check**: Did you type the full command name? (autocomplete with TAB)
- **Check**: Is command in `router.ts` dispatcher?
- **Check**: Look for typos in command name
- **Debug**: Type `help` to see all available commands

### Multi-context switching fails
- **Check**: Does context exist? Run `ctx` to list all contexts
- **Check**: Is `.mcp-verify/session.json` corrupted?
- **Fix**: Run `create <context-name>` to recreate context
- **Fix**: Delete `.mcp-verify/session.json` and restart shell
- **Debug**: Check console for JSON parse errors

### Output redirection not working
- **Check**: Is path valid and writable? (e.g., `> /path/to/output.txt`)
- **Check**: Does parent directory exist?
- **Check**: Are you using `>` (overwrite) or `>>` (append) correctly?
- **Debug**: Add `console.log` in `PersistenceManager.writeOutput()`

### History not persisting across sessions
- **Check**: Is `~/.mcp-verify/history.json` writable?
- **Check**: Is atomic write completing? (look for `.tmp` files)
- **Fix**: Delete `~/.mcp-verify/history.json` if corrupted
- **Debug**: Add breakpoint in `PersistenceManager.appendHistory()`

### Security profile not applying
- **Check**: Did you run `profile <name>` to switch profile?
- **Check**: Is profile name valid? (`light`, `balanced`, `aggressive`, or custom)
- **Check**: Are profile settings being merged in `router.ts`?
- **Debug**: Add `console.log(session.getProfile())` before command execution

### Autocomplete not working
- **Check**: Is `ContextCompleter` registered with readline?
- **Check**: Are you using TAB key (not space)?
- **Check**: Is completion context correct? (commands vs flags vs paths)
- **Debug**: Add `console.log` in `ContextCompleter.complete()`

### Commands timing out
- **Check**: Is target server responding? (test manually)
- **Check**: Is timeout too short for slow servers? (default: 120s)
- **Fix**: Increase timeout with `--timeout 300` flag
- **Fix**: Check server logs for errors

---

## Testing

```bash
# Unit tests (command handlers, parser, session)
cd apps/cli-verifier && npm test

# Test specific command
npm test -- src/commands/validate.spec.ts

# Test interactive shell components
npm test -- src/commands/interactive/

# Integration tests (full command flow)
npm test -- --testPathPattern=integration

# Watch mode (auto-run on changes)
npm test -- --watch

# Coverage report
npm test -- --coverage
```

**Test scenarios**:
1. **Parser**: Quote handling, flag extraction, redirection detection
2. **Session**: Multi-context switching, profile application, persistence
3. **Commands**: Each command handler with various flag combinations
4. **Completer**: 3-level autocomplete (commands, flags, paths)
5. **Persistence**: Atomic writes, secret redaction, crash recovery

**Example test**:
```typescript
import { ShellParser } from '../interactive/parser';

describe('ShellParser', () => {
  let parser: ShellParser;

  beforeEach(() => {
    parser = new ShellParser();
  });

  it('should parse redirection correctly', () => {
    const result = parser.parse('validate node server.js > report.json');

    expect(result.command).toBe('validate');
    expect(result.positionals).toEqual(['node', 'server.js']);
    expect(result.redirection).toEqual({ type: 'overwrite', file: 'report.json' });
  });

  it('should respect quoted strings with spaces', () => {
    const result = parser.parse('validate "node server.js" --output "My Report.html"');

    expect(result.positionals).toEqual(['node server.js']);
    expect(result.flags['output']).toBe('My Report.html');
  });
});
```

---

**Last Updated**: 2026-03-26
