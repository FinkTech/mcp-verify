# Interactive Shell - Modular Architecture

> Refactored from monolithic `interactive.ts` (2,144 lines) → 6 core modules + handlers

---

## 📁 Directory Structure

```
interactive/
├── types.ts           # Type definitions (SessionState, ParseResult, Language)
├── parser.ts          # ShellParser class (tokenization, flags, redirection)
├── persistence.ts     # PersistenceManager class (atomic I/O, history, session)
├── session.ts         # ShellSession class (multi-context state management)
├── completer.ts       # ContextCompleter class (3-level TAB completion)
├── utils.ts           # Helper functions (withRedirect, buildPrompt, etc.)
├── router.ts          # dispatch() - Command routing + dispatcher
├── handlers/          # Command handlers (17 total)
│   ├── shared.ts      # Shared utilities (resolveTarget, mergeOptions)
│   ├── validate.ts    # handleValidate
│   ├── fuzz.ts        # handleFuzz
│   ├── doctor.ts      # handleDoctor
│   ├── stress.ts      # handleStress
│   ├── dashboard.ts   # handleDashboard
│   ├── play.ts        # handlePlay
│   ├── proxy.ts       # handleProxy
│   ├── mock.ts        # handleMock
│   ├── init.ts        # handleInit
│   ├── fingerprint.ts # handleFingerprint
│   ├── inspect.ts     # handleInspect
│   ├── examples.ts    # handleExamples
│   ├── session.ts     # Session management handlers
│   ├── info.ts        # Help and about handlers
│   └── context-clone.ts # Context cloning handler
└── index.ts           # startInteractiveMode() - Entry point
```

---

## ✅ Complete Implementation (All Phases)

### 1. types.ts

**Exports**:

- `Language` - 'en' | 'es'
- `SessionState` - Multi-context session state interface
- `WorkspaceSession` - Persisted session format
- `ParseResult` - Tokenization + redirection result

**Dependencies**: None (type-only imports)

---

### 2. parser.ts

**Exports**:

- `ShellParser` class

**Public Methods**:

- `static parse(input: string): ParseResult` - Main entry point
- `static tokenise(input: string): string[]` - Quote-aware tokenization
- `static extractFlags(tokens: string[]): Record<string, string | true>` - Flag parsing
- `static extractPositionals(tokens: string[]): string[]` - Non-flag args

**Dependencies**:

- `./types` (ParseResult)

---

### 3. persistence.ts

**Exports**:

- `PersistenceManager` class

**Public Methods**:

- `static getPaths()` - Dynamic path resolution
- `static loadHistory(): string[]` - Load global history
- `static appendHistory(entry: string): void` - Atomic history append
- `static hydrateReadlineHistory(rl: readline.Interface): void` - Inject history into readline
- `static loadWorkspaceSession(): WorkspaceSession | undefined` - Load legacy session
- `static saveWorkspaceSession(state): void` - Save legacy session
- `static loadWorkspaceData(): WorkspaceContexts | LegacyWorkspaceSession | undefined` - Load v1.0 data
- `static saveWorkspaceContexts(contexts: WorkspaceContexts): void` - Atomic save v1.0
- `static writeOutput(filePath, content, append): void` - Output redirection

**Dependencies**:

- `./types` (WorkspaceSession)
- `../types/workspace-context` (WorkspaceContexts, LegacyWorkspaceSession)
- `../managers/migration` (migrateSessionFile)
- `@mcp-verify/core` (ConfigLoader)

---

### 4. session.ts

**Exports**:

- `ShellSession` class

**Public Methods**:

- Multi-context: `getActiveContext()`, `switchContext()`, `createContext()`, `cloneContext()`, `deleteContext()`, `listContexts()`
- Profiles: `setProfile()`, `saveCustomProfile()`
- Legacy: `setTarget()`, `setLang()`, `setConfig()`
- Security: `recordCommand()`, `redactSecrets()`, `redactConfig()`
- Utils: `elapsedTime()`, `fetchAvailableTools()`

**State**:

- `readonly state: SessionState` - Single source of truth

**Dependencies**:

- `./types` (Language, SessionState, WorkspaceSession)
- `./persistence` (PersistenceManager)
- `../types/workspace-context` (WorkspaceContexts, WorkspaceContext, LegacyWorkspaceSession)
- `../managers/global-config-manager` (GlobalConfigManager)
- `../managers/environment-loader` (EnvironmentLoader)
- `../managers/migration` (detectSessionVersion)
- `../profiles/security-profiles` (SECURITY_PROFILES, getSecurityProfile)
- `@mcp-verify/shared` (setLanguage)
- `@mcp-verify/core` (createTransport, ITransport)

---

### 5. completer.ts

**Exports**:

- `ContextCompleter` class
- `COMMAND_FLAGS` - Flags per command
- `PRIMARY_COMMANDS` - Main command list
- `ALL_COMMANDS` - All commands + aliases

**Public Methods**:

- `static complete(line: string, session?: ShellSession): [string[], string]` - 3-level completion

**Dependencies**:

- `./parser` (ShellParser)
- `./session` (ShellSession - optional parameter)

---

### 6. utils.ts

**Exports**:

- `withRedirect<T>(parsed, action): Promise<T>` - Output redirection wrapper
- `buildPrompt(session): string` - Dynamic prompt generation
- `showSessionSummary(session): void` - Exit summary
- `openUrl(url): void` - Cross-platform URL launcher
- `levenshteinDistance(a, b): number` - String similarity
- `getSimilarCommands(input): string[]` - Command suggestions

**Dependencies**:

- `./types` (ParseResult)
- `./session` (ShellSession)
- `./persistence` (PersistenceManager)
- `./completer` (PRIMARY_COMMANDS)
- `@mcp-verify/shared` (t)

### 7. router.ts

**Exports**:

- `dispatch()` - Main command dispatcher
- `showSessionSummary()` - Exit summary

**Public Methods**:

- `dispatch(cmd, args, session, rl): Promise<void>` - Routes commands to handlers

**Dependencies**:

- All handler files from `./handlers/*`
- `../handlers/*` (context, profile, status handlers)
- `./session` (ShellSession)
- `./persistence` (PersistenceManager)

**Handles 18+ commands**: validate, fuzz, doctor, stress, dashboard, play, proxy, mock, init, fingerprint, inspect, examples, context, profile, status, session management, help, about

---

### 8. index.ts (Entry Point)

**Exports**:

- `startInteractiveMode()` - Main entry point

**Functionality**:

- Loads workspace session
- Creates ShellSession instance
- Sets up readline interface with TAB completion
- Hydrates command history
- Starts REPL loop
- Handles exit and Ctrl+C gracefully

**Dependencies**:

- `./session`, `./parser`, `./persistence`, `./completer`, `./utils`, `./router`

---

### 9. handlers/ (17 files)

All handlers follow consistent patterns:

- Accept `(args, session, rl)` parameters
- Use `resolveTarget()` and `mergeOptions()` from shared.ts
- Handle errors gracefully with user-friendly messages
- Support output redirection via `withRedirect()`

**Complete handler list**:

- Security tools: validate, fuzz, doctor, stress, dashboard, play, proxy
- Utilities: mock, init, fingerprint, inspect, examples
- Session: session.ts (set, target, lang, config, history)
- Context: context-clone.ts
- Info: info.ts (help, about)
- Shared: shared.ts (utilities)

---

## 🔄 Dependency Graph

```
types.ts (no deps)
   ↓
parser.ts
   ↓
persistence.ts ──→ types.ts
   ↓
session.ts ──→ types.ts, persistence.ts, external managers
   ↓
completer.ts ──→ parser.ts, session.ts (optional)
   ↓
utils.ts ──→ types.ts, session.ts, persistence.ts, completer.ts
   ↓
handlers/shared.ts ──→ session.ts, parser.ts
   ↓
handlers/*.ts ──→ handlers/shared.ts, session.ts
   ↓
router.ts ──→ handlers/*.ts, session.ts
   ↓
index.ts ──→ router.ts, session.ts, persistence.ts, completer.ts, utils.ts
```

**No circular dependencies** ✅

---

## 💎 Key Benefits

- **Single Responsibility**: Each module handles exactly one concern (parsing, session, UI, etc.).
- **Maintainable**: Most files are < 200 lines of code.
- **Extensible**: Adding a new command only requires creating a new handler and registering it in the router.
- **Testable**: Decoupled modules allow for targeted unit testing of logic (e.g., parser, persistence).
- **Behavior**: Preserves 100% feature parity with the previous monolithic implementation (history, TAB completion, output redirection).

---

_Part of the mcp-verify CLI application._
