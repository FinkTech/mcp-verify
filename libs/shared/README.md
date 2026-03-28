# 🔧 Shared Utilities

Common utilities used across **all** mcp-verify applications and libraries. These are pure, framework-agnostic helpers that solve specific problems.

---

## 📋 Purpose

This library provides reusable utilities that are:

- **Pure Functions**: No side effects, testable
- **Framework-Agnostic**: No dependencies on Express, Commander, etc.
- **Used Everywhere**: By 2+ apps or libs
- **Small & Focused**: Each utility solves one problem

---

## 📁 Structure

```
libs/shared/
├── utils/
│   ├── cli/                         # CLI-specific utilities
│   │   ├── i18n-helper.ts           # Translation (t() function)
│   │   ├── output-helper.ts         # Console output (quiet mode)
│   │   ├── error-formatter.ts       # User-friendly error messages
│   │   └── external-editor.ts       # Launch $EDITOR for input
│   │
│   ├── path-validator.ts            # 🔒 Path traversal prevention
│   ├── url-validator.ts             # 🔒 Private IP detection
│   ├── api-key-manager.ts           # API key storage/retrieval
│   ├── command-normalizer.ts        # Command string normalization
│   ├── deep-merge.ts                # Deep object merging
│   ├── regex-safe.ts                # Safe regex execution
│   ├── smart-launcher.ts            # Process launcher with retries
│   └── reporting/
│       └── report-saver.ts          # Report file management
│
└── logger/
    └── logger.ts                    # Structured logging
```

---

## 🛠️ Utility Catalog

### 🌐 i18n Helper (`utils/cli/i18n-helper.ts`)

**Purpose**: Translate user-facing strings (English ↔ Spanish)

**Usage**:
```typescript
import { t, initLanguage, getCurrentLanguage } from 'libs/shared/utils/cli/i18n-helper';

// Initialize language detection
initLanguage(); // Detects from env, config, or system locale

// Translate keys
console.log(t('validation_complete'));  // → "Validation complete" or "Validación completa"

// With parameters
console.log(t('server_found', { name: 'MyServer' }));  // → "Server found: MyServer"

// Get current language
const lang = getCurrentLanguage();  // → 'en' | 'es'
```

**Key Features**:
- Auto-detects language (env → config → system locale → default)
- Parameter substitution: `{name}`, `{count}`, etc.
- Falls back to English if key missing

**When to use**:
- Any user-facing message (CLI output, errors, warnings)
- ✅ DO: `log(t('validation_complete'))`
- ❌ DON'T: `log('Validation complete')`

---

### 📤 Output Helper (`utils/cli/output-helper.ts`)

**Purpose**: Console output with quiet mode support (for CI/CD)

**Usage**:
```typescript
import { createLogger } from 'libs/shared/utils/cli/output-helper';

const isQuiet = Boolean(options.quiet);
const log = createLogger(isQuiet);

// Informational (suppressed if quiet)
log.info('Processing...');
log.success('Done!');
log.warn('Warning message');
log.log('Normal output');

// Errors (always shown, even in quiet mode)
log.error('Error occurred');

// Debug (only if DEBUG env set)
log.debug('Debug info');
```

**Key Features**:
- Quiet mode respects `--quiet` flag
- Errors always shown (critical info)
- Debug mode controlled by `DEBUG=1` env variable

**When to use**:
- Any CLI command that might run in CI/CD
- Commands with `--quiet` or `--json-stdout` flags

---

### 🔒 Path Validator (`utils/path-validator.ts`)

**Purpose**: Prevent path traversal attacks (`../../../etc/passwd`)

**Security**: ⚠️ CRITICAL - Prevents arbitrary file writes

**Usage**:
```typescript
import { PathValidator } from 'libs/shared/utils/path-validator';

// Validate output paths (reports, logs)
try {
  const safePath = PathValidator.validateOutputPath(
    options.output,     // User input: './reportes/custom.json'
    './reportes'        // Base directory
  );
  fs.writeFileSync(safePath, content);
} catch (error) {
  console.error('Invalid path:', error.message);
}

// Validate baseline paths
const baselinePath = PathValidator.validateBaselinePath(options.baseline);

// Check if path is safe (returns boolean)
if (PathValidator.isSafeOutputPath(userPath)) {
  // Proceed
}
```

**What it blocks**:
- ❌ `../../../etc/passwd` - Escapes base directory
- ❌ `/absolute/path/outside` - Absolute paths
- ❌ `../../outside/reportes/file.json` - Relative escapes

**What it allows**:
- ✅ `./reportes/custom.json` - Within base directory
- ✅ `reports/test.html` - Relative within base
- ✅ `./reportes/subdir/file.json` - Subdirectories

**When to use**:
- **ALWAYS** when writing files to user-specified paths
- Any `--output`, `--save`, `--baseline` flag
- Before `fs.writeFileSync()`, `fs.createWriteStream()`

---

### 🌐 URL Validator (`utils/url-validator.ts`)

**Purpose**: Detect private/reserved IP addresses (SSRF awareness)

**Security**: ⚠️ Warns users about SSRF risks

**Usage**:
```typescript
import { URLValidator } from 'libs/shared/utils/url-validator';

const target = 'http://192.168.1.1:3000';

// Check if URL points to private IP
if (URLValidator.isPrivateOrLocalhost(target)) {
  const reason = URLValidator.getPrivateIPReason(target);
  console.warn(`⚠️  Connecting to private network: ${reason}`);
  // → "Private network (192.168.0.0/16)"
}

// Check if string is a URL (not STDIO command)
if (URLValidator.isURL(target)) {
  // It's http:// or https://
}
```

**What it detects**:
- `10.x.x.x` - Private network (10.0.0.0/8)
- `172.16.x.x - 172.31.x.x` - Private network (172.16.0.0/12)
- `192.168.x.x` - Private network (192.168.0.0/16)
- `127.x.x.x` - Loopback (localhost)
- `169.254.x.x` - Link-local (169.254.0.0/16)
- `localhost` - Localhost hostname
- `[::1]` - IPv6 loopback
- `[fe80:...]` - IPv6 link-local

**When to use**:
- Before connecting to user-provided HTTP/HTTPS URLs
- To warn about potential SSRF risks (not blocking, just warning)

---

### ❌ Error Formatter (`utils/cli/error-formatter.ts`)

**Purpose**: Convert errors to user-friendly messages with troubleshooting tips

**Usage**:
```typescript
import { formatError } from 'libs/shared/utils/cli/error-formatter';

try {
  await validator.run();
} catch (error) {
  const formatted = formatError(error, {
    command: 'mcp-verify validate',
    target: 'http://localhost:3000'
  }, verbose);

  console.error(formatted.title);        // → "Connection Failed"
  console.error(formatted.message);      // → "The MCP server could not be reached at http://localhost:3000"

  // Show tips
  formatted.tips.forEach(tip => console.log(`  • ${tip}`));
  // → "Check if the server is running: ps aux | grep node"
  // → "Verify the port number is correct"
  // → "Try: mcp-verify doctor http://localhost:3000"

  // Technical details (if verbose)
  if (formatted.technicalDetails) {
    console.error(formatted.technicalDetails);
  }
}
```

**Error Categories**:
- `connection` - ECONNREFUSED, server not reachable
- `dns` - ENOTFOUND, hostname not resolved
- `timeout` - ETIMEDOUT, server slow
- `protocol` - Invalid JSON, protocol violations
- `auth` - 401/403, authentication failed
- `unknown` - Other errors

**When to use**:
- In CLI command catch blocks
- When displaying errors to users (not logs)

---

### 🔐 API Key Manager (`utils/api-key-manager.ts`)

**Purpose**: Securely store and retrieve API keys (Anthropic, OpenAI, etc.)

**Usage**:
```typescript
import { APIKeyManager } from 'libs/shared/utils/api-key-manager';

// Store API key (encrypted in ~/.mcp-verify/keys.json)
APIKeyManager.saveKey('anthropic', 'sk-ant-...');

// Retrieve API key
const key = APIKeyManager.getKey('anthropic');
if (!key) {
  console.error('No API key found for anthropic');
}

// List all stored providers
const providers = APIKeyManager.listKeys();  // → ['anthropic', 'openai']

// Delete key
APIKeyManager.deleteKey('anthropic');
```

**When to use**:
- CLI commands that need API keys (--llm anthropic)
- Interactive prompts for API key input

---

### 📝 Command Normalizer (`utils/command-normalizer.ts`)

**Purpose**: Normalize command strings for consistent handling

**Usage**:
```typescript
import { normalizeCommand } from 'libs/shared/utils/command-normalizer';

// Normalize various command formats
const cmd1 = normalizeCommand('  node  server.js  ');  // → 'node server.js'
const cmd2 = normalizeCommand('npx\t\ttsx\tserver.ts'); // → 'npx tsx server.ts'
```

**When to use**:
- Before executing STDIO commands
- When comparing commands for equality

---

### 🔀 Deep Merge (`utils/deep-merge.ts`)

**Purpose**: Deep merge objects (config merging, option overrides)

**Usage**:
```typescript
import { deepMerge } from 'libs/shared/utils/deep-merge';

const defaults = {
  timeout: 10000,
  transport: 'stdio',
  options: {
    verbose: false,
    quiet: false
  }
};

const userOptions = {
  timeout: 30000,
  options: {
    verbose: true
  }
};

const merged = deepMerge(defaults, userOptions);
// → {
//   timeout: 30000,
//   transport: 'stdio',
//   options: {
//     verbose: true,
//     quiet: false
//   }
// }
```

**When to use**:
- Merging configuration objects
- Overriding default options with user options

---

### 🛡️ Regex Safe (`utils/regex-safe.ts`)

**Purpose**: Execute regex with timeout (prevent ReDoS attacks)

**Usage**:
```typescript
import { regexTest, regexMatch } from 'libs/shared/utils/regex-safe';

// Safe regex test (with timeout)
const isMatch = regexTest(/^[a-z]+$/, input, 1000);  // timeout: 1000ms

// Safe regex match (with timeout)
const matches = regexMatch(/\d+/g, input, 1000);
if (matches) {
  console.log('Found numbers:', matches);
}
```

**When to use**:
- Testing regex on user input
- Preventing ReDoS (Regular Expression Denial of Service)

---

### 🚀 Smart Launcher (`utils/smart-launcher.ts`)

**Purpose**: Launch processes with automatic retries and error handling

**Usage**:
```typescript
import { SmartLauncher } from 'libs/shared/utils/smart-launcher';

const launcher = new SmartLauncher({
  retries: 3,
  retryDelay: 1000,  // ms
  timeout: 10000     // ms
});

const result = await launcher.launch('node', ['server.js'], {
  cwd: '/path/to/project',
  env: { PORT: '3000' }
});

if (result.success) {
  console.log('Process started:', result.pid);
} else {
  console.error('Failed to start:', result.error);
}
```

**When to use**:
- Launching STDIO transports
- Starting servers for testing
- Any process that might fail transiently

---

### 📊 Report Saver (`utils/reporting/report-saver.ts`)

**Purpose**: Save reports to disk with timestamp and organization

**Usage**:
```typescript
import { ReportSaver } from 'libs/shared/utils/reporting/report-saver';

const saver = new ReportSaver({
  outputDir: './reportes',
  format: 'json',        // 'json' | 'html' | 'md' | 'sarif'
  timestamp: true        // Add timestamp to filename
});

const paths = await saver.save(report);
// → {
//   json: './reportes/json/mcp-report-2024-02-03T14-30-00.json',
//   html: './reportes/html/mcp-report-2024-02-03T14-30-00.html',
//   md: './reportes/md/mcp-report-2024-02-03T14-30-00.md'
// }
```

**When to use**:
- Saving validation reports
- Organizing output files by type

---

### 📝 Logger (`logger/logger.ts`)

**Purpose**: Structured logging with levels (INFO, WARN, ERROR, DEBUG)

**Usage**:
```typescript
import { Logger } from 'libs/shared/logger/logger';

const logger = Logger.getInstance();

// Configure
logger.configure({
  level: 'INFO',           // 'DEBUG' | 'INFO' | 'WARN' | 'ERROR'
  enableConsole: true,
  enableFile: false,
  filePath: './logs/app.log'
});

// Log messages
logger.info('Starting validation', { target: 'http://localhost:3000' });
logger.warn('Slow response', { duration: 5000 });
logger.error('Connection failed', { error: err });
logger.debug('Raw response', { data: response });
```

**When to use**:
- Internal logging (not user-facing messages)
- Debugging production issues
- Structured logs for monitoring

---

## 🚫 What NOT to Put in Shared

### ❌ Anti-Pattern 1: Business Logic

**Problem**: Security rules in shared utilities

```typescript
// ❌ BAD: libs/shared/utils/security-checker.ts
export function checkSQLInjection(tool: McpTool): SecurityFinding[] {
  // This is business logic, not a utility!
}
```

**Solution**: Move to `libs/core/domain/security/rules/`

---

### ❌ Anti-Pattern 2: Framework Dependencies

**Problem**: Express/Commander imports

```typescript
// ❌ BAD: libs/shared/utils/server-helper.ts
import express from 'express';

export function createServer() {
  return express();
}
```

**Solution**: Move to `apps/` or `libs/core/infrastructure/`

---

### ❌ Anti-Pattern 3: Single-Use Functions

**Problem**: Only used in one place

```typescript
// ❌ BAD: libs/shared/utils/validate-helper.ts
export function formatValidationResult(result: any) {
  // Only used in apps/cli-verifier/src/commands/validate.ts
}
```

**Solution**: Keep it in the app that uses it

---

## 📊 Decision Tree: "Does This Belong in Shared?"

```
Is it used by 2+ apps/libs?
├─ NO → Keep it in the app/lib that uses it
└─ YES → Does it have business logic?
    ├─ YES → Move to libs/core/domain/
    └─ NO → Does it have framework dependencies?
        ├─ YES → Move to libs/core/infrastructure/
        └─ NO → ✅ OK for libs/shared/
```

---

## 🛠️ Adding New Utilities

### Task: Add a New Shared Utility

**Time**: ~15 minutes
**Difficulty**: Beginner

**Steps**:

#### 1. Create Utility File

```typescript
// libs/shared/utils/my-util.ts

/**
 * My Utility - Brief description
 *
 * Solves X problem by doing Y
 *
 * @module libs/shared/utils/my-util
 */

export class MyUtil {
  /**
   * Does something useful
   *
   * @param input - Input to process
   * @returns Processed output
   *
   * @example
   * const result = MyUtil.process('input');
   * console.log(result);  // → 'processed input'
   */
  static process(input: string): string {
    // Implementation
    return input.toLowerCase().trim();
  }
}
```

#### 2. Add Tests

```typescript
// libs/shared/utils/__tests__/my-util.spec.ts

import { describe, it, expect } from 'vitest';
import { MyUtil } from '../my-util';

describe('MyUtil', () => {
  it('should process input correctly', () => {
    const result = MyUtil.process('  INPUT  ');
    expect(result).toBe('input');
  });

  it('should handle empty input', () => {
    const result = MyUtil.process('');
    expect(result).toBe('');
  });
});
```

#### 3. Use in Your Code

```typescript
// apps/cli-verifier/src/commands/my-command.ts

import { MyUtil } from '../../../../libs/shared/utils/my-util';

const processed = MyUtil.process(userInput);
```

---

## 🔍 Common Patterns

### Pattern 1: Validator Classes

**Structure**: Static methods for validation

```typescript
export class MyValidator {
  static validate(input: string): boolean {
    // Validation logic
  }

  static getErrorMessage(input: string): string | null {
    // Error message generation
  }
}
```

**Examples**:
- `PathValidator` - Path validation
- `URLValidator` - URL validation

---

### Pattern 2: Helper Functions

**Structure**: Pure functions, no state

```typescript
export function myHelper(input: string, options?: Options): Result {
  // Pure transformation
  return transformed;
}
```

**Examples**:
- `deepMerge` - Object merging
- `formatError` - Error formatting
- `normalizeCommand` - Command normalization

---

### Pattern 3: Manager Classes

**Structure**: Singleton or stateful utilities

```typescript
export class MyManager {
  private static instance: MyManager;

  private constructor() {
    // Initialize
  }

  static getInstance(): MyManager {
    if (!this.instance) {
      this.instance = new MyManager();
    }
    return this.instance;
  }

  public doSomething(): void {
    // Implementation
  }
}
```

**Examples**:
- `APIKeyManager` - API key storage
- `Logger` - Structured logging

---

## 🧪 Testing Shared Utilities

### Test Location

**Pattern**: `libs/shared/utils/__tests__/[utility-name].spec.ts`

**Example**:
```
libs/shared/
├── utils/
│   ├── path-validator.ts
│   └── __tests__/
│       └── path-validator.spec.ts
```

### Test Coverage Requirement

**Minimum**: 80% for shared utilities (high reuse = high test value)

### Running Tests

```bash
# All shared tests
npm test -- libs/shared

# Specific utility
npm test -- libs/shared/utils/__tests__/path-validator.spec.ts

# Watch mode
npm test -- libs/shared --watch
```

---

## 📚 Related Documentation

- **[libs/README.md](../README.md)** - Library architecture
- **[CODE_MAP.md](../../CODE_MAP.md)** - "I want to..." quick reference
- **[DEVELOPMENT.md](../../DEVELOPMENT.md)** - Testing guide
- **[libs/core/README.md](../core/README.md)** - Core business logic

---

## 💡 Tips & Best Practices

### Tip 1: Keep Utilities Pure

**Good**:
```typescript
export function formatDate(date: Date): string {
  return date.toISOString();
}
```

**Bad**:
```typescript
let globalState = '';
export function formatDate(date: Date): string {
  globalState = date.toISOString();  // Side effect!
  return globalState;
}
```

---

### Tip 2: Use Type Safety

**Good**:
```typescript
export function process(input: string, options: Options): Result {
  // Type-safe implementation
}
```

**Bad**:
```typescript
export function process(input: any, options: any): any {
  // No type safety
}
```

---

### Tip 3: Document with Examples

**Good**:
```typescript
/**
 * Process input string
 *
 * @example
 * const result = process('input');  // → 'PROCESSED: input'
 */
export function process(input: string): string {
  return `PROCESSED: ${input}`;
}
```

---

### Tip 4: Handle Edge Cases

**Good**:
```typescript
export function divide(a: number, b: number): number {
  if (b === 0) {
    throw new Error('Division by zero');
  }
  return a / b;
}
```

**Bad**:
```typescript
export function divide(a: number, b: number): number {
  return a / b;  // Crashes on b=0
}
```

---

## 🆘 Common Issues

### Issue 1: "Cannot find module '../../../shared/utils'"

**Cause**: Incorrect import path
**Solution**: Use absolute imports from project root

```typescript
// ❌ BAD
import { t } from '../../../shared/utils/cli/i18n-helper';

// ✅ GOOD
import { t } from 'libs/shared/utils/cli/i18n-helper';
```

---

### Issue 2: Circular Dependencies

**Cause**: Shared utility imports from core
**Solution**: Keep shared completely independent

```typescript
// ❌ BAD: libs/shared/utils/my-util.ts
import { SecurityRule } from '../../core/domain/security';  // NO!

// ✅ GOOD: Pass dependency as parameter
export function process(input: string, validator: (s: string) => boolean) {
  return validator(input);
}
```

---

## 📊 Utility Usage Matrix

| Utility | Used By | Imports |
|---------|---------|---------|
| `i18n-helper` | CLI commands, reports | `libs/core/domain/reporting/i18n` |
| `output-helper` | CLI commands | `chalk`, `ora` |
| `error-formatter` | CLI commands | None (pure) |
| `path-validator` | CLI commands, report saver | `path`, `fs` |
| `url-validator` | CLI commands, transports | None (pure) |
| `api-key-manager` | CLI commands, LLM providers | `fs`, `path` |

