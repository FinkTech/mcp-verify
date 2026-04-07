# 🎯 CLI Verifier Application

Command-line interface for **mcp-verify** - the comprehensive security and quality validator for Model Context Protocol (MCP) servers.

---

## 📋 Purpose

This is the main user-facing application of mcp-verify. It provides:

- **Interactive CLI** - User-friendly command interface
- **CI/CD Integration** - Exit codes, JSON output, baseline comparison
- **Multi-Transport Support** - STDIO, HTTP, SSE
- **Security Scanning** - 12 OWASP rules, vulnerability detection
- **Quality Analysis** - LLM semantic analysis (Anthropic, Ollama, OpenAI)
- **Report Generation** - JSON, HTML, Markdown, SARIF formats
- **Developer Tools** - Playground, dashboard, stress testing

---

## 📁 Structure

```
apps/cli-verifier/
├── src/
│   ├── bin/
│   │   └── index.ts              # Entry point, command registration
│   │
│   ├── commands/                 # Command implementations
│   │   ├── validate.ts           # Main validation command (most important)
│   │   ├── doctor.ts             # Diagnostic tool
│   │   ├── stress.ts             # Load testing
│   │   ├── mock.ts               # Mock MCP server
│   │   ├── dashboard.ts          # Real-time dashboard UI
│   │   ├── play.ts               # Interactive playground
│   │   ├── proxy.ts              # MCP proxy with logging
│   │   ├── init.ts               # Config file initialization
│   │   ├── examples.ts           # Show usage examples
│   │   └── interactive.ts        # Interactive mode (default)
│   │
│   └── utils/                    # CLI-specific utilities
│       ├── transport-factory.ts  # Transport creation
│       ├── cleanup-handlers.ts   # Process cleanup
│       ├── logging-helper.ts     # Logging configuration
│       ├── output-helper.ts      # Output formatting
│       ├── env-parser.ts         # Environment variable parsing
│       └── url-helpers.ts        # URL utilities
│
├── package.json                  # CLI dependencies
└── tsconfig.json                 # TypeScript config
```

---

## 🏗️ Architecture

### Entry Point Flow

```
bin/index.ts
    ↓
[Command Registered]
    ↓
commands/*.ts (action handlers)
    ↓
libs/core/use-cases/* (business logic)
    ↓
libs/core/domain/* (pure logic)
```

### Key Concepts

1. **Command Pattern**: Each command is a separate module with an action handler
2. **Commander.js**: CLI framework for argument parsing
3. **Clean Separation**: CLI concerns (formatting, I/O) separate from business logic (validation, security)
4. **Utility Factories**: Reusable helpers for transport, logging, output

---

## 🛠️ Common Tasks

### Task 1: Add a New CLI Command

**Time**: ~30 minutes
**Difficulty**: Beginner

**Steps**:

#### 1. Create Command File

Create `src/commands/my-command.ts`:

```typescript
/**
 * My Command
 *
 * Brief description of what this command does
 */

import ora from "ora";
import chalk from "chalk";
import { t } from "../../../../libs/shared/utils/cli/i18n-helper";
import { createLogger } from "../../../../libs/shared/utils/cli/output-helper";

export async function runMyCommandAction(
  target: string,
  options: Record<string, unknown>,
) {
  // Determine if quiet mode (suppress spinners)
  const isQuiet = Boolean(options.quiet || options.jsonStdout);
  const log = createLogger(isQuiet);
  const spinner = isQuiet ? null : ora("Starting...").start();

  try {
    // STEP 1: Validate inputs
    if (!target) {
      throw new Error("Target is required");
    }

    // STEP 2: Call use-case from libs/core
    if (spinner) spinner.text = "Processing...";

    // Example: Import from core
    // import { MyUseCase } from '../../../../libs/core/use-cases/my-use-case';
    // const result = await new MyUseCase().execute(target);

    // STEP 3: Output results
    if (spinner) spinner.succeed("Completed!");

    log.log(chalk.green("✓ Success!"));
    log.log(`Result: ${chalk.cyan(target)}`);
  } catch (error) {
    if (spinner) spinner.fail("Failed");

    log.log("");
    log.error(chalk.red.bold("❌ Error\n"));
    log.error(
      chalk.red("Error: ") +
        (error instanceof Error ? error.message : String(error)),
    );

    // STEP 4: Exit with error code for CI/CD
    process.exit(1);
  }
}
```

#### 2. Register Command in `bin/index.ts`

```typescript
// Import your command handler
import { runMyCommandAction } from "../commands/my-command";

// Register command
program
  .command("my-command <target>")
  .description("Description of my command")
  .option("-o, --output <path>", "Output directory", "./output")
  .option("--verbose", "Enable verbose logging")
  .action(runMyCommandAction);
```

#### 3. Add i18n Keys (if needed)

Add translations to `libs/core/domain/reporting/i18n.ts`:

```typescript
// English
cmd_my_command_desc: 'Description of my command',

// Spanish
cmd_my_command_desc: 'Descripción de mi comando',
```

#### 4. Test Your Command

```bash
# Build
npm run build

# Test
mcp-verify my-command "test-target" --verbose
```

#### 5. Add Tests

Create `tests/cli-verifier/commands/my-command.spec.ts`:

```typescript
import { describe, it, expect } from "vitest";
import { runMyCommandAction } from "../../../apps/cli-verifier/src/commands/my-command";

describe("my-command", () => {
  it("should process target successfully", async () => {
    // Test implementation
  });
});
```

---

### Task 2: Add a New CLI Option to Existing Command

**Time**: ~10 minutes
**Difficulty**: Beginner

**Example**: Add `--timeout` option to `validate` command

#### 1. Update Command Registration in `bin/index.ts`

```typescript
program
  .command("validate <target>")
  .description(t("cmd_validate_desc"))
  // ... existing options ...
  .option("--timeout <ms>", "Request timeout in milliseconds", "10000") // ← ADD THIS
  .action(runValidationAction);
```

#### 2. Use Option in Command Handler `commands/validate.ts`

```typescript
export async function runValidationAction(
  target: string,
  options: Record<string, unknown>,
) {
  // Extract option
  const timeout = Number(options.timeout || 10000);

  // Use it
  transport = createTransport(target, {
    transportType,
    timeout, // ← PASS TO TRANSPORT
    // ...
  });
}
```

#### 3. Update Documentation

Update `guides/EXAMPLES.md`:

````markdown
## Custom Timeout

```bash
mcp-verify validate "node server.js" --timeout 30000
```
````

````

---

### Task 3: Add Custom Output Format

**Time**: ~2 hours
**Difficulty**: Intermediate

**Example**: Add CSV report format

#### 1. Create Generator in `libs/core/domain/reporting/`

```typescript
// libs/core/domain/reporting/csv-generator.ts
import { ValidationReport } from '../types';

export class CsvGenerator {
  static generate(report: ValidationReport): string {
    const rows: string[] = [];

    // Header
    rows.push('Severity,Rule,Tool,Message');

    // Data rows
    report.security.findings.forEach(finding => {
      const row = [
        finding.severity,
        finding.ruleCode,
        finding.toolName || 'N/A',
        `"${finding.message.replace(/"/g, '""')}"`
      ].join(',');
      rows.push(row);
    });

    return rows.join('\n');
  }
}
````

#### 2. Update CLI Command `commands/validate.ts`

```typescript
import { CsvGenerator } from "../../../../libs/core/domain/reporting/csv-generator";

// In runValidationAction, after report generation:
const reportFormat = String(options.format || "json");

if (reportFormat === "csv") {
  const csvDir = path.join(outputDir, "csv");
  fs.mkdirSync(csvDir, { recursive: true });

  const csvContent = CsvGenerator.generate(report);
  const csvPath = path.join(csvDir, `${filenameBase}.csv`);
  fs.writeFileSync(csvPath, csvContent);

  log.log(`CSV: ${chalk.magenta(csvPath)}`);
}
```

#### 3. Update Help Text in `bin/index.ts`

```typescript
.option('--format <type>', 'Report format (json|html|sarif|csv)', 'json') // ← ADD csv
```

#### 4. Test

```bash
mcp-verify validate "node server.js" --format csv
```

---

### Task 4: Add Environment Variable Support

**Time**: ~15 minutes
**Difficulty**: Beginner

**Example**: Add `MCP_VERIFY_TIMEOUT` environment variable

#### 1. Check Environment Variable in Command

```typescript
// commands/validate.ts
export async function runValidationAction(
  target: string,
  options: Record<string, unknown>,
) {
  // Priority: CLI flag > ENV variable > default
  const timeout = Number(
    options.timeout || process.env.MCP_VERIFY_TIMEOUT || 10000,
  );

  // Use timeout...
}
```

#### 2. Document in Help Text

Update `bin/index.ts`:

```typescript
.option('--timeout <ms>', 'Request timeout (env: MCP_VERIFY_TIMEOUT)', '10000')
```

#### 3. Add to Documentation

Update `guides/EXAMPLES.md`:

````markdown
## Environment Variables

```bash
# Set default timeout
export MCP_VERIFY_TIMEOUT=30000
mcp-verify validate "node server.js"
```
````

````

---

## 🔍 Key Components

### 1. Entry Point (`bin/index.ts`)

**Responsibilities**:
- Register all commands with Commander.js
- Set up global flags (`--quiet`, `--json-stdout`, `--no-color`)
- Initialize i18n (language support)
- Check for updates (update-notifier)
- Default to interactive mode if no command specified

**Key Pattern**:
```typescript
program
  .command('command-name <required> [optional]')
  .description('Command description')
  .option('-f, --flag <value>', 'Flag description', 'default')
  .action(handlerFunction);
````

---

### 2. Validate Command (`commands/validate.ts`)

**Most Important Command** - 450 lines

**Responsibilities**:

- Main validation workflow
- Transport detection and creation
- Security scanning orchestration
- Report generation (JSON, HTML, MD, SARIF)
- Baseline comparison
- Exit code management for CI/CD

**Key Features**:

- **Quiet Mode**: Suppress spinners for CI/CD (`--quiet`, `--json-stdout`)
- **Transport Auto-Detection**: Detects STDIO vs HTTP from target string
- **Security Warnings**: Alerts for private IPs, missing sandbox
- **Multi-Format Reports**: Generates 4 formats simultaneously
- **Baseline Tracking**: Compare current vs. baseline scores
- **Exit Codes**:
  - `0` = Success
  - `1` = Validation failure
  - `2` = Critical security issue or baseline degradation

**Usage**:

```bash
mcp-verify validate "node server.js" --security --llm ollama:llama3.2
```

---

### 3. Doctor Command (`commands/doctor.ts`)

**Responsibilities**:

- Diagnose connection issues
- Test transport connectivity
- Check environment (Node.js, API keys, Ollama)
- Provide troubleshooting tips

**Key Features**:

- Environment checks (Node version, Deno, API keys)
- Connection testing (handshake, discovery)
- JSON-RPC diagnostics

**Usage**:

```bash
mcp-verify doctor "node server.js"
```

---

### 4. Interactive Mode (`commands/interactive.ts`)

**Responsibilities**:

- Default mode when no command specified
- Presents menu of common operations
- Guides users through validation workflow

**Key Features**:

- Command selection menu (Inquirer.js)
- Input prompts with validation
- Executes selected command

**Triggered When**:

```bash
mcp-verify  # No command = interactive mode
```

---

### 5. Transport Factory (`utils/transport-factory.ts`)

**Responsibilities**:

- Auto-detect transport type (STDIO vs HTTP vs SSE)
- Create appropriate transport instance
- Configure transport options (env vars, sandbox, timeout)

**Detection Logic**:

```typescript
export function detectTransportType(target: string): TransportType {
  if (target.startsWith("http://") || target.startsWith("https://")) {
    return "http";
  }
  if (target.includes("sse") || target.includes(":events")) {
    return "sse";
  }
  return "stdio"; // Default
}
```

**Usage**:

```typescript
const transport = createTransport(target, {
  transportType: "stdio",
  envVars: { API_KEY: "xxx" },
  sandbox: new DenoSandbox(),
  timeout: 10000,
});
```

---

### 6. Output Helper (`utils/output-helper.ts`)

**Responsibilities**:

- Manage quiet mode
- Format console output
- Handle stdout piping for CI/CD

**Key Pattern**:

```typescript
const log = createLogger(isQuiet);
log.log("Normal output"); // Suppressed if quiet
log.error("Error message"); // Always shown
```

---

## 🎨 CLI Design Patterns

### 1. Quiet Mode Pattern

**Problem**: CI/CD systems don't need spinners, only final output
**Solution**: `--quiet` or `--json-stdout` suppresses visual feedback

```typescript
const isQuiet = Boolean(options.quiet || options.jsonStdout);
const spinner = isQuiet ? null : ora("Loading...").start();

// Use spinner safely
if (spinner) spinner.text = "Processing...";
if (spinner) spinner.succeed("Done!");
```

---

### 2. Exit Code Pattern

**Problem**: CI/CD needs to know if validation passed
**Solution**: Use standard exit codes

```typescript
// Success
process.exit(0);

// Validation failure (non-critical)
process.exit(1);

// Critical security issue or baseline degradation
process.exit(2);
```

**Usage in CI/CD**:

```yaml
- run: mcp-verify validate "node server.js"
  continue-on-error: true # Don't fail build on exit code 1
```

---

### 3. Stdout Piping Pattern

**Problem**: Users want to pipe JSON to other tools
**Solution**: Output JSON to stdout, logs to stderr

```typescript
if (outputToStdout) {
  // JSON to stdout (for piping)
  printOutput(report);
  return;
}

// Visual report to stderr (won't interfere with piping)
process.stderr.write(chalk.bold("Report:\n"));
```

**Usage**:

```bash
mcp-verify validate "node server.js" --json-stdout | jq '.security.score'
```

---

### 4. i18n Pattern

**Problem**: Support multiple languages
**Solution**: Use `t()` function for all user-facing strings

```typescript
import { t } from "../../../../libs/shared/utils/cli/i18n-helper";

// Never hardcode strings
log.log("Validation complete"); // ❌ BAD

// Always use t()
log.log(t("validation_complete")); // ✅ GOOD

// With parameters
log.log(t("server_found", { name: "MyServer" }));
```

---

## 🚫 Anti-Patterns (What NOT to Do)

### ❌ Anti-Pattern 1: Business Logic in CLI Commands

**Problem**: Mixing validation logic with CLI formatting

```typescript
// ❌ BAD: commands/validate.ts
export async function runValidationAction(target: string, options: any) {
  // DON'T implement security checks here
  if (tool.inputSchema && tool.inputSchema.includes("exec")) {
    findings.push({ severity: "high", message: "Command injection risk" });
  }
}
```

**Solution**: Delegate to use-cases

```typescript
// ✅ GOOD: commands/validate.ts
export async function runValidationAction(target: string, options: any) {
  const validator = new MCPValidator(transport);
  const report = await validator.generateReport(); // Business logic in use-case

  // CLI only handles formatting
  log.log(`Score: ${report.security.score}`);
}
```

---

### ❌ Anti-Pattern 2: Hardcoded Strings

**Problem**: No internationalization support

```typescript
// ❌ BAD
log.log("Validation complete");
spinner.text = "Processing...";
throw new Error("Invalid target");
```

**Solution**: Use i18n

```typescript
// ✅ GOOD
log.log(t("validation_complete"));
spinner.text = t("processing");
throw new Error(t("invalid_target"));
```

---

### ❌ Anti-Pattern 3: Direct process.exit() Everywhere

**Problem**: Prevents proper cleanup

```typescript
// ❌ BAD
try {
  await validator.run();
} catch (error) {
  console.error(error);
  process.exit(1); // Transport not cleaned up!
}
```

**Solution**: Cleanup in finally block

```typescript
// ✅ GOOD
try {
  await validator.run();
} catch (error) {
  log.error(error);
  process.exit(1);
} finally {
  if (validator) await validator.cleanup(); // Always cleanup
}
```

---

### ❌ Anti-Pattern 4: Ignoring Quiet Mode

**Problem**: Spinners appear in CI/CD logs

```typescript
// ❌ BAD
const spinner = ora("Loading...").start();
spinner.text = "Processing...";
```

**Solution**: Respect quiet mode

```typescript
// ✅ GOOD
const isQuiet = Boolean(options.quiet || options.jsonStdout);
const spinner = isQuiet ? null : ora("Loading...").start();

if (spinner) spinner.text = "Processing...";
```

---

## 📊 Command Cheat Sheet

| Command       | Purpose             | Typical Use Case            |
| ------------- | ------------------- | --------------------------- |
| **validate**  | Full validation     | Production readiness check  |
| **doctor**    | Diagnostics         | "Why isn't this working?"   |
| **stress**    | Load testing        | Performance testing         |
| **dashboard** | Real-time UI        | Development debugging       |
| **play**      | Interactive testing | Manual exploration          |
| **proxy**     | Traffic inspection  | Protocol debugging          |
| **mock**      | Mock server         | Testing client integrations |
| **init**      | Create config       | First-time setup            |
| **examples**  | Show examples       | Learning commands           |

---

## 🧪 Testing CLI Commands

### Unit Tests

**Location**: `tests/cli-verifier/commands/`

**Pattern**:

```typescript
import { describe, it, expect, vi } from "vitest";
import { runValidationAction } from "../../../apps/cli-verifier/src/commands/validate";

describe("validate command", () => {
  it("should validate STDIO transport", async () => {
    const target = "node server.js";
    const options = { transport: "stdio" };

    await runValidationAction(target, options);

    // Assertions
  });
});
```

### Integration Tests

**Run CLI directly**:

```bash
npm run build
mcp-verify validate "node tools/mocks/servers/simple-server.js"
```

### E2E Tests

**Test full workflow**:

```bash
# Test with real server
npm run build
mcp-verify validate "http://localhost:3000" --html --format sarif
```

---

## 🔗 Related Documentation

- **[CODE_MAP.md](../../CODE_MAP.md)** - "I want to..." quick reference
- **[DEVELOPMENT.md](../../DEVELOPMENT.md)** - Local setup, testing
- **[guides/EXAMPLES.md](../../guides/EXAMPLES.md)** - Copy-paste commands
- **[libs/core/README.md](../../libs/core/README.md)** - Core business logic
- **[libs/README.md](../../libs/README.md)** - Library architecture

---

## 💡 Tips & Tricks

### Tip 1: Debug Mode

```bash
# Enable verbose logging
mcp-verify validate "node server.js" --verbose

# Output raw JSON for debugging
mcp-verify validate "node server.js" --json-stdout | jq .
```

### Tip 2: Quick Iteration

```bash
# Watch mode for development
npm run dev

# Test specific command
node apps/cli-verifier/src/bin/index.ts validate "node server.js"
```

### Tip 3: CI/CD Integration

```bash
# Fail build on critical issues (exit code 2)
mcp-verify validate "node server.js" --fail-on-degradation

# Generate SARIF for GitHub
mcp-verify validate "node server.js" --format sarif
```

### Tip 4: Multi-LLM Testing

```bash
# Compare LLM providers
mcp-verify validate "node server.js" --llm anthropic:claude-haiku-4-5-20251001
mcp-verify validate "node server.js" --llm ollama:llama3.2
mcp-verify validate "node server.js" --llm openai:gpt-4o-mini
```

---

## 📈 Performance Considerations

### Command Startup Time

**Goal**: < 500ms for `--help`

**How**:

- Lazy-load heavy dependencies (only when command runs)
- Import only what's needed
- Avoid top-level async operations

### Memory Usage

**Goal**: < 100MB for typical validation

**How**:

- Stream large responses (don't buffer entire JSON)
- Clean up transports after use
- Avoid global state

---

## 🆘 Common Issues

### Issue 1: "Command not found"

**Cause**: Not linked globally
**Solution**:

```bash
npm link
mcp-verify --version
```

### Issue 2: "TypeError: Cannot read property..."

**Cause**: Missing dependency or outdated Node.js
**Solution**:

```bash
node --version  # Requires 18.x or higher
npm install
npm run build
```

### Issue 3: Exit code always 0 in CI/CD

**Cause**: Not checking `process.exitCode`
**Solution**: Use explicit `process.exit()` in error cases

---

## 🎓 Learning Path

### Day 1: Read Existing Commands

1. Read `bin/index.ts` - Understand command registration
2. Read `commands/validate.ts` - Main workflow
3. Read `commands/examples.ts` - Simple command example

### Day 2: Create Simple Command

1. Copy `commands/examples.ts`
2. Rename and modify
3. Register in `bin/index.ts`
4. Test with `npm run dev`

### Week 1: Create Complex Command

1. Study `commands/validate.ts` structure
2. Integrate with `libs/core/use-cases`
3. Add i18n support
4. Write unit tests
