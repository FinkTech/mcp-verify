# Contributing to mcp-verify

Thank you for your interest in contributing to mcp-verify! This document provides guidelines and information for contributors.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for everyone.

## Ethical Guidelines

**MCP Verify is a defensive security tool.** All contributions must align with our ethical principles:

- **Only add features** for validating and auditing **authorized systems**
- **Do not add** exploit automation or weaponization features
- **Do not add** features designed for unauthorized scanning
- **Read** [RESPONSIBLE_USAGE.md](RESPONSIBLE_USAGE.md) before contributing

Contributors who submit features that violate these principles will have their PRs rejected.

## Getting Started for New Contributors

**Welcome!** Here's how to quickly orient yourself in the codebase:

### 1. Read the Navigation Guides

| Document | Purpose | Read Time |
|----------|---------|-----------|
| **[CODE_MAP.md](CODE_MAP.md)** | "I want to..." quick reference | 2 min |
| **[CLAUDE.md](./CLAUDE.md)** | Project overview & architecture | 5 min |
| **[ARCHITECTURE.md](./ARCHITECTURE.md)** | System design & patterns | 10 min |
| **[DEVELOPMENT.md](./DEVELOPMENT.md)** | Local setup & testing | 10 min |

### 2. Use CLAUDE.md Files for Module Navigation

The project includes `CLAUDE.md` files in every major directory:

```bash
# Start at root
cat CLAUDE.md  # Project overview

# Navigate to specific modules
cat apps/cli-verifier/CLAUDE.md  # CLI structure
cat libs/core/CLAUDE.md          # Business logic
cat libs/fuzzer/CLAUDE.md        # Fuzzer architecture
```

**Why?** These files reduce context exploration by ~90% and provide:
- File/function location reference
- Common patterns & conventions
- Module-specific architecture

### 3. Find "Where to Change" Using CODE_MAP.md

**Example workflows:**
```
"I want to add a new security rule"
→ CODE_MAP.md → libs/core/domain/security/rules/

"I want to add a new CLI command"
→ CODE_MAP.md → apps/cli-verifier/src/commands/

"I want to modify fuzzer payloads"
→ CODE_MAP.md → libs/fuzzer/generators/
```

### 4. Check Existing Patterns

Before writing code, review similar implementations:
```bash
# Adding a new security rule?
cat libs/core/domain/security/rules/sql-injection.rule.ts

# Adding a new fuzzer generator?
cat libs/fuzzer/generators/prompt-injection.ts

# Adding a new CLI command?
cat apps/cli-verifier/src/commands/validate.ts
```

---

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in [Issues](https://github.com/FinkTech/mcp-verify/issues)
2. If not, create a new issue with:
   - Clear title and description
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (Node.js version, OS, etc.)

### Suggesting Features

1. Open an issue with the `enhancement` label
2. Describe the feature and its use case
3. Discuss with maintainers before implementing

### Pull Requests

We use **Git Flow** for branch management. See [docs/BRANCHING.md](./docs/BRANCHING.md) for full details.

**Quick workflow:**

1. Fork the repository
2. Create a feature branch from `develop`: `git checkout -b feature/my-feature develop`
3. Make your changes following [AGENTS.md](./AGENTS.md) standards
4. Run tests: `npm test`
5. Run linting: `npm run lint`
6. Commit with DCO sign-off: `git commit -s -m "feat(scope): description"`
7. Push to your fork: `git push origin feature/my-feature`
8. Create a Pull Request targeting **`develop`** branch
9. CI checks run automatically (tests, linting, type checking, build)
10. Maintainer reviews your code
11. If approved → Squash merge to `develop`

**Important:**
- Always target **`develop`** branch for PRs (not `main`)
- Use branch naming: `feature/*`, `bugfix/*`, `docs/*`
- All commits must have DCO sign-off (`-s` flag)
- Follow Conventional Commits format

## Developer Certificate of Origin (DCO)

All contributions must be signed off according to the [DCO](DCO.txt).

**Sign your commits:**

```bash
git commit -s -m "feat: add new feature"
```

This adds a `Signed-off-by` line to your commit message, certifying that you wrote the code or have the right to submit it.

## Commit Message Convention

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

Signed-off-by: Your Name <your.email@example.com>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Adding or updating tests
- `refactor`: Code refactoring
- `chore`: Maintenance tasks

**Examples:**
```bash
git commit -s -m "feat(security): add SEC-013 prompt injection detection"
git commit -s -m "fix(cli): handle spaces in server paths"
git commit -s -m "docs: update README installation section"
```

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/mcp-verify.git
cd mcp-verify

# Install dependencies
npm install

# Build
npm run build

# Run tests
npm test

# Run linting
npm run lint
```

## Project Structure

```
mcp-verify/
├── apps/                           # User-facing applications
│   ├── cli-verifier/              # Interactive CLI + one-shot commands
│   │   ├── src/commands/          # 12 commands (validate, fuzz, stress, etc.)
│   │   ├── src/types/             # Workspace & profile types
│   │   ├── src/managers/          # Config, environment, health managers
│   │   ├── src/profiles/          # Security profile presets
│   │   └── src/handlers/          # Interactive shell handlers
│   │
│   ├── mcp-server/                # MCP Server with 7 tools for AI agents
│   ├── vscode-extension/          # VSCode extension (experimental)
│   └── web-dashboard/             # Web dashboard (experimental)
│
├── libs/                           # Shared business logic
│   ├── core/                      # Core validation engine
│   │   ├── domain/                # Business rules (60 security rules, reporting)
│   │   ├── infrastructure/        # External adapters (logging, sandbox)
│   │   └── use-cases/             # Workflows (validator, fuzzer, proxy)
│   │
│   ├── fuzzer/                    # Smart Fuzzer v1.0 Engine
│   │   ├── generators/            # 9 payload generators
│   │   ├── detectors/             # 10 anomaly detectors
│   │   ├── mutations/             # 12 mutation strategies
│   │   └── fingerprinting/        # Server language detection
│   │
│   ├── shared/                    # Common utilities (i18n, validators)
│   ├── protocol/                  # MCP protocol types
│   └── transport/                 # Transport layer (stdio, HTTP, SSE)
│
├── tools/                          # Development tools
│   ├── mocks/servers/             # Test MCP servers (simple, vulnerable, broken)
│   ├── scripts/                   # Build/deployment scripts
│   └── demo/                      # Demo servers for examples
│
├── tests/                          # Test suites
│   ├── unit/                      # Fast, isolated tests
│   ├── integration/               # Real I/O tests
│   └── fixtures/                  # Test data
│
├── guides/                         # Public documentation
│   ├── LLM_SETUP.md               # LLM provider configuration
│   ├── EXAMPLES.md                # Usage examples
│   └── CI_CD.md                   # CI/CD integration
│
└── docs/                           # Additional documentation
    ├── SECURITY.md                # Security model & threat analysis
    ├── ARCHITECTURE.md            # System design & patterns
    ├── DEVELOPMENT.md             # Local setup & testing
    └── CODE_MAP.md                # "I want to..." quick reference
```

**Key Documentation Files:**
- **CLAUDE.md files**: Navigation guides in every major directory
- **CODE_MAP.md**: Quick "where to find X" reference
- **ARCHITECTURE.md**: Hexagonal architecture deep dive
- **DEVELOPMENT.md**: Local setup, testing, debugging

## Testing

- **Unit tests**: `npm test`
- **Integration tests**: `npm run test:integration`
- **Coverage report**: `npm run test:coverage`

All PRs must maintain or improve test coverage.

## Security

If you discover a security vulnerability, please report it privately to hello.finksystems@gmail.com instead of creating a public issue.

## Common Contribution Workflows

### Adding a New Security Rule

1. **Find pattern**: Read existing rule (e.g., `libs/core/domain/security/rules/sql-injection.rule.ts`)
2. **Create file**: `libs/core/domain/security/rules/my-rule.ts`
3. **Implement**: Follow `ISecurityRule` interface
   ```typescript
   export class MyRule implements ISecurityRule {
     readonly code = 'SEC-XXX';
     evaluate(discovery: DiscoveryResult) { ... }
   }
   ```
4. **Register**: Add to `libs/core/domain/security/security-scanner.ts`
5. **Test**: Create `tests/core/domain/security/rules/my-rule.spec.ts`
6. **Document**: Add to `SECURITY_SCORING.md`

### Adding a New CLI Command

1. **Find pattern**: Read existing command (e.g., `apps/cli-verifier/src/commands/validate.ts`)
2. **Create file**: `apps/cli-verifier/src/commands/my-command.ts`
3. **Implement**: Export async function with signature `(args, options) => Promise<void>`
4. **Register**: Add to `apps/cli-verifier/src/bin/index.ts`
5. **Test**: Create `tests/cli-verifier/commands/my-command.spec.ts`
6. **Document**: Add to `COMMANDS.md`

### Adding a New Fuzzer Generator

1. **Find pattern**: Read `libs/fuzzer/generators/prompt-injection.ts`
2. **Create file**: `libs/fuzzer/generators/my-generator.ts`
3. **Implement**: Export `generatePayloads(toolSchema): Payload[]`
4. **Register**: Add to `libs/fuzzer/engine/fuzzer-engine.ts`
5. **Test**: Create `tests/fuzzer/generators/my-generator.spec.ts`
6. **Document**: Add to `libs/fuzzer/CLAUDE.md`

### Adding a New Report Format

1. **Find pattern**: Read `libs/core/domain/reporting/markdown-generator.ts`
2. **Create file**: `libs/core/domain/reporting/my-format-generator.ts`
3. **Implement**: Export `generate(results): string`
4. **Register**: Add to `libs/core/domain/reporting/enhanced-reporter.ts`
5. **Test**: Create `tests/core/domain/reporting/my-format-generator.spec.ts`
6. **Document**: Update README.md "Report Formats" section

---

## Code Quality Standards

All contributions are expected to meet our quality standards:

### Automated CI Checks (Required)

These run automatically on every PR via GitHub Actions:

- **Tests**: All unit, integration, and security tests must pass (`npm test`)
- **Linting**: Code must follow ESLint rules (`npm run lint`)
- **Type Checking**: No TypeScript errors (`npm run type-check`)
- **Build**: Project must build successfully (`npm run build`)

### Code Quality Guidelines

Follow these best practices (enforced through code review):

- **No `any` types**: Use `unknown`, `never`, or proper types
- **Internationalization**: Use `t()` for all user-facing strings (no hardcoded text)
- **Timeouts**: All async operations must have reasonable timeouts
- **License compliance**: Dependencies must be compatible with AGPL-3.0
- **Security rules**: Must have comprehensive tests with no false positives

### Periodic Quality Audits

We run internal code quality audits on a scheduled basis (typically weekly) to:

- Review architecture compliance
- Scan for license compatibility issues
- Validate security rule implementations

These audits help maintain long-term code health. Maintainers will follow up on any findings that require attention.

See [docs/BRANCHING.md](./docs/BRANCHING.md) for more details on our development workflow.

---

## Questions?

- **Branching strategy**: Read [docs/BRANCHING.md](./docs/BRANCHING.md)
- **Codebase navigation**: Read [CODE_MAP.md](CODE_MAP.md) and [CLAUDE.md](./CLAUDE.md)
- **Architecture questions**: See [ARCHITECTURE.md](./ARCHITECTURE.md)
- **Development help**: Check [DEVELOPMENT.md](./DEVELOPMENT.md)
- **Discussions**: Open a [Discussion](https://github.com/FinkTech/mcp-verify/discussions)
- **Email**: hello.finksystems@gmail.com

---

Thank you for contributing!
