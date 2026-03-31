# 🗺️ Code Map - Navigate the Codebase

**Last Updated**: 2026-03-30
**Target Audience**: Contributors (Persona 4)
**Purpose**: Find the right file to edit in 30 seconds

---

## 🎯 "I want to..." Quick Reference

| I want to... | Edit this file | Location |
|--------------|----------------|----------|
| **Add a new security rule** | `libs/core/domain/security/rules/<rule>.ts` | [Security Rules](#security-rules) |
| **Add a new CLI command** | `apps/cli-verifier/src/commands/<cmd>.ts` | [CLI Commands](#cli-commands) |
| **Add a new LLM provider** | `libs/core/domain/quality/providers/<provider>.ts` | [LLM Providers](#llm-providers) |
| **Change validation logic** | `libs/core/use-cases/validator/validator.ts` | [Validator](#validator) |
| **Add i18n translation** | `libs/core/domain/reporting/i18n.ts` | [I18n](#internationalization) |
| **Modify report format** | `libs/core/domain/reporting/<format>-generator.ts` | [Reporters](#report-generators) |
| **Add transport type** | `libs/core/domain/transport.ts` | [Transports](#transports) |
| **Change exit codes** | `apps/cli-verifier/src/commands/validate.ts` | [Exit Codes](#exit-codes) |
| **Add fuzzing rule** | `libs/fuzzer/generators/` | [Fuzzer](#fuzzer-new-modular-architecture) |
| **Modify scoring algorithm** | `libs/core/domain/security/security-scanner.ts` | [Security Scanner](#security-scanner) |

---

## 📁 Directory Structure Overview

```
mcp-verify/
│
├── apps/                           # Applications (CLI, Dashboard, etc.)
│   └── cli-verifier/               # Main CLI application
│       ├── src/
│       │   ├── bin/index.ts        # 🎯 CLI entry point
│       │   ├── commands/           # 🎯 CLI commands (validate, doctor, etc.)
│       │   └── utils/              # CLI-specific utilities
│       └── package.json
│
├── libs/                           # Shared libraries
│   ├── core/                       # 🎯 Core business logic
│   │   ├── domain/                 # Business models & rules
│   │   │   ├── mcp-server/         # MCP protocol entities
│   │   │   ├── security/           # 🎯 Security rules & scoring
│   │   │   ├── quality/            # 🎯 Quality analysis & LLM
│   │   │   ├── reporting/          # 🎯 Report generation & i18n
│   │   │   ├── transport/          # 🎯 Transport implementations
│   │   │   └── baseline/           # Baseline comparison
│   │   │
│   │   ├── infrastructure/         # External services
│   │   │   ├── logging/            # Logging system
│   │   │   ├── diagnostics/        # Doctor command checks
│   │   │   └── sandbox/            # Deno sandbox
│   │   │
│   │   └── use-cases/              # Application logic
│   │       ├── validator/          # 🎯 Main validation orchestrator
│   │       ├── fuzzer/             # 🎯 Fuzzing/chaos testing
│   │       └── proxy/              # Runtime proxy & guardrails
│   │
│   ├── shared/                     # Shared utilities
│   │   └── utils/                  # 🎯 Common helpers (i18n, path, etc.)
│   │
│   ├── fuzzer/                     # 🎯 Advanced modular fuzzer (v1.0)
│   │   ├── engine/                 # FuzzerEngine orchestrator
│   │   ├── generators/             # Attack payload generators
│   │   ├── detectors/              # Vulnerability detectors
│   │   ├── fingerprint/            # Server fingerprinting
│   │   └── utils/                  # Report mappers
│   │
│   ├── transport/                  # 🎯 Transport layer (stdio, HTTP, SSE)
│   │
│   └── protocol/                   # MCP protocol types & schemas
│
├── tools/                          # Development tools
│   └── mocks/                      # Mock servers for testing
│       └── servers/                # Example MCP servers
│
├── tests/                          # Test files (mirrors src)
│
├── guides/                         # Public documentation
│   ├── LLM_SETUP.md               # LLM configuration guide
│   ├── EXAMPLES.md                # Usage examples
│   └── CI_CD.md                   # CI/CD integration
│
└── dist/                           # Compiled output (generated)
```

---

## 🔍 Key Components Deep Dive

### CLI Entry Point

**File**: `apps/cli-verifier/src/bin/index.ts`

**Purpose**: CLI application entry point, command registration

**Key Code**:
```typescript
const program = new Command();

program
  .command('validate <target>')
  .option('--security', 'Enable security scanning')
  .option('--llm <provider:model>', 'LLM provider')
  .action(runValidationAction);

program.parse(process.argv);
```

**Edit when**:
- Adding new global CLI flags
- Adding new commands
- Changing default behavior

---

### CLI Commands

**Directory**: `apps/cli-verifier/src/commands/`

**Files**:
- `validate.ts` - Main validation command
- `doctor.ts` - Connection diagnostics
- `stress.ts` - Load testing
- `mock.ts` - Mock server
- `play.ts` - Interactive playground
- `proxy.ts` - Runtime proxy
- `dashboard.ts` - Web dashboard
- `examples.ts` - Show examples
- `interactive.ts` - Interactive shell

**Structure (validate.ts example)**:
```typescript
export async function runValidationAction(
  target: string,
  options: any
): Promise<void> {
  // 1. Parse options
  const enableSecurity = options.security;
  const llmProvider = options.llm;

  // 2. Create transport
  const transport = await createTransport(target, options.transport);

  // 3. Create validator
  const validator = new MCPValidator(transport, undefined, {
    enableSemanticCheck: options.llm !== undefined,
    llmProvider: options.llm
  });

  // 4. Run validation
  const report = await validator.validate();

  // 5. Generate reports
  await generateReports(report, options);

  // 6. Exit with appropriate code
  process.exit(getExitCode(report));
}
```

**Edit when**:
- Adding new command options
- Changing command behavior
- Modifying output format

---

### Validator

**File**: `libs/core/use-cases/validator/validator.ts`

**Purpose**: Main validation orchestrator, coordinates all checks

**Key Methods**:
```typescript
export class MCPValidator {
  async validate(): Promise<ValidationReport> {
    // 1. Initialize (handshake)
    await this.transport.initialize();

    // 2. Discovery (list tools/resources)
    const discovery = await this.discover();

    // 3. Schema validation
    const schemaReport = await this.validateSchemas(discovery);

    // 4. Security analysis
    const securityReport = await this.securityScanner.scan(discovery);

    // 5. Quality analysis (including LLM)
    const qualityReport = await this.semanticAnalyzer.analyze(discovery);

    // 6. Combine reports
    return {
      discovery,
      schema: schemaReport,
      security: securityReport,
      quality: qualityReport
    };
  }
}
```

**Edit when**:
- Adding new validation steps
- Changing validation flow
- Modifying report structure

---

### Security Rules

**Directory**: `libs/core/domain/security/rules/`

**Files**:
- `sql-injection.ts` - SEC-003: SQL injection
- `command-injection.ts` - SEC-002: Command execution
- `path-traversal.ts` - SEC-007: File path manipulation
- `ssrf.ts` - SEC-004: Server-side request forgery
- `data-leakage.ts` - SEC-008: Sensitive data exposure
- `xxe.ts` - SEC-005: XML external entities
- `deserialization.ts` - SEC-006: Insecure deserialization
- `redos.ts` - SEC-011: ReDoS
- `auth-bypass.ts` - SEC-001: Authentication bypass
- `sensitive-exposure.ts` - SEC-009: PII/credential exposure
- `rate-limiting.ts` - SEC-010: Missing rate limits
- `weak-crypto.ts` - SEC-012: Weak cryptography

**Structure**:
```typescript
export class SqlInjectionRule implements ISecurityRule {
  readonly code = 'SEC-003';
  readonly name = 'SQL Injection';
  severity: 'critical' = 'critical';

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    // Check patterns in name/description
    const dangerousPatterns = /\b(sql|query|database|drop|delete|insert|update)\b/i;

    for (const tool of discovery.tools) {
      if (dangerousPatterns.test(tool.name) || dangerousPatterns.test(tool.description)) {
        findings.push({
          ruleCode: this.code,
          severity: this.severity,
          message: `SQL injection pattern detected in tool "${tool.name}"`,
          component: `tool:${tool.name}`,
          suggestion: 'Use parameterized queries or ORM instead of dynamic SQL'
        });
      }
    }

    return findings;
  }
}
```

**Edit when**:
- Adding new security rule
- Modifying existing rule patterns
- Changing severity levels

---

### Security Scanner

**File**: `libs/core/domain/security/security-scanner.ts`

**Purpose**: Orchestrates security rules, calculates security score

**Key Code**:
```typescript
export class SecurityScanner {
  private rules: ISecurityRule[] = [
    new SqlInjectionRule(),
    new CommandInjectionRule(),
    // ... all 60 rules
  ];

  async scan(discovery: DiscoveryResult): Promise<SecurityReport> {
    const findings: SecurityFinding[] = [];

    // Run all rules
    for (const rule of this.rules) {
      const ruleFindings = rule.evaluate(discovery);
      findings.push(...ruleFindings);
    }

    // Calculate score
    const score = this.calculateScore(findings);

    return { score, findings };
  }

  private calculateScore(findings: SecurityFinding[]): number {
    let score = 100;

    for (const finding of findings) {
      switch (finding.severity) {
        case 'critical': score -= 30; break;
        case 'high': score -= 15; break;
        case 'medium': score -= 10; break;
        case 'low': score -= 5; break;
        case 'info': score -= 2; break;
      }
    }

    return Math.max(0, score);
  }
}
```

**Edit when**:
- Changing scoring algorithm
- Modifying severity penalties
- Adding new rule types

---

### LLM Providers

**Directory**: `libs/core/domain/quality/providers/`

**Files**:
- `llm-provider.interface.ts` - Provider interface
- `anthropic-provider.ts` - Anthropic Claude implementation
- `ollama-provider.ts` - Ollama (local) implementation
- `openai-provider.ts` - OpenAI GPT implementation

**Structure**:
```typescript
export class AnthropicProvider implements ILLMProvider {
  private client: Anthropic | null = null;

  async isAvailable(): Promise<boolean> {
    return !!process.env.ANTHROPIC_API_KEY;
  }

  async complete(messages: LLMMessage[], options?: {...}): Promise<LLMResponse> {
    const response = await this.client.messages.create({
      model: this.config.model,
      max_tokens: options.maxTokens,
      messages: messages
    });

    return {
      text: response.content[0].text,
      usage: { inputTokens: ..., outputTokens: ... }
    };
  }
}
```

**Edit when**:
- Adding new LLM provider
- Changing API integration
- Modifying error handling

---

### LLM Semantic Analyzer

**File**: `libs/core/domain/quality/llm-semantic-analyzer.ts`

**Purpose**: Orchestrates LLM analysis, parses findings

**Key Methods**:
```typescript
export class LLMSemanticAnalyzer {
  async analyze(discovery: DiscoveryResult, options: LLMAnalysisOptions): Promise<LLMSemanticResult> {
    // 1. Initialize provider
    await this.initializeProvider(options.llmProvider);

    // 2. Build prompt
    const prompt = this.buildAnalysisPrompt(discovery);

    // 3. Call LLM
    const response = await this.provider.complete([{ role: 'user', content: prompt }]);

    // 4. Parse findings
    const findings = this.parseFindings(response.text);

    return { enabled: true, findings };
  }
}
```

**Edit when**:
- Changing LLM prompt
- Modifying finding parsing logic
- Adding new analysis types

---

### Report Generators

**Directory**: `libs/core/domain/reporting/`

**Files**:
- `html-generator.ts` - HTML report (human-friendly)
- `markdown-generator.ts` - Markdown summary
- `sarif-generator.ts` - SARIF (GitHub Security)
- `badge-generator.ts` - SVG badges

**Structure**:
```typescript
export class HtmlReportGenerator {
  async generate(report: ValidationReport, outputPath: string): Promise<string> {
    // 1. Build HTML template
    const html = `
      <!DOCTYPE html>
      <html>
        <head>
          <title>MCP Validation Report</title>
          ${this.generateCSS()}
        </head>
        <body>
          ${this.generateHeader(report)}
          ${this.generateSecuritySection(report.security)}
          ${this.generateQualitySection(report.quality)}
        </body>
      </html>
    `;

    // 2. Write to file
    await fs.writeFile(outputPath, html);

    return outputPath;
  }
}
```

**Edit when**:
- Changing report format
- Adding new sections
- Modifying styles

---

### Transports

**File**: `libs/core/domain/transport.ts`

**Transport types**:
- `StdioTransport` - STDIO (Node.js child process)
- `SSETransport` - Server-Sent Events
- `HttpTransport` - HTTP requests (includes User-Agent header)

**Future location**: `libs/transport/` (refactoring planned)

**Structure**:
```typescript
export class StdioTransport implements ITransport {
  private process: ChildProcess | null = null;

  async initialize(): Promise<void> {
    this.process = spawn(this.command, this.args);
    await this.sendRequest('initialize', {...});
  }

  async sendRequest(method: string, params: any): Promise<any> {
    // JSON-RPC over stdio
  }
}

export class HttpTransport implements ITransport {
  private userAgent: string;

  constructor(baseUrl: string) {
    this.userAgent = getUserAgent(); // mcp-verify/1.0.0
  }
}
```

**Edit when**:
- Adding new transport type
- Changing protocol implementation
- Fixing connection issues

---

### Internationalization

**File**: `libs/core/domain/reporting/i18n.ts`

**Purpose**: Translation strings for all languages

**Structure**:
```typescript
export const translations = {
  en: {
    cmd_validate_desc: 'Run validation scan',
    security_score: 'Security Score',
    llm_analysis_using: '🧠 LLM analysis: {provider}',
    // ... 1000+ keys
  },
  es: {
    cmd_validate_desc: 'Ejecutar escaneo de validación',
    security_score: 'Puntaje de Seguridad',
    llm_analysis_using: '🧠 Análisis LLM: {provider}',
    // ... 1000+ keys
  }
};
```

**Edit when**:
- Adding new user-facing strings
- Adding new language
- Fixing translation errors

**Helper Function**:
```typescript
import { t } from '../shared/utils/cli/i18n-helper';

// Usage
const message = t('security_score');  // "Security Score" or "Puntaje de Seguridad"
const withParam = t('llm_analysis_using', { provider: 'ollama' });  // "🧠 LLM analysis: ollama"
```

---

### Fuzzer (New Modular Architecture)

**Location**: `libs/fuzzer/`

**Purpose**: Advanced security fuzzing with modular generators and detectors

**Architecture**:
```
libs/fuzzer/
├── index.ts              # Public API exports
├── engine/               # FuzzerEngine orchestrator
├── generators/           # Payload generators
│   ├── prompt-injection/ # LLM-specific attacks
│   ├── classic/          # SQLi, XSS, Command Injection
│   ├── protocol/         # JSON-RPC, Schema confusion
│   └── advanced/         # JWT, Prototype Pollution
├── detectors/            # Vulnerability detectors
│   ├── prompt-leak/      # System prompt extraction
│   ├── jailbreak/        # LLM guardrail bypass
│   ├── timing/           # Timing-based attacks
│   └── weak-id/          # Predictable ID detection
├── fingerprint/          # Server fingerprinting
└── utils/                # Report mappers
```

**Key Usage**:
```typescript
import {
  FuzzerEngine,
  PromptInjectionGenerator,
  ClassicPayloadGenerator,
  PromptLeakDetector,
  JailbreakDetector,
  TimingDetector
} from '@mcp-verify/fuzzer';

const engine = new FuzzerEngine({
  generators: [
    new PromptInjectionGenerator(),
    new ClassicPayloadGenerator(),
  ],
  detectors: [
    new PromptLeakDetector(),
    new JailbreakDetector(),
    new TimingDetector()
  ],
  enableFingerprinting: true, // Auto-disable irrelevant generators
  concurrency: 5
});

const session = await engine.fuzz(target, 'tool-name');
```

**Edit when**:
- Adding new attack generators
- Adding new vulnerability detectors
- Modifying fingerprinting logic
- Changing fuzzing strategy

---

### Legacy Fuzzer

**File**: `libs/core/use-cases/fuzzer/fuzzer.ts`

**Purpose**: Basic chaos testing (deprecated, use `@mcp-verify/fuzzer` for new features)

**Edit when**:
- Maintaining backwards compatibility

---

### Exit Codes

**File**: `apps/cli-verifier/src/commands/validate.ts`

**Purpose**: Determine CLI exit codes based on report

**Key Code**:
```typescript
function getExitCode(report: ValidationReport): number {
  // Critical security issues
  if (report.security.criticalCount > 0) {
    return 2;  // Critical
  }

  // Validation failures
  if (!report.schema.valid) {
    return 1;  // Invalid
  }

  // Success
  return 0;
}

// Usage
process.exit(getExitCode(report));
```

**Exit Codes**:
- `0` - Success (no issues)
- `1` - Validation failed (non-critical)
- `2` - Critical security issues detected

**Edit when**:
- Changing exit code logic
- Adding new exit codes
- Modifying failure conditions

---

## 🔗 Component Relationships

```
CLI (index.ts)
    ↓
Command (validate.ts)
    ↓
Validator (validator.ts)
    ↓
    ├─→ Transport (stdio-transport.ts)
    ├─→ SecurityScanner (security-scanner.ts)
    │       ↓
    │       └─→ Rules (sql-injection.ts, etc.)
    ├─→ SemanticAnalyzer (semantic-analyzer.ts)
    │       ↓
    │       └─→ LLMSemanticAnalyzer (llm-semantic-analyzer.ts)
    │               ↓
    │               └─→ Providers (anthropic-provider.ts, etc.)
    └─→ Reporters (html-generator.ts, etc.)
```

---

## 📚 Common Tasks

### Add New CLI Command

1. Create `apps/cli-verifier/src/commands/my-command.ts`
2. Register in `apps/cli-verifier/src/bin/index.ts`
3. Add tests in `tests/cli-verifier/commands/my-command.spec.ts`
4. Update i18n keys in `libs/core/domain/reporting/i18n.ts`

### Add New Security Rule

1. Create `libs/core/domain/security/rules/my-rule.ts`
2. Register in `libs/core/domain/security/security-scanner.ts`
3. Add tests in `tests/core/domain/security/rules/my-rule.spec.ts`
4. Document in `SECURITY_SCORING.md`

### Add New LLM Provider

1. Create `libs/core/domain/quality/providers/my-provider.ts`
2. Export in `libs/core/domain/quality/providers/index.ts`
3. Add case in `libs/core/domain/quality/llm-semantic-analyzer.ts` (`initializeProvider()`)
4. Add tests in `tests/core/domain/quality/providers/my-provider.spec.ts`
5. Document in `guides/LLM_SETUP.md`

### Add Translation String

1. Add key to both `en` and `es` in `libs/core/domain/reporting/i18n.ts`
2. Use `t('my_key')` in code
3. Test with both languages:
   ```bash
   export MCP_VERIFY_LANG=en && npm test
   export MCP_VERIFY_LANG=es && npm test
   ```

---

## 🎓 Learning Path

**Day 1**: Understand structure
- Read this CODE_MAP.md
- Browse directory structure
- Run `npm test` to see what works

**Day 2**: Make small change
- Add translation key
- Fix typo in error message
- Add test case

**Day 3**: Medium complexity
- Add new security rule
- Modify report format
- Add CLI option

**Week 2**: Advanced contributions
- Add new LLM provider
- Add new transport type
- Refactor complex component

---

## 🆘 Still Lost?

**Can't find what you need?**

1. **Search the codebase**:
   ```bash
   grep -r "keyword" libs/
   ```

2. **Check imports**: Files import what they need, follow the trail

3. **Ask for help**:
   - GitHub Discussions: https://github.com/FinkTech/mcp-verify/discussions
   - Open issue: https://github.com/FinkTech/mcp-verify/issues

---

## 📚 Related Documentation

- [DEVELOPMENT.md](./DEVELOPMENT.md) - Local setup & workflow
- [ARCHITECTURE.md](./ARCHITECTURE.md) - System design
- [CONTRIBUTING.md](./CONTRIBUTING.md) - Contribution guidelines
- [TESTING.md](./TESTING.md) - Testing strategy

---

**Made with ❤️ by Fink**
