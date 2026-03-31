# 🎯 Core Library

Business logic for mcp-verify following clean/hexagonal architecture.

---

## 🏛️ Architecture

This library implements **Hexagonal Architecture** (Ports & Adapters pattern):

```
┌─────────────────────────────────────────────────────────┐
│                    Use Cases Layer                      │
│  (Application orchestration - validates, fuzzes, etc.)  │
└─────────────────────────────────────────────────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        ↓                  ↓                  ↓
┌───────────────┐  ┌──────────────┐  ┌──────────────────┐
│  Domain Layer │  │ Domain Layer │  │  Infrastructure  │
│  (Security)   │  │  (Quality)   │  │     Layer        │
│  Pure Logic   │  │  Pure Logic  │  │  (I/O Adapters)  │
└───────────────┘  └──────────────┘  └──────────────────┘
```

**Key Principle**: Domain is **pure** (no I/O, no frameworks), Infrastructure **adapts** external services.

---

## 📁 Structure

```
libs/core/
│
├── domain/                    # 🎯 Business Logic (Pure TypeScript)
│   ├── mcp-server/           # MCP protocol entities
│   │   └── entities/         # Tool, Resource, Prompt types
│   │
├── security/             # Security analysis
│   ├── rules/            # 60 security rules (6 threat category blocks)
│   └── security-scanner.ts  # Rule orchestrator + scoring
│   │
│   ├── quality/              # Quality analysis
│   │   ├── providers/        # LLM providers (Anthropic, Ollama, OpenAI)
│   │   ├── llm-semantic-analyzer.ts  # LLM orchestrator
│   │   └── semantic-analyzer.ts      # Quality orchestrator
│   │
│   ├── reporting/            # Report generation
│   │   ├── html-generator.ts    # HTML reports
│   │   ├── sarif-generator.ts   # SARIF (GitHub Security)
│   │   ├── markdown-generator.ts # Markdown summaries
│   │   └── i18n.ts              # Translations (EN/ES)
│   │
│   ├── transport/            # Transport implementations
│   │   ├── transport.interface.ts  # ITransport interface
│   │   ├── stdio-transport.ts      # STDIO (Node.js)
│   │   ├── sse-transport.ts        # Server-Sent Events
│   │   └── http-transport.ts       # HTTP
│   │
│   ├── baseline/             # Baseline comparison
│   │   └── baseline-manager.ts # Save/compare baselines
│   │
│   └── shared/               # Domain utilities
│       └── common.types.ts   # Shared domain types
│
├── infrastructure/            # 🔌 External Adapters
│   ├── logging/              # Logging system
│   │   └── logger.ts         # Winston logger
│   │
│   ├── diagnostics/          # Doctor command checks
│   │   └── checks/           # Network, DNS, port checks
│   │
│   └── sandbox/              # Code execution sandbox
│       └── deno-sandbox.ts   # Deno runtime sandbox
│
└── use-cases/                # 🎬 Application Orchestration
    ├── validator/            # Main validation workflow
    │   └── validator.ts      # MCPValidator class
    │
    ├── fuzzer/               # Fuzzing/chaos testing
    │   └── fuzzer.ts         # SmartFuzzer class
    │
    └── proxy/                # Runtime proxy & guardrails
        ├── proxy-server.ts   # Proxy implementation
        └── guardrails/       # Security guardrails
```

---

## 🎯 Layer Responsibilities

### Domain Layer (Pure Business Logic)

**Purpose**: Business rules, calculations, validations

**Rules**:
- ✅ Pure TypeScript (no I/O, no frameworks)
- ✅ Unit-testable without mocks
- ✅ Imports from `shared/` only
- ❌ NO imports from `infrastructure/` or `use-cases/`
- ❌ NO imports from external frameworks (Express, etc.)
- ❌ NO I/O operations (file reads, network calls)

**Examples**:
- Security rule checks (SQL injection detection)
- Score calculations (0-100 algorithm)
- Report formatting (HTML generation)
- LLM response parsing

---

### Infrastructure Layer (External Adapters)

**Purpose**: Adapt external services to domain interfaces

**Rules**:
- ✅ Can import from `domain/` and `shared/`
- ✅ Contains I/O operations
- ✅ Implements domain interfaces
- ❌ NO imports from `use-cases/`
- ❌ NO business logic (that goes in domain/)

**Examples**:
- Logger (Winston adapter)
- Sandbox (Deno runtime adapter)
- File system operations
- Network diagnostics

---

### Use Cases Layer (Application Orchestration)

**Purpose**: Coordinate domain + infrastructure to achieve goals

**Rules**:
- ✅ Can import from `domain/`, `infrastructure/`, `shared/`
- ✅ Orchestrates workflows
- ✅ Handles errors and recovery
- ❌ NO direct I/O (delegate to infrastructure/)
- ❌ NO business logic (that goes in domain/)

**Examples**:
- Validator (orchestrates handshake → discovery → analysis → reporting)
- Fuzzer (generates test cases → executes → analyzes results)
- Proxy (intercepts traffic → applies guardrails → forwards)

---

## 🛠️ Common Tasks

### Task 1: Add a New Security Rule

**Location**: `domain/security/rules/`

**Example**: Add detection for "Hardcoded Secrets"

1. **Create rule file**: `domain/security/rules/hardcoded-secrets.ts`

```typescript
import { ISecurityRule, SecurityFinding } from '../security-scanner';
import { DiscoveryResult } from '../../mcp-server/entities/validation.types';

export class HardcodedSecretsRule implements ISecurityRule {
  readonly code = 'SEC-013';
  readonly name = 'Hardcoded Secrets';
  readonly severity: 'critical' = 'critical';

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const secretPatterns = /\b(password|secret|key|token)\s*=\s*['"][^'"]+['"]/gi;

    for (const tool of discovery.tools) {
      // Check description
      if (secretPatterns.test(tool.description)) {
        findings.push({
          ruleCode: this.code,
          severity: this.severity,
          message: `Hardcoded secret detected in tool "${tool.name}"`,
          component: `tool:${tool.name}`,
          suggestion: 'Remove hardcoded secrets, use environment variables'
        });
      }
    }

    return findings;
  }
}
    }

    // Check parameters
    if (tool.inputSchema?.properties) {
      for (const [paramName, paramConfig] of Object.entries(tool.inputSchema.properties)) {
        const desc = (paramConfig as any).description || '';
        if (secretPatterns.test(desc)) {
          findings.push({
            ruleCode: this.id,
            severity: this.severity,
            message: `Hardcoded secret in parameter "${paramName}"`,
            component: `tool:${tool.name}.${paramName}`,
            suggestion: 'Use environment variables for secrets'
          });
        }
      }
    }

    return findings;
  }
}
```

2. **Register rule**: `domain/security/security-scanner.ts`

```typescript
import { HardcodedSecretsRule } from './rules/hardcoded-secrets';

export class SecurityScanner {
  private rules: ISecurityRule[] = [
    // ... existing rules
    new HardcodedSecretsRule(), // ← Add here
  ];
}
```

3. **Add tests**: `tests/core/domain/security/rules/hardcoded-secrets.spec.ts`

```typescript
import { describe, test, expect } from '@jest/globals';
import { HardcodedSecretsRule } from '../../../../../libs/core/domain/security/rules/hardcoded-secrets';

describe('HardcodedSecretsRule', () => {
  test('should detect hardcoded password in description', () => {
    const rule = new HardcodedSecretsRule();
    const findings = rule.evaluate({
      tools: [{
        name: 'login',
        description: 'Login with password="admin123"',
        inputSchema: { type: 'object', properties: {} }
      }],
      resources: [],
      prompts: []
    });

    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('critical');
  });

  test('should not flag normal description', () => {
    const rule = new HardcodedSecretsRule();
    const findings = rule.evaluate({
      tools: [{
        name: 'get_weather',
        description: 'Get current weather',
        inputSchema: { type: 'object', properties: {} }
      }],
      resources: [],
      prompts: []
    });

    expect(findings).toHaveLength(0);
  });
});
```

4. **Update documentation**: Add to `SECURITY_SCORING.md`

**Time**: ~30 minutes

---

### Task 2: Add a New LLM Provider

**Location**: `domain/quality/providers/`

**Example**: Add support for "Gemini"

1. **Create provider**: `domain/quality/providers/gemini-provider.ts`

```typescript
import { ILLMProvider, LLMMessage, LLMResponse } from './llm-provider.interface';
import { t } from '../../../../shared/utils/cli/i18n-helper';

export class GeminiProvider implements ILLMProvider {
  private apiKey: string;
  private model: string;

  constructor(config: { apiKey?: string; model: string }) {
    if (!config.apiKey) {
      throw new Error(t('gemini_api_key_not_configured'));
    }
    this.apiKey = config.apiKey;
    this.model = config.model;
  }

  getName(): string {
    return `Google Gemini ${this.model}`;
  }

  async isAvailable(): Promise<boolean> {
    return !!this.apiKey && this.apiKey.length > 0;
  }

  async complete(messages: LLMMessage[], options?: {...}): Promise<LLMResponse> {
    const response = await fetch('https://generativelanguage.googleapis.com/v1/models/gemini-pro:generateContent', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-goog-api-key': this.apiKey
      },
      body: JSON.stringify({
        contents: messages.map(m => ({
          role: m.role,
          parts: [{ text: m.content }]
        }))
      })
    });

    const data = await response.json();

    return {
      text: data.candidates[0].content.parts[0].text,
      usage: {
        inputTokens: data.usageMetadata.promptTokenCount,
        outputTokens: data.usageMetadata.candidatesTokenCount
      }
    };
  }

  getModelInfo() {
    return {
      name: this.model,
      provider: 'custom' as const,
      contextWindow: 32000
    };
  }
}
```

2. **Register provider**: `domain/quality/llm-semantic-analyzer.ts`

```typescript
import { GeminiProvider } from './providers/gemini-provider';

async initializeProvider(providerSpec?: string): Promise<ILLMProvider | null> {
  const [providerName, model] = providerSpec.split(':');

  switch (providerName.toLowerCase()) {
    case 'gemini':
      provider = new GeminiProvider({
        apiKey: process.env.GEMINI_API_KEY,
        model
      });
      break;
    // ... other cases
  }
}
```

3. **Add i18n keys**: `domain/reporting/i18n.ts`

```typescript
export const translations = {
  en: {
    gemini_api_key_not_configured: 'Google Gemini API key not configured',
  },
  es: {
    gemini_api_key_not_configured: 'Clave API de Google Gemini no configurada',
  }
};
```

4. **Update docs**: Add Gemini section to `guides/LLM_SETUP.md`

**Time**: ~1 hour

---

### Task 3: Add a New Report Format

**Location**: `domain/reporting/`

**Example**: Add "PDF Report"

1. **Create generator**: `domain/reporting/pdf-generator.ts`

```typescript
import { ValidationReport } from '../mcp-server/entities/validation.types';
import * as fs from 'fs/promises';

export class PdfReportGenerator {
  async generate(report: ValidationReport, outputPath: string): Promise<string> {
    // Generate PDF content (using a library like pdfkit)
    const pdfBuffer = await this.buildPdf(report);

    // Write to file
    await fs.writeFile(outputPath, pdfBuffer);

    return outputPath;
  }

  private async buildPdf(report: ValidationReport): Promise<Buffer> {
    // PDF generation logic
    // ...
  }
}
```

2. **Register in validator**: `use-cases/validator/validator.ts`

```typescript
import { PdfReportGenerator } from '../../domain/reporting/pdf-generator';

// In report generation section
if (format === 'pdf') {
  const pdfGenerator = new PdfReportGenerator();
  await pdfGenerator.generate(report, outputPath);
}
```

3. **Add CLI option**: `apps/cli-verifier/src/bin/index.ts`

```typescript
program
  .command('validate <target>')
  .option('--format <type>', 'Report format: json, html, sarif, md, pdf', 'json')
```

**Time**: ~2 hours (depending on PDF library complexity)

---

### Task 4: Add a New Transport Type

**Location**: `domain/transport/`

**Example**: Add "WebSocket Transport"

1. **Create transport**: `domain/transport/websocket-transport.ts`

```typescript
import { ITransport } from './transport.interface';
import WebSocket from 'ws';

export class WebSocketTransport implements ITransport {
  private ws: WebSocket | null = null;
  private url: string;

  constructor(url: string) {
    this.url = url;
  }

  async initialize(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.ws = new WebSocket(this.url);

      this.ws.on('open', () => {
        // Send handshake
        this.sendRequest('initialize', {}).then(resolve);
      });

      this.ws.on('error', reject);
    });
  }

  async sendRequest(method: string, params: any): Promise<any> {
    return new Promise((resolve, reject) => {
      const request = {
        jsonrpc: '2.0',
        id: Date.now(),
        method,
        params
      };

      this.ws!.send(JSON.stringify(request));

      this.ws!.once('message', (data: string) => {
        const response = JSON.parse(data);
        resolve(response.result);
      });
    });
  }

  async close(): Promise<void> {
    this.ws?.close();
  }
}
```

2. **Add to factory**: `apps/cli-verifier/src/utils/transport-factory.ts`

```typescript
import { WebSocketTransport } from '../../../../libs/core/domain/transport/websocket-transport';

export async function createTransport(target: string, type?: string): Promise<ITransport> {
  if (type === 'ws' || target.startsWith('ws://')) {
    return new WebSocketTransport(target);
  }
  // ... other transports
}
```

3. **Add tests**: `tests/core/domain/transport/websocket-transport.spec.ts`

**Time**: ~1.5 hours

---

## 🚫 What NOT to Do

### ❌ Anti-Pattern 1: Business Logic in Infrastructure

```typescript
// ❌ BAD: infrastructure/logging/logger.ts
export class Logger {
  logSecurityFinding(tool: McpTool) {
    // Analyzing security here? NO!
    if (tool.description.includes('sql')) {
      this.warn('SQL injection detected');
    }
  }
}
```

**Why?** Security analysis is business logic → belongs in `domain/security/`

**Fix**: Keep infrastructure dumb (just logging), move logic to domain.

---

### ❌ Anti-Pattern 2: I/O in Domain

```typescript
// ❌ BAD: domain/security/security-scanner.ts
export class SecurityScanner {
  async scan(discovery: DiscoveryResult) {
    const config = await fs.readFile('./config.json'); // NO I/O in domain!
  }
}
```

**Why?** Domain should be pure (unit-testable without mocks).

**Fix**: Pass config as parameter, read it in use-case or infrastructure.

---

### ❌ Anti-Pattern 3: Use Case Logic in Domain

```typescript
// ❌ BAD: domain/validator/validator.ts
export class Validator {
  async validate() {
    // Orchestrating multiple steps? This is use-case logic!
    await this.handshake();
    await this.discover();
    await this.analyze();
  }
}
```

**Why?** Domain contains business rules, not workflows.

**Fix**: Move orchestration to `use-cases/validator/validator.ts`

---

## 📊 Dependency Flow

```
Apps (CLI)
    ↓ creates
Use Cases (Validator)
    ↓ uses
Domain (SecurityScanner, SemanticAnalyzer)
    ↓ uses
Domain Entities (McpTool, SecurityFinding)
    ↓ uses
Shared Utilities (i18n, formatters)
```

**Key Rules**:
1. Domain NEVER imports from Use Cases or Infrastructure
2. Use Cases can import from Domain and Infrastructure
3. Infrastructure can import from Domain (to implement interfaces)
4. Everyone can import from Shared

---

## 🧪 Testing Strategy

### Domain Tests (Pure Unit Tests)

```typescript
// No mocks needed! Domain is pure.
test('SecurityScanner calculates score correctly', () => {
  const analyzer = new SecurityScanner();
  const result = analyzer.analyze({
    tools: [{
      name: 'dangerous',
      description: 'SQL query: DROP TABLE'
    }]
  });

  expect(result.score).toBeLessThan(70);
  expect(result.findings).toHaveLength(1);
});
```

### Use Case Tests (Integration Tests)

```typescript
// Mock infrastructure, test orchestration
test('Validator orchestrates workflow', async () => {
  const mockTransport = createMockTransport();
  const validator = new MCPValidator(mockTransport);

  const report = await validator.validate();

  expect(mockTransport.initialize).toHaveBeenCalled();
  expect(report.security.score).toBeDefined();
});
```

---

## 🎓 Learning Path

**Day 1**: Understand layers
- Read this README
- Browse `domain/security/` (simplest domain)
- Check `use-cases/validator/` (orchestration example)

**Day 2**: Add small feature
- Add new security rule
- Add test
- See it work end-to-end

**Week 1**: Medium complexity
- Add new LLM provider
- Add new report format
- Modify scoring algorithm

**Week 2**: Advanced
- Add new transport type
- Refactor use case
- Improve architecture

---

## 📚 Related Documentation

- [CODE_MAP.md](../../CODE_MAP.md) - "I want to add X" quick reference
- [ARCHITECTURE.md](../../ARCHITECTURE.md) - System design philosophy
- [DEVELOPMENT.md](../../DEVELOPMENT.md) - Local setup & testing
- [libs/README.md](../README.md) - Library structure overview

---

## 🆘 Need Help?

**Still confused about where code belongs?**

1. Check [CODE_MAP.md](../../CODE_MAP.md) - Searchable examples
2. Use the decision tree in [libs/README.md](../README.md#finding-the-right-place)
3. Ask in [GitHub Discussions](https://github.com/FinkTech/mcp-verify/discussions)

**General rule**: If it's a business rule → domain/. If it's I/O → infrastructure/. If it's orchestration → use-cases/.

