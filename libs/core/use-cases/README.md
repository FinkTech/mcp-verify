# 🎼 Use Cases Layer

Application orchestration for **mcp-verify** - coordinates domain logic and infrastructure adapters.

---

## 📋 Purpose

The **use cases layer** orchestrates **workflows** by combining pure domain logic with infrastructure adapters. This layer implements the application's business workflows without framework coupling.

### Orchestration Pattern

```
CLI Command (apps/)
      ↓
Use Case (this layer)  ← Orchestrates workflow
      ↓
   ┌──┴──┐
   ↓     ↓
Domain  Infrastructure  ← Uses both
Logic   Adapters
```

**Key Responsibilities**:
1. **Coordinate**: Call domain logic + infrastructure in sequence
2. **Transform**: Convert between external and domain types
3. **Error Handling**: Catch and handle errors from both layers
4. **Transaction Management**: Ensure consistency across operations

---

## 📁 Structure

```
libs/core/use-cases/
├── validator/                        # ✅ Main validation workflow
│   ├── validator.ts                  # MCPValidator - orchestrates full validation
│   └── __tests__/
│       └── validator.spec.ts
│
├── fuzzer/                           # 🎲 Fuzzing workflow
│   ├── fuzzer.ts                     # SmartFuzzer - mutation testing
│   ├── mutation-engine.ts            # Generate test inputs
│   ├── payloads.ts                   # Attack payloads
│   └── response-analyzer.ts          # Analyze fuzzing results
│
├── stress-tester/                    # ⚡ Load testing workflow
│   └── stress-tester.ts              # Concurrent request testing
│
├── playground/                       # 🎮 Interactive testing
│   └── tool-executor.ts              # Execute tools interactively
│
├── proxy/                            # 🔄 MCP proxy with guardrails
│   ├── proxy-server.ts               # Proxy orchestrator
│   ├── proxy.types.ts                # Proxy types
│   └── guardrails/                   # Security guardrails
│       ├── https-enforcer.ts         # Force HTTPS
│       ├── input-sanitizer.ts        # Sanitize inputs
│       ├── pii-redactor.ts           # Redact PII
│       ├── rate-limiter.ts           # Rate limiting
│       └── sensitive-command-blocker.ts # Block dangerous commands
│
├── sandbox/                          # 🔒 Sandbox orchestration
│   ├── sandbox.service.ts            # Sandbox workflow
│   ├── deno-runner.ts                # Run in Deno sandbox
│   ├── static-analyzer.ts            # Static code analysis
│   ├── taint-analyzer.ts             # Taint analysis
│   └── types.ts                      # Sandbox types
│
├── mock/                             # 🎭 Mock server
│   └── mock-server.ts                # Mock MCP server
│
├── compliance/                       # 📋 Protocol compliance
│   └── protocol-tester.ts            # Test protocol compliance
│
└── discoverer/                       # 🔍 Capability discovery
    └── capability-discoverer.ts      # Discover MCP capabilities
```

---

## 🏗️ Use Case Modules

### 1. Validator (`validator/`)

**Purpose**: Main validation workflow - orchestrates all validation steps

**Workflow**:
```
1. Test Handshake        (transport)
   ↓
2. Discover Capabilities (transport)
   ↓
3. Validate Schema       (domain: validation)
   ↓
4. Security Scan         (domain: security)
   ↓
5. Quality Analysis      (domain: quality + infrastructure: LLM)
   ↓
6. Generate Report       (domain: reporting + infrastructure: file system)
```

**Usage**:
```typescript
import { MCPValidator } from './use-cases/validator/validator';
import { StdioTransport } from './infrastructure/transport/stdio-transport';

// Create transport (infrastructure)
const transport = new StdioTransport('node', ['server.js']);

// Create validator (use case)
const validator = new MCPValidator(transport);

// Run full validation workflow
const handshakeResult = await validator.testHandshake();
const discoveryResult = await validator.discoverCapabilities();
const validationResult = await validator.validateSchema();

// Generate report (orchestrates domain + infrastructure)
const report = await validator.generateReport({
  handshake: handshakeResult,
  discovery: discoveryResult,
  validation: validationResult
});
```

**Key Methods**:
- `testHandshake()` - Test MCP handshake
- `discoverCapabilities()` - Discover tools/resources/prompts
- `validateSchema()` - Validate against MCP schema
- `generateReport()` - Create validation report
- `cleanup()` - Cleanup resources

---

### 2. Fuzzer (`fuzzer/`)

**Purpose**: Automated fuzz testing with intelligent mutations

**Workflow**:
```
1. Generate Payloads      (domain: fuzzer/payloads)
   ↓
2. Mutate Inputs          (domain: mutation-engine)
   ↓
3. Execute via Transport  (infrastructure: transport)
   ↓
4. Analyze Responses      (domain: response-analyzer)
   ↓
5. Detect Crashes/Errors  (domain: analysis)
```

**Usage**:
```typescript
import { SmartFuzzer } from './use-cases/fuzzer/fuzzer';

const fuzzer = new SmartFuzzer(transport);

// Run fuzzing on discovered tools
const results = await fuzzer.run(discoveryResult);

// results: {
//   totalTests: 150,
//   failedTests: 3,
//   crashes: 1,
//   findings: [...]
// }
```

**Components**:
- `fuzzer.ts` - Main orchestrator
- `mutation-engine.ts` - Generates test inputs
- `payloads.ts` - Attack payload database
- `response-analyzer.ts` - Detects anomalies

---

### 3. Stress Tester (`stress-tester/`)

**Purpose**: Load testing with concurrent requests

**Workflow**:
```
1. Create Virtual Users  (infrastructure: processes)
   ↓
2. Send Concurrent Requests (infrastructure: transport)
   ↓
3. Measure Performance   (domain: performance analysis)
   ↓
4. Generate Report       (domain: reporting)
```

**Usage**:
```typescript
import { StressTester } from './use-cases/stress-tester/stress-tester';

const tester = new StressTester(transport);

// Run stress test
const results = await tester.run({
  concurrentUsers: 10,
  duration: 30000,  // 30 seconds
  rampUp: 5000      // 5 second ramp-up
});

// results: {
//   totalRequests: 450,
//   successfulRequests: 448,
//   failedRequests: 2,
//   averageResponseTime: 125ms
// }
```

---

### 4. Playground (`playground/`)

**Purpose**: Interactive tool testing

**Workflow**:
```
1. List Available Tools  (transport)
   ↓
2. Get User Input        (infrastructure: CLI)
   ↓
3. Validate Input        (domain: validation)
   ↓
4. Execute Tool          (transport)
   ↓
5. Display Results       (infrastructure: output)
```

**Usage**:
```typescript
import { ToolExecutor } from './use-cases/playground/tool-executor';

const executor = new ToolExecutor(transport);

// Execute tool interactively
const result = await executor.execute({
  toolName: 'get_weather',
  arguments: { location: 'New York' }
});

console.log(result);
```

---

### 5. Proxy (`proxy/`)

**Purpose**: Transparent MCP proxy with security guardrails

**Workflow**:
```
Client Request
   ↓
Apply Guardrails (domain: security)
├── HTTPS Enforcer
├── Input Sanitizer
├── PII Redactor
├── Rate Limiter
└── Sensitive Command Blocker
   ↓
Forward to Server (infrastructure: transport)
   ↓
Return Response
```

**Usage**:
```typescript
import { ProxyServer } from './use-cases/proxy/proxy-server';

const proxy = new ProxyServer({
  targetCommand: 'node',
  targetArgs: ['server.js'],
  port: 8080,
  guardrails: {
    enforceHttps: true,
    sanitizeInputs: true,
    redactPII: true,
    rateLimit: { maxRequests: 100, windowMs: 60000 }
  }
});

await proxy.start();
```

**Guardrails**:
- **HTTPS Enforcer**: Reject non-HTTPS URLs
- **Input Sanitizer**: Remove dangerous characters
- **PII Redactor**: Mask credit cards, SSNs
- **Rate Limiter**: Prevent abuse
- **Command Blocker**: Block `rm -rf`, `exec`, etc.

---

### 6. Sandbox (`sandbox/`)

**Purpose**: Safe code execution orchestration

**Workflow**:
```
1. Static Analysis       (domain: static-analyzer)
   ↓
2. Taint Analysis        (domain: taint-analyzer)
   ↓
3. Execute in Sandbox    (infrastructure: deno-sandbox)
   ↓
4. Monitor Execution     (infrastructure: monitoring)
   ↓
5. Cleanup               (infrastructure: cleanup)
```

**Usage**:
```typescript
import { SandboxService } from './use-cases/sandbox/sandbox.service';

const sandbox = new SandboxService({
  allowRead: ['.'],
  allowWrite: [],
  allowNet: [],
  timeout: 10000
});

const result = await sandbox.executeSecurely('node', ['server.js']);
```

---

### 7. Mock Server (`mock/`)

**Purpose**: Simple mock MCP server for testing

**Usage**:
```typescript
import { MockServer } from './use-cases/mock/mock-server';

const mock = new MockServer({
  tools: [
    {
      name: 'test_tool',
      description: 'A test tool',
      inputSchema: { type: 'object', properties: {} }
    }
  ]
});

await mock.start(3000);
```

---

### 8. Compliance Testing (`compliance/`)

**Purpose**: Test MCP protocol compliance

**Usage**:
```typescript
import { ProtocolTester } from './use-cases/compliance/protocol-tester';

const tester = new ProtocolTester(transport);
const results = await tester.runAllTests();

// results: {
//   jsonRpc: { passed: true },
//   handshake: { passed: true },
//   discovery: { passed: false, error: 'Missing tools/list' }
// }
```

---

## 🎯 Use Case Patterns

### Pattern 1: Orchestration

**Problem**: Need to coordinate multiple domain + infrastructure operations

**Solution**: Use case orchestrates the sequence

```typescript
export class MCPValidator {
  constructor(
    private transport: ITransport,           // Infrastructure
    private sandbox?: ISandbox,              // Infrastructure
    private enableSemanticCheck?: boolean,   // Config
    private llmProvider?: string             // Config
  ) {}

  async generateReport(data: ValidationData): Promise<Report> {
    // Step 1: Domain - Security analysis
    const securityScanner = new SecurityScanner();
    const securityReport = await securityScanner.scan(data.discovery);
    const findings = securityReport.findings;

    // Step 2: Domain + Infrastructure - Quality analysis
    let qualityIssues = [];
    if (this.enableSemanticCheck && this.llmProvider) {
      const llmAnalyzer = new LLMSemanticAnalyzer(this.llmProvider);
      qualityIssues = await llmAnalyzer.analyzeTools(data.discovery.tools);
    }

    // Step 3: Domain - Calculate scores
    const securityScore = securityReport.score;
    const qualityScore = this.calculateQualityScore(qualityIssues);

    // Step 4: Domain - Generate report
    return {
      security: securityReport,
      quality: { score: qualityScore, issues: qualityIssues },
      // ...
    };
  }
}
```

---

### Pattern 2: Error Handling

**Problem**: Errors from domain or infrastructure need consistent handling

**Solution**: Use case catches and transforms errors

```typescript
export class SmartFuzzer {
  async run(discovery: DiscoveryResult): Promise<FuzzingResult> {
    try {
      // Generate payloads (domain)
      const payloads = this.mutationEngine.generate(discovery.tools);

      // Execute (infrastructure)
      const responses = await this.executePayloads(payloads);

      // Analyze (domain)
      return this.responseAnalyzer.analyze(responses);

    } catch (error) {
      // Transform infrastructure errors to domain errors
      if (error.code === 'ETIMEDOUT') {
        return {
          status: 'timeout',
          message: 'Server did not respond in time',
          totalTests: payloads.length,
          failedTests: payloads.length
        };
      }

      throw error;
    }
  }
}
```

---

### Pattern 3: Dependency Injection

**Problem**: Use case needs different implementations (testing vs. production)

**Solution**: Inject dependencies through constructor

```typescript
export class MCPValidator {
  constructor(
    private transport: ITransport,        // ← Interface, not implementation
    private sandbox?: ISandbox,           // ← Optional for testing
    private logger?: ILogger              // ← Optional for testing
  ) {}

  async testHandshake(): Promise<HandshakeResult> {
    this.logger?.info('Testing handshake...');

    try {
      const response = await this.transport.sendRequest('initialize', {});
      return { success: true, response };
    } catch (error) {
      this.logger?.error('Handshake failed', { error });
      return { success: false, error: error.message };
    }
  }
}
```

**Testing**:
```typescript
// Test with mock transport
const mockTransport = new MockTransport();
const validator = new MCPValidator(mockTransport);

// Test with real transport
const realTransport = new StdioTransport('node', ['server.js']);
const validator = new MCPValidator(realTransport);
```

---

## 🔍 What Belongs in Use Cases?

### ✅ YES - Use Cases Layer

**Workflow Orchestration**:
```typescript
// ✅ GOOD: Coordinates domain + infrastructure
export class MCPValidator {
  async validate(): Promise<Report> {
    // 1. Infrastructure - Get data from server
    const tools = await this.transport.sendRequest('tools/list');

    // 2. Domain - Analyze security
    const securityReport = await this.securityScanner.scan(discovery);
    const findings = securityReport.findings;

    // 3. Domain - Generate report
    const report = this.reportGenerator.generate(findings);

    // 4. Infrastructure - Save to disk
    await this.fileSystem.writeFile('report.json', JSON.stringify(report));

    return report;
  }
}
```

**Error Transformation**:
```typescript
// ✅ GOOD: Transform infrastructure errors to domain errors
export class StressTester {
  async run(options: StressOptions): Promise<StressResult> {
    try {
      return await this.executeStressTest(options);
    } catch (error) {
      // Transform to domain error
      throw new StressTestError(
        `Stress test failed: ${error.message}`,
        { cause: error, options }
      );
    }
  }
}
```

---

### ❌ NO - Not Use Cases Layer

**Pure Business Logic**:
```typescript
// ❌ BAD: Pure domain logic in use case
export class MCPValidator {
  calculateScore(findings: Finding[]): number {
    let score = 100;
    findings.forEach(f => score -= f.severity === 'critical' ? 20 : 10);
    return Math.max(0, score);
  }
}

// ✅ GOOD: Move to domain
// domain/security/security-scorer.ts
export class SecurityScorer {
  calculate(findings: Finding[]): number {
    let score = 100;
    findings.forEach(f => score -= f.severity === 'critical' ? 20 : 10);
    return Math.max(0, score);
  }
}
```

**Direct I/O**:
```typescript
// ❌ BAD: Direct file I/O in use case
export class MCPValidator {
  async generateReport(): Promise<void> {
    const report = this.createReport();
    fs.writeFileSync('report.json', JSON.stringify(report));  // NO!
  }
}

// ✅ GOOD: Delegate I/O to infrastructure
export class MCPValidator {
  async generateReport(): Promise<Report> {
    return this.createReport();  // Just return data
  }
}

// Caller (CLI command) handles I/O
const report = await validator.generateReport();
await fileSystem.writeFile('report.json', JSON.stringify(report));
```

---

## 🛠️ Common Tasks

### Task 1: Create a New Use Case

**Time**: ~1 hour
**Difficulty**: Intermediate

**Steps**:

#### 1. Create Use Case File

```typescript
// use-cases/my-workflow/my-workflow.ts

import { ITransport } from '../../domain/transport';
import { MyDomainService } from '../../domain/my-module/my-service';

export interface MyWorkflowOptions {
  option1: string;
  option2: number;
}

export interface MyWorkflowResult {
  success: boolean;
  data: any;
}

export class MyWorkflow {
  constructor(
    private transport: ITransport,
    private options?: MyWorkflowOptions
  ) {}

  async execute(): Promise<MyWorkflowResult> {
    try {
      // Step 1: Get data from infrastructure
      const rawData = await this.transport.sendRequest('my/method', {});

      // Step 2: Process with domain logic
      const domainService = new MyDomainService();
      const processedData = domainService.process(rawData);

      // Step 3: Return result
      return {
        success: true,
        data: processedData
      };

    } catch (error) {
      return {
        success: false,
        data: null,
        error: error.message
      };
    }
  }

  async cleanup(): Promise<void> {
    await this.transport.cleanup();
  }
}
```

#### 2. Add Tests

```typescript
// use-cases/my-workflow/__tests__/my-workflow.spec.ts

import { describe, it, expect } from 'vitest';
import { MyWorkflow } from '../my-workflow';
import { MockTransport } from '../../../__mocks__/mock-transport';

describe('MyWorkflow', () => {
  it('should execute workflow successfully', async () => {
    const transport = new MockTransport();
    const workflow = new MyWorkflow(transport);

    const result = await workflow.execute();

    expect(result.success).toBe(true);
  });
});
```

#### 3. Use in CLI Command

```typescript
// apps/cli-verifier/src/commands/my-command.ts

import { MyWorkflow } from '../../../../libs/core/use-cases/my-workflow/my-workflow';

export async function runMyCommandAction(target: string, options: any) {
  const transport = createTransport(target);
  const workflow = new MyWorkflow(transport, options);

  const result = await workflow.execute();

  if (result.success) {
    console.log('Success!', result.data);
  } else {
    console.error('Failed:', result.error);
    process.exit(1);
  }

  await workflow.cleanup();
}
```

---

## 🧪 Testing Use Cases

### Unit Testing with Mocks

```typescript
import { describe, it, expect, vi } from 'vitest';
import { MCPValidator } from './validator';

describe('MCPValidator', () => {
  it('should generate report', async () => {
    // Mock transport
    const mockTransport = {
      sendRequest: vi.fn().mockResolvedValue({
        tools: [{ name: 'test_tool' }]
      }),
      cleanup: vi.fn()
    };

    const validator = new MCPValidator(mockTransport as any);
    const report = await validator.generateReport({});

    expect(report).toBeDefined();
    expect(mockTransport.sendRequest).toHaveBeenCalled();
  });
});
```

### Integration Testing

```typescript
describe('MCPValidator Integration', () => {
  it('should validate real server', async () => {
    // Real transport (integration test)
    const transport = new StdioTransport('node', ['tools/mocks/servers/simple-server.js']);
    const validator = new MCPValidator(transport);

    const handshake = await validator.testHandshake();
    expect(handshake.success).toBe(true);

    await validator.cleanup();
  });
});
```

---

## 🔗 Related Documentation

- **[libs/core/README.md](../README.md)** - Core architecture overview
- **[libs/core/domain/README.md](../domain/README.md)** - Domain layer
- **[libs/core/infrastructure/README.md](../infrastructure/README.md)** - Infrastructure adapters
- **[../../../CODE_MAP.md](../../../CODE_MAP.md)** - Codebase navigation

