# 📖 API Reference Documentation

Guide for generating and maintaining API documentation for mcp-verify using TypeDoc.

---

## 🎯 Overview

This document explains how to:

- Document your code with JSDoc comments
- Generate API documentation with TypeDoc
- Follow documentation best practices
- Maintain consistent documentation standards

---

## 🚀 Quick Start

### Generate API Documentation

```bash
# Install TypeDoc (if not already installed)
npm install --save-dev typedoc

# Generate API docs
npm run docs:generate

# Open generated documentation
open docs/api/index.html  # macOS
start docs/api/index.html # Windows
```

---

## 📚 TypeDoc Overview

### What is TypeDoc?

TypeDoc is a documentation generator for TypeScript projects. It:

- Parses TypeScript source files
- Extracts JSDoc comments
- Generates structured HTML documentation
- Creates searchable API reference

### Why Use TypeDoc?

✅ **Automatic**: Generates docs from your code
✅ **Type-safe**: Uses TypeScript type information
✅ **Searchable**: Built-in search functionality
✅ **Versioned**: Docs track code changes
✅ **IDE Integration**: Many IDEs show JSDoc tooltips

---

## 🔧 Setup and Configuration

### Installation

```bash
npm install --save-dev typedoc
```

### TypeDoc Configuration

**File**: `typedoc.json`

```json
{
  "entryPoints": [
    "libs/core/index.ts",
    "libs/transport/index.ts",
    "libs/protocol/index.ts",
    "libs/shared/index.ts",
    "apps/cli-verifier/src/index.ts"
  ],
  "out": "docs/api",
  "exclude": ["**/*.test.ts", "**/__tests__/**", "**/node_modules/**"],
  "excludePrivate": true,
  "excludeProtected": false,
  "excludeInternal": false,
  "readme": "README.md",
  "name": "mcp-verify API Documentation",
  "includeVersion": true,
  "categorizeByGroup": true,
  "categoryOrder": [
    "Security",
    "Validation",
    "Transport",
    "Quality",
    "Reporting",
    "Infrastructure",
    "*"
  ],
  "sort": ["source-order"],
  "plugin": ["typedoc-plugin-markdown"],
  "theme": "default"
}
```

### NPM Scripts

Add to `package.json`:

```json
{
  "scripts": {
    "docs:generate": "typedoc",
    "docs:serve": "npx http-server docs/api -o",
    "docs:watch": "typedoc --watch",
    "docs:json": "typedoc --json docs/api.json"
  }
}
```

---

## 📝 Documentation Style Guide

### Basic JSDoc Template

````typescript
/**
 * Brief description of what the function/class does.
 *
 * More detailed explanation if needed. Can span multiple lines.
 * Explain the purpose, behavior, and any important details.
 *
 * @param paramName - Description of the parameter
 * @param options - Configuration options
 * @returns Description of return value
 * @throws {ErrorType} When this error occurs
 *
 * @example
 * ```typescript
 * const result = myFunction('input', { option: true });
 * console.log(result); // Expected output
 * ```
 *
 * @see {@link RelatedFunction} for related functionality
 * @category CategoryName
 */
export function myFunction(paramName: string, options: Options): Result {
  // Implementation
}
````

---

## 🎨 Documentation Examples

### Example 1: Security Rule

**File**: `libs/core/domain/security/rules/sql-injection-rule.ts`

````typescript
/**
 * Detects potential SQL injection vulnerabilities in MCP tool definitions.
 *
 * This rule analyzes tool descriptions, parameter names, and schemas for
 * patterns that suggest SQL queries with user-controlled input. It checks
 * for string concatenation, template literals in SQL contexts, and unsafe
 * query construction patterns.
 *
 * @category Security
 * @see {@link ISecurityRule} for the base interface
 * @see {@link SecurityScanner} for how rules are orchestrated
 *
 * @example
 * Basic usage:
 * ```typescript
 * const rule = new SqlInjectionRule();
 * const findings = rule.check(discoveryResult);
 *
 * if (findings.length > 0) {
 *   console.log('SQL injection vulnerabilities detected!');
 *   findings.forEach(f => console.log(f.message));
 * }
 * ```
 *
 * @example
 * Vulnerable pattern detection:
 * ```typescript
 * // This tool description will be flagged:
 * const tool = {
 *   name: 'query_users',
 *   description: 'Execute SQL: SELECT * FROM users WHERE id = ${userId}',
 *   inputSchema: { type: 'object', properties: {} }
 * };
 *
 * const findings = rule.check({ tools: [tool], resources: [], prompts: [] });
 * // findings[0].severity === 'critical'
 * // findings[0].ruleCode === 'SEC-001'
 * ```
 */
export class SqlInjectionRule implements ISecurityRule {
  /**
   * Regular expression patterns used to detect SQL injection vulnerabilities.
   *
   * Matches common SQL keywords followed by suspicious string operations,
   * template literals, or concatenation patterns.
   *
   * @internal
   */
  private readonly sqlPatterns: RegExp[] = [
    /SELECT.*\$\{.*\}/i,
    /INSERT.*\+.*INTO/i,
    /DELETE.*FROM.*\$\{/i,
    // ... more patterns
  ];

  /**
   * Analyzes the discovery result for SQL injection vulnerabilities.
   *
   * Examines tool descriptions, parameter descriptions, and schema patterns
   * to identify potential SQL injection risks. Returns detailed findings
   * with severity, location, and remediation recommendations.
   *
   * @param discovery - The MCP server discovery result to analyze
   * @returns Array of security findings, empty if no issues found
   *
   * @example
   * ```typescript
   * const rule = new SqlInjectionRule();
   * const discovery = await mcpClient.discover();
   * const findings = rule.check(discovery);
   *
   * if (findings.length > 0) {
   *   findings.forEach(finding => {
   *     console.log(`${finding.severity}: ${finding.message}`);
   *     console.log(`Tool: ${finding.component}`);
   *     console.log(`Recommendation: ${finding.recommendation}`);
   *   });
   * }
   * ```
   */
  check(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    // Analyze tools
    for (const tool of discovery.tools) {
      const toolFindings = this.analyzeTool(tool);
      findings.push(...toolFindings);
    }

    return findings;
  }

  /**
   * Gets metadata about this security rule.
   *
   * @returns Rule metadata including ID, name, severity, and category
   *
   * @example
   * ```typescript
   * const rule = new SqlInjectionRule();
   * const metadata = rule.getRuleMetadata();
   * console.log(metadata.id);        // 'SEC-001'
   * console.log(metadata.name);      // 'SQL Injection Detection'
   * console.log(metadata.severity);  // 'critical'
   * ```
   */
  getRuleMetadata(): RuleMetadata {
    return {
      id: "SEC-001",
      name: "SQL Injection Detection",
      description: "Detects SQL injection vulnerabilities",
      severity: "critical",
      category: "injection",
      references: [
        "https://owasp.org/www-community/attacks/SQL_Injection",
        "https://cwe.mitre.org/data/definitions/89.html",
      ],
    };
  }

  /**
   * Analyzes a single tool for SQL injection patterns.
   *
   * @param tool - The tool definition to analyze
   * @returns Array of findings for this tool
   * @internal
   */
  private analyzeTool(tool: Tool): SecurityFinding[] {
    // Implementation...
    return [];
  }
}
````

### Example 2: Transport Interface

**File**: `libs/transport/types.ts`

````typescript
/**
 * Configuration options for transport connections.
 *
 * @category Transport
 */
export interface TransportOptions {
  /**
   * Connection timeout in milliseconds.
   * @defaultValue 30000 (30 seconds)
   */
  timeout?: number;

  /**
   * Maximum number of retry attempts for failed connections.
   * @defaultValue 3
   */
  maxRetries?: number;

  /**
   * Retry strategy to use.
   * - `exponential`: Exponential backoff (recommended)
   * - `linear`: Fixed delay between retries
   * - `none`: No retries
   * @defaultValue 'exponential'
   */
  retryStrategy?: "exponential" | "linear" | "none";

  /**
   * Initial delay between retries in milliseconds.
   * Only applicable when retryStrategy is not 'none'.
   * @defaultValue 1000
   */
  retryDelay?: number;

  /**
   * Whether to enable debug logging.
   * @defaultValue false
   */
  debug?: boolean;
}

/**
 * Base interface for MCP transport implementations.
 *
 * Transports handle communication between the validator and MCP servers.
 * Different transport types (STDIO, HTTP, SSE) implement this interface
 * to provide a consistent API.
 *
 * @category Transport
 * @see {@link StdioTransport} for process-based communication
 * @see {@link HttpTransport} for HTTP-based communication
 * @see {@link SSETransport} for Server-Sent Events
 *
 * @example
 * Implementing a custom transport:
 * ```typescript
 * class CustomTransport implements ITransport {
 *   async connect(): Promise<void> {
 *     // Establish connection
 *   }
 *
 *   async send(request: JsonRpcRequest): Promise<JsonRpcResponse> {
 *     // Send request and return response
 *   }
 *
 *   async close(): Promise<void> {
 *     // Clean up resources
 *   }
 *
 *   isConnected(): boolean {
 *     return this.connected;
 *   }
 * }
 * ```
 */
export interface ITransport {
  /**
   * Establishes connection to the MCP server.
   *
   * This method should handle all connection initialization, including
   * spawning processes (STDIO), establishing HTTP connections, or
   * setting up event streams (SSE).
   *
   * @throws {TransportError} If connection fails after all retry attempts
   *
   * @example
   * ```typescript
   * const transport = new StdioTransport('node', ['server.js']);
   * try {
   *   await transport.connect();
   *   console.log('Connected successfully');
   * } catch (error) {
   *   console.error('Connection failed:', error.message);
   * }
   * ```
   */
  connect(): Promise<void>;

  /**
   * Sends a JSON-RPC request to the MCP server.
   *
   * @param request - The JSON-RPC 2.0 request to send
   * @returns Promise resolving to the server's response
   * @throws {TransportError} If the request fails or times out
   * @throws {JsonRpcError} If the server returns an error response
   *
   * @example
   * Sending an initialize request:
   * ```typescript
   * const response = await transport.send({
   *   jsonrpc: '2.0',
   *   id: 1,
   *   method: 'initialize',
   *   params: {
   *     protocolVersion: '2024-11-05',
   *     capabilities: {},
   *     clientInfo: { name: 'mcp-verify', version: '1.0.0' }
   *   }
   * });
   *
   * console.log('Server:', response.result.serverInfo.name);
   * ```
   *
   * @example
   * Listing tools:
   * ```typescript
   * const response = await transport.send({
   *   jsonrpc: '2.0',
   *   id: 2,
   *   method: 'tools/list',
   *   params: {}
   * });
   *
   * console.log('Tools:', response.result.tools);
   * ```
   */
  send(request: JsonRpcRequest): Promise<JsonRpcResponse>;

  /**
   * Closes the transport connection and releases resources.
   *
   * This method should gracefully shut down the connection, terminate
   * any child processes, and clean up event listeners.
   *
   * @example
   * ```typescript
   * try {
   *   await transport.connect();
   *   // ... do work ...
   * } finally {
   *   await transport.close();
   *   console.log('Connection closed');
   * }
   * ```
   */
  close(): Promise<void>;

  /**
   * Checks if the transport is currently connected.
   *
   * @returns `true` if connected, `false` otherwise
   *
   * @example
   * ```typescript
   * if (transport.isConnected()) {
   *   const response = await transport.send(request);
   * } else {
   *   await transport.connect();
   * }
   * ```
   */
  isConnected(): boolean;
}
````

### Example 3: Validator Use Case

**File**: `libs/core/use-cases/validator/validator.ts`

````typescript
/**
 * Configuration options for the MCP validator.
 *
 * @category Validation
 */
export interface ValidatorOptions {
  /**
   * Whether to enable LLM-based semantic analysis.
   * Requires API key configuration.
   * @defaultValue false
   */
  enableLLM?: boolean;

  /**
   * LLM provider configuration.
   * Only used if enableLLM is true.
   */
  llmConfig?: {
    /** Provider name: 'anthropic', 'openai', or 'ollama' */
    provider: "anthropic" | "openai" | "ollama";
    /** Model identifier (e.g., 'claude-3-haiku-20240307') */
    model: string;
    /** API key (not needed for Ollama) */
    apiKey?: string;
  };

  /**
   * Output directory for generated reports.
   * @defaultValue './reportes'
   */
  outputDir?: string;

  /**
   * Report formats to generate.
   * @defaultValue ['json']
   */
  formats?: Array<"json" | "html" | "sarif" | "markdown">;

  /**
   * Minimum security score to pass validation (0-100).
   * If the actual score is below this threshold, validation fails.
   * @defaultValue 50
   */
  minSecurityScore?: number;

  /**
   * Whether to include detailed findings in the report.
   * @defaultValue true
   */
  includeDetails?: boolean;
}

/**
 * Main validator for MCP servers.
 *
 * Orchestrates the complete validation workflow:
 * 1. Connects to MCP server via transport
 * 2. Performs protocol handshake
 * 3. Discovers server capabilities
 * 4. Runs security analysis
 * 5. Optionally runs LLM quality analysis
 * 6. Generates reports
 *
 * @category Validation
 *
 * @example
 * Basic validation:
 * ```typescript
 * const transport = new StdioTransport('node', ['server.js']);
 * const validator = new MCPValidator(transport);
 *
 * const report = await validator.validate();
 *
 * console.log(`Security Score: ${report.securityScore}/100`);
 * console.log(`Status: ${report.status}`);
 * ```
 *
 * @example
 * Validation with LLM analysis:
 * ```typescript
 * const validator = new MCPValidator(transport, {
 *   enableLLM: true,
 *   llmConfig: {
 *     provider: 'anthropic',
 *     model: 'claude-3-haiku-20240307',
 *     apiKey: process.env.ANTHROPIC_API_KEY
 *   }
 * });
 *
 * const report = await validator.validate();
 * console.log(`Quality Score: ${report.qualityScore}/100`);
 * ```
 *
 * @example
 * Validation with custom thresholds:
 * ```typescript
 * const validator = new MCPValidator(transport, {
 *   minSecurityScore: 80,
 *   outputDir: './reports',
 *   formats: ['json', 'html', 'sarif']
 * });
 *
 * try {
 *   const report = await validator.validate();
 *   console.log('Validation passed!');
 * } catch (error) {
 *   console.error('Validation failed:', error.message);
 * }
 * ```
 */
export class MCPValidator {
  /** @internal */
  private transport: ITransport;

  /** @internal */
  private options: Required<ValidatorOptions>;

  /** @internal */
  private securityScanner: SecurityScanner;

  /** @internal */
  private llmAnalyzer?: LLMSemanticAnalyzer;

  /**
   * Creates a new MCP validator instance.
   *
   * @param transport - Transport layer for communication with MCP server
   * @param options - Optional configuration options
   *
   * @example
   * ```typescript
   * const transport = new HttpTransport({ url: 'http://localhost:3000' });
   * const validator = new MCPValidator(transport, {
   *   minSecurityScore: 90,
   *   formats: ['json', 'html']
   * });
   * ```
   */
  constructor(transport: ITransport, options?: ValidatorOptions) {
    this.transport = transport;
    this.options = {
      enableLLM: false,
      outputDir: "./reportes",
      formats: ["json"],
      minSecurityScore: 50,
      includeDetails: true,
      ...options,
    };

    this.securityScanner = new SecurityScanner();

    if (this.options.enableLLM && this.options.llmConfig) {
      this.llmAnalyzer = new LLMSemanticAnalyzer(this.options.llmConfig);
    }
  }

  /**
   * Runs complete validation workflow.
   *
   * This is the main entry point for validation. It performs:
   * - Connection and handshake
   * - Server capability discovery
   * - Security analysis
   * - Optional LLM quality analysis
   * - Report generation
   *
   * @returns Complete validation report
   * @throws {ValidationError} If validation fails at any step
   * @throws {TransportError} If connection fails
   * @throws {SecurityError} If critical security issues found
   *
   * @example
   * ```typescript
   * const validator = new MCPValidator(transport);
   *
   * try {
   *   const report = await validator.validate();
   *
   *   console.log(`✓ Validation complete`);
   *   console.log(`  Security: ${report.securityScore}/100`);
   *   console.log(`  Tools: ${report.tools.length}`);
   *   console.log(`  Findings: ${report.findings.length}`);
   * } catch (error) {
   *   console.error(`✗ Validation failed: ${error.message}`);
   *   process.exit(1);
   * }
   * ```
   */
  async validate(): Promise<ValidationReport> {
    // Implementation...
    return {} as ValidationReport;
  }

  /**
   * Tests protocol handshake with MCP server.
   *
   * Useful for troubleshooting connection issues. Tests only the
   * initialize step without performing full validation.
   *
   * @returns Handshake result with server information
   * @throws {TransportError} If connection fails
   *
   * @example
   * ```typescript
   * const validator = new MCPValidator(transport);
   *
   * try {
   *   const result = await validator.testHandshake();
   *   console.log(`Server: ${result.serverName} v${result.version}`);
   *   console.log(`Protocol: ${result.protocolVersion}`);
   * } catch (error) {
   *   console.error('Handshake failed:', error.message);
   * }
   * ```
   */
  async testHandshake(): Promise<HandshakeResult> {
    // Implementation...
    return {} as HandshakeResult;
  }
}
````

---

## 🛡️ Proxy Command API (Security Gateway v1.0)

This section documents the API for interacting with the Security Gateway proxy programmatically.

### HTTP API

The proxy exposes an HTTP endpoint for JSON-RPC 2.0 requests.

#### Endpoint

```
POST http://localhost:<port>/
Content-Type: application/json
```

#### Request Format

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "tool_name",
    "arguments": {
      "arg1": "value1",
      "arg2": "value2"
    }
  }
}
```

#### Response Format (Success)

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "success": true,
    "data": {
      /* tool response */
    }
  }
}
```

#### Response Format (Blocked by Gateway)

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32003,
    "message": "Security Gateway blocked request",
    "data": {
      "blocked": true,
      "layer": 1,
      "latency_ms": 8,
      "findings": [
        {
          "ruleId": "SEC-003",
          "severity": "critical",
          "message": "SQL injection detected in parameter 'filter'",
          "cwe": "CWE-89",
          "owasp": "A03:2021 - Injection",
          "remediation": "Use parameterized queries",
          "matchedPattern": "OR 1=1",
          "affectedParameter": "filter"
        }
      ]
    }
  }
}
```

#### Response Format (Panic Mode)

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": 503,
    "message": "Client in PANIC MODE - permanently blocked",
    "data": {
      "clientId": "192.168.1.100",
      "strikes": 3,
      "blockedUntil": null,
      "panicMode": true,
      "reason": "Exceeded 3 rate limit violations"
    }
  }
}
```

---

### Client Headers

#### x-client-id (Optional)

Custom client identifier. If not provided, IP address is used.

```http
POST / HTTP/1.1
Host: localhost:3000
Content-Type: application/json
x-client-id: my-custom-client-123

{ "jsonrpc": "2.0", ... }
```

**Priority Chain**:

1. `x-client-id` header (highest priority)
2. `x-forwarded-for` header (first IP in chain)
3. `req.socket.remoteAddress` (direct connection IP)
4. `"default-client"` (fallback)

---

### Audit Log Format (JSONL)

Each blocked request is logged to the audit log file in JSONL format.

#### Log Entry Structure

```json
{
  "timestamp": "2026-03-07T15:30:45.123Z",
  "clientId": "192.168.1.100",
  "blocked": true,
  "layer": 1,
  "latency_ms": 8,
  "request": {
    "method": "tools/call",
    "params": {
      "name": "query_users",
      "arguments": { "filter": "' OR 1=1--" }
    }
  },
  "findings": [
    {
      "ruleId": "SEC-003",
      "severity": "critical",
      "message": "SQL injection detected",
      "cwe": "CWE-89",
      "owasp": "A03:2021 - Injection"
    }
  ],
  "strikes": 0,
  "cacheHit": false
}
```

#### Parsing Audit Logs

```bash
# Count total blocked requests
jq -s 'map(select(.blocked == true)) | length' audit.jsonl

# Group by client ID
jq -s 'group_by(.clientId) | map({client: .[0].clientId, blocks: length})' audit.jsonl

# Find all critical findings
jq 'select(.findings[].severity == "critical")' audit.jsonl

# Calculate average latency per layer
jq -s 'group_by(.layer) | map({layer: .[0].layer, avgLatency: (map(.latency_ms) | add / length)})' audit.jsonl
```

---

### Error Codes

| Code     | Meaning             | Description                                      |
| -------- | ------------------- | ------------------------------------------------ |
| `-32003` | Security Block      | Request blocked by Security Gateway              |
| `429`    | Too Many Requests   | Client in backoff period (Strike 1 or 2)         |
| `503`    | Service Unavailable | Client in PANIC MODE (Strike 3, permanent block) |
| `-32700` | Parse Error         | Invalid JSON                                     |
| `-32600` | Invalid Request     | Not JSON-RPC 2.0                                 |
| `-32601` | Method Not Found    | Unknown method                                   |
| `-32602` | Invalid Params      | Malformed parameters                             |

---

### TypeScript Client Example

```typescript
import fetch from "node-fetch";

interface ProxyClient {
  call(tool: string, args: any): Promise<any>;
}

class MCPProxyClient implements ProxyClient {
  private requestId = 0;

  constructor(
    private readonly proxyUrl: string,
    private readonly clientId?: string,
  ) {}

  async call(tool: string, args: any): Promise<any> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };

    if (this.clientId) {
      headers["x-client-id"] = this.clientId;
    }

    const response = await fetch(this.proxyUrl, {
      method: "POST",
      headers,
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: ++this.requestId,
        method: "tools/call",
        params: {
          name: tool,
          arguments: args,
        },
      }),
    });

    const result = await response.json();

    if (result.error) {
      if (result.error.code === -32003) {
        // Security Gateway blocked
        throw new SecurityBlockError(result.error.data);
      } else if (result.error.code === 503) {
        // Panic Mode
        throw new PanicModeError(result.error.data);
      } else {
        throw new Error(
          `RPC Error ${result.error.code}: ${result.error.message}`,
        );
      }
    }

    return result.result;
  }
}

class SecurityBlockError extends Error {
  constructor(public readonly data: any) {
    super(`Security Gateway blocked: ${data.findings[0]?.message}`);
  }
}

class PanicModeError extends Error {
  constructor(public readonly data: any) {
    super(`Client in PANIC MODE: ${data.reason}`);
  }
}

// Usage
const client = new MCPProxyClient("http://localhost:3000", "my-app-v1.0");

try {
  const result = await client.call("get_user", { userId: "123" });
  console.log("Success:", result);
} catch (error) {
  if (error instanceof SecurityBlockError) {
    console.error("Blocked:", error.data.findings);
  } else if (error instanceof PanicModeError) {
    console.error("Panic Mode:", error.data);
  } else {
    console.error("Error:", error);
  }
}
```

---

### Python Client Example

```python
import requests
import json

class MCPProxyClient:
    def __init__(self, proxy_url: str, client_id: str = None):
        self.proxy_url = proxy_url
        self.client_id = client_id
        self.request_id = 0

    def call(self, tool: str, args: dict) -> dict:
        headers = {'Content-Type': 'application/json'}
        if self.client_id:
            headers['x-client-id'] = self.client_id

        self.request_id += 1
        payload = {
            'jsonrpc': '2.0',
            'id': self.request_id,
            'method': 'tools/call',
            'params': {
                'name': tool,
                'arguments': args
            }
        }

        response = requests.post(
            self.proxy_url,
            headers=headers,
            json=payload,
            timeout=5
        )

        result = response.json()

        if 'error' in result:
            if result['error']['code'] == -32003:
                raise SecurityBlockError(result['error']['data'])
            elif result['error']['code'] == 503:
                raise PanicModeError(result['error']['data'])
            else:
                raise Exception(f"RPC Error: {result['error']['message']}")

        return result['result']

class SecurityBlockError(Exception):
    def __init__(self, data):
        self.data = data
        super().__init__(f"Blocked: {data['findings'][0]['message']}")

class PanicModeError(Exception):
    def __init__(self, data):
        self.data = data
        super().__init__(f"Panic Mode: {data['reason']}")

# Usage
client = MCPProxyClient('http://localhost:3000', 'my-app-v1.0')

try:
    result = client.call('get_user', {'userId': '123'})
    print('Success:', result)
except SecurityBlockError as e:
    print('Blocked:', e.data['findings'])
except PanicModeError as e:
    print('Panic Mode:', e.data)
except Exception as e:
    print('Error:', e)
```

---

### Monitoring Proxy Health

The proxy does not currently expose a dedicated health check endpoint. Monitor health by:

1. **Checking audit logs** for unusual block rates
2. **Monitoring latency** in audit log entries
3. **Tracking strike counts** per client
4. **Observing cache hit ratio** in audit logs

```bash
# Example: Calculate cache hit ratio
jq -s '[.[] | select(.cacheHit != null)] | group_by(.cacheHit) | map({cached: .[0].cacheHit, count: length})' audit.jsonl

# Output:
# [
#   {"cached": false, "count": 250},
#   {"cached": true, "count": 750}
# ]
# Cache hit ratio: 75%
```

---

### Performance Metrics

Expected latencies under normal operation:

| Metric                           | Target     | Notes                      |
| -------------------------------- | ---------- | -------------------------- |
| Layer 1 (Fast Rules)             | <10ms      | Pattern-based detection    |
| Layer 2 (Suspicious)             | <50ms      | Heuristic analysis         |
| Layer 3 (LLM)                    | 500-2000ms | External API call (opt-in) |
| Cache Hit                        | <1ms       | SHA-256 lookup             |
| Full Request (L1+L2, cache miss) | <60ms      | Most common case           |
| Full Request (L1+L2, cache hit)  | <2ms       | Ideal case                 |

**Throughput**: ~1000 requests/second (Layers 1+2 only, with cache)

---

### Rate Limiting

The proxy itself does not rate limit clients. Rate limiting is handled by:

1. **Panic Stop System**: Tracks MCP server 429 responses
2. **Classic Rate Limiter Guardrail**: Optional post-gateway rate limiting

To enable classic rate limiting:

```bash
node dist/mcp-verify.js proxy \
  --target "node my-server.js" \
  --rate-limit 100  # 100 requests/minute per tool
```

---

## 🎯 Documentation Best Practices

### 1. Write for Your Audience

```typescript
// ❌ Bad: Too technical, assumes knowledge
/**
 * Impl of SEC-001 rule for SQLI detection via regex pattern matching
 */

// ✅ Good: Clear, explains purpose
/**
 * Detects SQL injection vulnerabilities in tool descriptions.
 *
 * Analyzes tool definitions for patterns suggesting SQL queries with
 * user-controlled input, such as string concatenation or template
 * literals in SQL statements.
 */
```

### 2. Include Examples

````typescript
// ❌ Bad: No example
/**
 * Validates a tool definition.
 * @param tool - The tool to validate
 * @returns Validation result
 */

// ✅ Good: With example
/**
 * Validates a tool definition against the MCP specification.
 *
 * @param tool - The tool to validate
 * @returns Validation result indicating if the tool is valid
 *
 * @example
 * ```typescript
 * const tool = {
 *   name: 'my_tool',
 *   description: 'Does something useful',
 *   inputSchema: { type: 'object', properties: {} }
 * };
 *
 * const result = validateTool(tool);
 * if (!result.isValid) {
 *   console.error('Validation errors:', result.errors);
 * }
 * ```
 */
````

### 3. Document Edge Cases

````typescript
/**
 * Calculates security score from findings.
 *
 * @param findings - Array of security findings
 * @returns Score from 0-100, where 100 is perfect
 *
 * @remarks
 * - Returns 100 if findings array is empty
 * - Critical findings subtract 30 points each
 * - High severity findings subtract 15 points each
 * - Medium severity findings subtract 5 points each
 * - Score never goes below 0
 *
 * @example
 * ```typescript
 * const findings = [
 *   { severity: 'critical', message: '...' },
 *   { severity: 'high', message: '...' }
 * ];
 *
 * const score = calculateScore(findings);
 * // score === 55 (100 - 30 - 15)
 * ```
 */
function calculateScore(findings: SecurityFinding[]): number {
  // Implementation
}
````

### 4. Use Proper Type Annotations

```typescript
// ❌ Bad: Missing types in docs
/**
 * @param options - Configuration options
 * @returns The result
 */

// ✅ Good: Clear types
/**
 * @param options - Configuration options
 * @param options.timeout - Connection timeout in milliseconds
 * @param options.retries - Maximum retry attempts
 * @returns Promise resolving to the connection result
 */
function connect(options: {
  timeout: number;
  retries: number;
}): Promise<Result>;
```

### 5. Link Related Documentation

```typescript
/**
 * Base interface for security rules.
 *
 * @see {@link SqlInjectionRule} for SQL injection detection
 * @see {@link CommandInjectionRule} for command injection detection
 * @see {@link SecurityScanner} for how rules are orchestrated
 * @see [OWASP Top 10](https://owasp.org/www-project-top-ten/)
 */
export interface ISecurityRule {
  // ...
}
```

### 6. Document Deprecations

````typescript
/**
 * Legacy method for validation.
 *
 * @deprecated Use {@link validate} instead. This method will be removed in a future version.
 *
 * @example
 * Migration guide:
 * ```typescript
 * // Old (deprecated):
 * const result = validator.runValidation();
 *
 * // New:
 * const result = await validator.validate();
 * ```
 */
runValidation(): ValidationResult {
  // Implementation
}
````

---

## 📊 JSDoc Tags Reference

| Tag             | Purpose                | Example                        |
| --------------- | ---------------------- | ------------------------------ |
| `@param`        | Document parameters    | `@param name - User's name`    |
| `@returns`      | Document return value  | `@returns User object`         |
| `@throws`       | Document thrown errors | `@throws {Error} When invalid` |
| `@example`      | Show usage example     | See examples above             |
| `@see`          | Link related docs      | `@see {@link OtherClass}`      |
| `@category`     | Group in docs          | `@category Security`           |
| `@deprecated`   | Mark as deprecated     | `@deprecated Use newFunc`      |
| `@internal`     | Mark as internal       | `@internal`                    |
| `@defaultValue` | Default value          | `@defaultValue 5000`           |
| `@remarks`      | Additional notes       | `@remarks This is async`       |
| `@typeParam`    | Generic type param     | `@typeParam T - Item type`     |

---

## 🔍 Generating Documentation

### Generate Full API Docs

```bash
# Generate HTML documentation
npm run docs:generate

# Open in browser
npm run docs:serve
```

### Generate JSON Format

```bash
# Useful for custom documentation sites
npm run docs:json

# Output: docs/api.json
```

### Watch Mode

```bash
# Auto-regenerate on file changes
npm run docs:watch
```

---

## 📂 Documentation Structure

Generated docs will have this structure:

```
docs/api/
├── index.html              # Main entry point
├── modules/
│   ├── libs_core.html      # Core module
│   ├── libs_transport.html # Transport module
│   └── ...
├── classes/
│   ├── SqlInjectionRule.html
│   ├── MCPValidator.html
│   └── ...
├── interfaces/
│   ├── ITransport.html
│   ├── ISecurityRule.html
│   └── ...
├── functions/
│   └── ...
└── assets/
    ├── style.css
    └── search.js
```

---

## ✅ Documentation Checklist

Before submitting code, ensure:

- [ ] All public APIs have JSDoc comments
- [ ] Parameters are documented with types
- [ ] Return values are documented
- [ ] At least one `@example` is provided
- [ ] Edge cases are documented in `@remarks`
- [ ] Related functions linked with `@see`
- [ ] Proper `@category` tags used
- [ ] Error conditions documented with `@throws`
- [ ] Default values specified with `@defaultValue`
- [ ] Deprecated items marked with `@deprecated`

---

## 🎓 Additional Resources

- [TypeDoc Official Documentation](https://typedoc.org/)
- [TSDoc Standard](https://tsdoc.org/)
- [JSDoc Cheat Sheet](https://devhints.io/jsdoc)
- [TypeScript Handbook](https://www.typescriptlang.org/docs/handbook/intro.html)
