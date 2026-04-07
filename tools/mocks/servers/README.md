# Mock MCP Servers

These are test MCP servers for validating mcp-verify functionality.

## Available Servers

### 1. simple-server.js ✅

**A clean, valid MCP server**

- Follows all MCP protocol specifications
- Includes well-documented tools with proper schemas
- Should pass all mcp-verify validations
- **Security Score**: ~95-100%
- **Quality Score**: ~95-100%

**Tools**:

- `get_weather` - Get weather for a location
- `calculate` - Perform math operations

**Usage**:

```bash
# Test with mcp-verify CLI
node dist/mcp-verify.js validate --server "node tools/mocks/servers/simple-server.js"

# Test with MCP Server wrapper
# (Call validateServer tool with command: "node" and args: ["tools/mocks/servers/simple-server.js"])
```

---

### 2. vulnerable-server.js ⚠️

**A server with intentional security vulnerabilities**

Contains multiple security issues for testing detection:

| Vulnerability            | Rule Code | Severity |
| ------------------------ | --------- | -------- |
| SQL Injection            | SEC-003   | Critical |
| Command Injection        | SEC-002   | Critical |
| SSRF                     | SEC-004   | Critical |
| Data Leakage             | SEC-008   | High     |
| Path Traversal           | SEC-007   | Critical |
| Sensitive Data Exposure  | SEC-009   | High     |
| XXE Injection            | SEC-005   | High     |
| Insecure Deserialization | SEC-006   | High     |

**Expected Results**:

- **Security Score**: ~20-40% (LOW)
- **Critical Findings**: 4+
- **High Findings**: 3+
- **Status**: INVALID

**Usage**:

```bash
# Should detect multiple security issues
node dist/mcp-verify.js validate --server "node tools/mocks/servers/vulnerable-server.js"
```

---

### 3. broken-server.js ❌

**A server with protocol violations**

Contains multiple MCP protocol issues:

**Issues**:

- Missing required fields (tool names, descriptions)
- Invalid JSON-RPC responses
- Wrong protocol version (2023-01-01 instead of 2024-11-05)
- Malformed schemas
- Invalid URI formats
- Inconsistent response structures

**Expected Results**:

- **Schema Valid**: false
- **Protocol Compliance**: Failed tests
- **Status**: INVALID

**Usage**:

```bash
# Should detect protocol violations
node dist/mcp-verify.js validate --server "node tools/mocks/servers/broken-server.js"
```

---

## Testing Workflow

### 1. Test Individual Servers

```bash
# Valid server (should pass)
node dist/mcp-verify.js validate \
  --server "node tools/mocks/servers/simple-server.js" \
  --output simple-report.json

# Vulnerable server (should fail security)
node dist/mcp-verify.js validate \
  --server "node tools/mocks/servers/vulnerable-server.js" \
  --output vulnerable-report.json

# Broken server (should fail schema/protocol)
node dist/mcp-verify.js validate \
  --server "node tools/mocks/servers/broken-server.js" \
  --output broken-report.json
```

### 2. Compare Results

```bash
# View security scores
jq '.security.score' simple-report.json vulnerable-report.json broken-report.json

# View findings
jq '.security.findings' vulnerable-report.json
```

### 3. Test with MCP Server Wrapper

If you're using mcp-verify as an MCP server (FASE 3), configure it:

```json
{
  "mcpServers": {
    "mcp-verify": {
      "command": "node",
      "args": ["./apps/mcp-server/dist/apps/mcp-server/src/index.js"]
    }
  }
}
```

Then call tools:

```typescript
// Validate simple server
tools/call validateServer {
  "command": "node",
  "args": ["./tools/mocks/servers/simple-server.js"]
}

// Scan vulnerable server for security issues
tools/call scanSecurity {
  "command": "node",
  "args": ["./tools/mocks/servers/vulnerable-server.js"]
}

// Analyze quality of simple server
tools/call analyzeQuality {
  "command": "node",
  "args": ["./tools/mocks/servers/simple-server.js"]
}
```

---

## Expected Validation Matrix

| Server               | Schema Valid | Security Score | Quality Score | Status     |
| -------------------- | ------------ | -------------- | ------------- | ---------- |
| simple-server.js     | ✅ Yes       | 95-100%        | 95-100%       | ✅ VALID   |
| vulnerable-server.js | ✅ Yes       | 20-40%         | 60-80%        | ❌ INVALID |
| broken-server.js     | ❌ No        | N/A            | N/A           | ❌ INVALID |

---

## Creating Your Own Mock Server

Template:

```javascript
#!/usr/bin/env node

const readline = require("readline");

const serverInfo = {
  name: "my-server",
  version: "1.0.0",
};

const tools = [
  {
    name: "my_tool",
    description: "Clear description of what this tool does",
    inputSchema: {
      type: "object",
      properties: {
        param: {
          type: "string",
          description: "Parameter description",
        },
      },
      required: ["param"],
    },
  },
];

function handleMessage(message) {
  const { jsonrpc, id, method, params } = message;

  switch (method) {
    case "initialize":
      return {
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: "2024-11-05",
          capabilities: { tools: {} },
          serverInfo,
        },
      };

    case "tools/list":
      return {
        jsonrpc: "2.0",
        id,
        result: { tools },
      };

    // ... handle other methods
  }
}

// Stdio server setup
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false,
});

rl.on("line", (line) => {
  try {
    const message = JSON.parse(line);
    const response = handleMessage(message);
    console.log(JSON.stringify(response));
  } catch (error) {
    console.log(
      JSON.stringify({
        jsonrpc: "2.0",
        id: null,
        error: { code: -32700, message: "Parse error" },
      }),
    );
  }
});
```

---

## Troubleshooting

### Server won't start

```bash
# Check Node.js version
node --version  # Should be >= 18.0.0

# Make server executable (Unix/Mac)
chmod +x tools/mocks/servers/*.js

# Run directly
node tools/mocks/servers/simple-server.js
```

### Can't connect

- Ensure server is running via stdio (stdin/stdout)
- Check that JSON-RPC messages are newline-delimited
- Verify server responds to `initialize` method

### Validation fails unexpectedly

- Check server logs for errors
- Verify JSON-RPC 2.0 compliance
- Ensure all required fields are present
- Validate schema structures

---

## Contributing

Want to add more mock servers? Consider:

- **performance-server.js** - For stress testing
- **timeout-server.js** - Tests timeout handling
- **malicious-server.js** - Advanced attack scenarios
- **legacy-server.js** - Old protocol version testing

Follow the existing patterns and document expected behavior.
