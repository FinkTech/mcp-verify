# 📚 MCP Verify Examples

Quick examples to get you started with MCP Verify.

## 🆕 NEW: Regression Detection

Detect security degradation between code changes - perfect for CI/CD!

```bash
# Try the interactive demo
cd regression-detection
./demo.sh
```

[📖 Full Guide](./regression-detection/) | [📄 Documentation](../REGRESSION-DETECTION.md)

---

## 🚀 Quick Start

### 1. Basic Validation
```bash
# Validate a local server
mcp-verify validate http://localhost:3000

# Validate with HTML report
mcp-verify validate http://localhost:3000 --html
```

### 2. Security Scan
```bash
# Run full security audit
mcp-verify validate http://localhost:3000 --html

# Check the HTML report for:
# - Path Traversal vulnerabilities
# - Command Injection risks
# - SSRF detection
# - Data Leakage warnings
```

### 3. Stress Testing
```bash
# Light load test (5 users, 10 seconds)
mcp-verify stress http://localhost:3000

# Heavy load test (50 users, 60 seconds)
mcp-verify stress http://localhost:3000 --users 50 --duration 60

# Check for:
# - P95/P99 latency
# - Throughput (req/sec)
# - Error rates
```

### 4. Interactive Playground
```bash
# Test tools interactively
mcp-verify play http://localhost:3000

# You can:
# - List all available tools
# - Execute tools with custom inputs
# - Test prompts
# - Debug responses
```

### 5. CI/CD Integration
```bash
# Generate SARIF report for GitHub
mcp-verify validate http://localhost:3000 --format sarif

# Upload to GitHub Code Scanning:
# - Commit the .sarif file
# - GitHub will show security alerts automatically
```

## 📁 Example Servers

### Test Against Dummy Server
```bash
# Terminal 1: Start dummy server
node examples/servers/dummy-server.js

# Terminal 2: Validate it
mcp-verify validate http://localhost:3000
```

### Test Against Broken Server (for testing)
```bash
# Terminal 1: Start broken server
node examples/servers/broken-server.js

# Terminal 2: See how mcp-verify handles errors
mcp-verify validate http://localhost:3000
```

## 🔧 Advanced Usage

### Fuzzing (Chaos Testing)
```bash
# Run chaos tests to find edge cases
mcp-verify validate http://localhost:3000 --fuzz

# This will:
# - Send malformed inputs
# - Test boundary conditions
# - Look for crashes
```

### Proxy Mode (Security Gateway)
```bash
# Start security proxy
mcp-verify proxy http://localhost:3000 --port 8080

# Then connect your LLM to: http://localhost:8080/sse
# The proxy will:
# - Block dangerous commands
# - Log all requests
# - Add safety guardrails
```

### Mock Server
```bash
# Start a mock MCP server for testing
mcp-verify mock --port 3000

# Useful for:
# - Testing your validator logic
# - Demos and tutorials
# - Development without real servers
```

## 📖 More Examples

See the `use-cases/` directory for detailed examples:
- [Basic Validation](./use-cases/basic-validation.md)
- [Security Scanning](./use-cases/security-scan.md)
- [Load Testing](./use-cases/stress-testing.md)
- [CI/CD Setup](./use-cases/ci-cd-integration.md)

## 🆘 Troubleshooting

### Connection Issues?
```bash
# Diagnose connection problems
mcp-verify doctor http://localhost:3000
```

### Need Help?
```bash
# Interactive mode
mcp-verify

# Then type: help
```

## 🔗 Learn More

- [Documentation](../docs/)
- [GitHub](https://github.com/FinkTech/mcp-verify)
- [Report Issues](https://github.com/FinkTech/mcp-verify/issues)
