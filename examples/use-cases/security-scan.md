# 🛡️ Security Scanning Example

## What MCP Verify Checks

MCP Verify includes **4 security detection rules**:

1. **SEC-001**: Path Traversal Detection
2. **SEC-002**: Command Injection Detection
3. **SEC-003**: SSRF & Network Access
4. **SEC-004**: Sensitive Data Exposure

## Example: Detecting Path Traversal

### Vulnerable Server Example
```typescript
// ⚠️ BAD: Path parameter without validation
tools: [{
  name: 'read_file',
  inputSchema: {
    properties: {
      path: {
        type: 'string'
        // ❌ NO pattern validation!
      }
    }
  }
}]
```

### Running Security Scan
```bash
mcp-verify validate http://localhost:3000 --html
```

### Output
```
Security Audit:
Score: 60/100 (High Risk)
  • [CRITICAL] Tool "read_file" has path parameter "path" without validation pattern
  • [HIGH] Resource "logs" has dynamic URI without documented restrictions
```

### HTML Report Shows
```
Finding: SEC-001
Severity: CRITICAL
Message: Tool "read_file" has path parameter "path" without validation pattern
Evidence:
  - toolName: read_file
  - parameterName: path
  - hasPattern: false
Remediation:
  Add a regex pattern to validate the "path" parameter.
  Example: "^[a-zA-Z0-9_/-]+\\.txt$" to allow only safe filenames.
```

## Fix the Vulnerability

### ✅ GOOD: Add validation pattern
```typescript
tools: [{
  name: 'read_file',
  inputSchema: {
    properties: {
      path: {
        type: 'string',
        pattern: '^[a-zA-Z0-9_-]+\\.[a-z]{2,4}$'  // ✅ Safe!
      }
    }
  }
}]
```

### Verify the Fix
```bash
mcp-verify validate http://localhost:3000
```

### New Output
```
Security Audit:
Score: 95/100 (Low Risk)
  • No critical issues found
```

## Example: Command Injection

### Vulnerable Tool
```typescript
tools: [{
  name: 'execute_command',
  inputSchema: {
    properties: {
      cmd: {
        type: 'string'
        // ❌ Allows shell metacharacters!
      }
    }
  }
}]
```

### Detection
```
• [CRITICAL] Potential Command Injection: Parameter "cmd" lacks validation
  Remediation: Use whitelist regex like ^[a-zA-Z0-9]+$ to prevent shell metacharacters
```

### Fix
```typescript
{
  cmd: {
    type: 'string',
    pattern: '^(start|stop|restart)$'  // ✅ Whitelist only
  }
}
```

## Example: SSRF Detection

### Vulnerable Tool
```typescript
tools: [{
  name: 'fetch_url',
  inputSchema: {
    properties: {
      url: {
        type: 'string'
        // ❌ No domain restrictions!
      }
    }
  }
}]
```

### Detection
```
• [HIGH] Potential SSRF: Parameter "url" accepts URLs but lacks domain validation
  Remediation: Restrict to specific domains: ^https://api\\.example\\.com/
```

### Fix
```typescript
{
  url: {
    type: 'string',
    pattern: '^https://api\\.mycompany\\.com/.+$'  // ✅ Locked down
  }
}
```

## Example: Data Leakage

### Vulnerable Resource
```typescript
resources: [{
  name: 'env-vars',
  uri: 'file:///app/.env'  // ❌ Exposes secrets!
}]
```

### Detection
```
• [CRITICAL] Resource "env-vars" exposes a potentially sensitive file
  Evidence: Risky file extension/name (.env)
  Remediation: Do not expose configuration files with credentials
```

## Understanding the Security Score

```
Score: 100  → No issues (Low Risk)
Score: 90   → Minor warnings (Low Risk)
Score: 70   → Some medium issues (Medium Risk)
Score: 50   → Critical issues found (High Risk)
Score: < 50 → Multiple critical issues (High Risk)
```

### Score Calculation
- Start at 100 points
- Deduct for each finding:
  - Critical: -40 points
  - High: -25 points
  - Medium: -15 points
  - Low: -5 points

## Best Practices

### ✅ DO:
- **Always validate path parameters** with strict regex
- **Whitelist commands** instead of blacklisting
- **Lock down URLs** to specific domains
- **Never expose** `.env`, `.key`, `config.json` files
- **Use environment variables** for secrets, not tool parameters

### ❌ DON'T:
- Use `.*` or overly permissive patterns
- Allow arbitrary file paths
- Accept any URL without validation
- Expose system directories (`/etc`, `/var`, `C:\Windows`)
- Pass secrets as tool arguments

## CI/CD Integration

### GitHub Actions
```yaml
- name: Security Scan
  run: |
    mcp-verify validate http://localhost:3000 --format sarif
    # Fails if critical issues found
```

### Pre-commit Hook
```bash
#!/bin/bash
mcp-verify validate http://localhost:3000
if [ $? -ne 0 ]; then
  echo "❌ Security issues found. Fix before committing."
  exit 1
fi
```

## Real-World Example

### Before Security Scan
```typescript
// Filesystem MCP Server (vulnerable)
tools: [{
  name: 'write_file',
  inputSchema: {
    properties: {
      path: { type: 'string' },  // ❌ No validation
      content: { type: 'string' }
    }
  }
}]
```

**Score: 55/100 (High Risk)**

### After Hardening
```typescript
tools: [{
  name: 'write_file',
  inputSchema: {
    properties: {
      path: {
        type: 'string',
        pattern: '^/safe-dir/[a-zA-Z0-9_-]+\\.txt$'  // ✅ Restricted
      },
      content: {
        type: 'string',
        maxLength: 10000  // ✅ Size limit
      }
    }
  }
}]
```

**Score: 90/100 (Low Risk)**

## Next Steps

1. Run scan on your server
2. Review HTML report findings
3. Apply recommended fixes
4. Re-scan to verify
5. Integrate into CI/CD

## Get Help

If you see a security finding you don't understand:
```bash
# Open the HTML report - it has detailed explanations
open ./reportes/mcp-report-*.html
```

Or ask in [GitHub Discussions](https://github.com/FinkTech/mcp-verify/discussions)
