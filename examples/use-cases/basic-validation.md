# 📋 Basic Validation Example

## Scenario
You've just created an MCP server and want to verify it follows the protocol correctly.

## Step 1: Start Your Server
```bash
# Your MCP server (example)
npm start
# Now listening on http://localhost:3000
```

## Step 2: Run Basic Validation
```bash
mcp-verify validate http://localhost:3000
```

## Expected Output
```
✓ Connecting via HTTP...
✓ Testing protocol handshake...
✓ Discovering tools and resources...
✓ Validating schema compliance...
✓ Generating report...
✓ Validation complete!

Validation Report:
──────────────────────────────────────────────────
Server: my-mcp-server
Status: ✓ VALID
Protocol: 2024-11-05
Tools: 5 (5 valid)
Resources: 2 (2 valid)
Duration: 127ms

Security Audit:
Score: 85/100 (Medium Risk)
  • [MEDIUM] Filesystem modification detected in tool

──────────────────────────────────────────────────
JSON: ./reportes/mcp-report-2026-01-20T12-30-45.json
HTML: ./reportes/mcp-report-2026-01-20T12-30-45.html
```

## Step 3: View HTML Report
```bash
# Open the HTML report in your browser
open ./reportes/mcp-report-2026-01-20T12-30-45.html

# On Windows:
start ./reportes/mcp-report-2026-01-20T12-30-45.html
```

## What Gets Validated?

### ✅ Protocol Handshake
- `initialize` method works
- Returns `protocolVersion`
- Returns `serverInfo` with name and version

### ✅ Tool Discovery
- `tools/list` returns array
- Each tool has valid schema:
  - `name` (required, string)
  - `description` (optional)
  - `inputSchema` (optional, JSON Schema)

### ✅ Resource Discovery
- `resources/list` returns array
- Each resource has:
  - `name` (required)
  - `uri` (required)
  - `mimeType` (optional)

### ✅ Schema Compliance
- All JSON-RPC 2.0 fields present
- No unknown/invalid fields
- Proper error handling

## Next Steps

### 1. Fix Any Issues
If validation found problems, check the HTML report for details:
- Red findings = Critical issues
- Yellow findings = Warnings
- Green = All good

### 2. Run Security Scan
```bash
# Already included in basic validation
# Check the "Security Audit" section
```

### 3. Stress Test
Once basic validation passes, test performance:
```bash
mcp-verify stress http://localhost:3000
```

## Common Issues

### ❌ "Failed to connect"
**Problem:** Server isn't running or wrong URL

**Solutions:**
- Check server is actually running: `curl http://localhost:3000`
- Verify the port number
- Try: `mcp-verify doctor http://localhost:3000`

### ❌ "Protocol version mismatch"
**Problem:** Server uses old/unknown MCP version

**Solution:**
- Update your MCP server library
- Check your `protocolVersion` response

### ❌ "Tools invalid"
**Problem:** Tool schema doesn't match spec

**Solution:**
- Each tool needs at minimum a `name` field
- Check the detailed error in HTML report
- Fix the tool definition in your server code

## Tips

💡 **Use verbose mode for debugging:**
```bash
mcp-verify validate http://localhost:3000 --verbose
```

💡 **Generate different formats:**
```bash
# JSON only (for scripts)
mcp-verify validate http://localhost:3000

# HTML report (for humans)
mcp-verify validate http://localhost:3000 --html

# SARIF (for GitHub)
mcp-verify validate http://localhost:3000 --format sarif
```

💡 **Test locally during development:**
```bash
# Watch mode (not built-in yet, but you can script it)
while true; do
  mcp-verify validate http://localhost:3000
  sleep 5
done
```
