# 🛠️ Development Tools

Development utilities, mock servers, and automation scripts for **mcp-verify**.

---

## 📋 Purpose

This directory contains tools that help with:

- **Testing**: Mock MCP servers for validation
- **Development**: Build scripts, code generation
- **Maintenance**: i18n management, cleanup scripts
- **Quality Assurance**: Report generation, testing utilities

---

## 📁 Structure

```
tools/
├── mocks/                           # Mock MCP servers
│   └── servers/
│       ├── simple-server.js         # ✅ Valid server (score: 95+)
│       ├── vulnerable-server.js     # ⚠️ Insecure server (score: <50)
│       ├── broken-server.js         # ❌ Protocol violations
│       └── README.md                # Mock server documentation
│
└── scripts/                         # Development scripts
    ├── bundle.js                    # Bundle application
    ├── generate-report-preview.ts   # Generate HTML preview
    │
    ├── i18n/                        # Translation management
    │   ├── extract-i18n-strings.js  # Extract translatable strings
    │   ├── clean-i18n.js            # Remove unused keys
    │   ├── clean-i18n-v2.js         # Advanced cleanup
    │   ├── fix-i18n.js              # Fix formatting issues
    │   ├── verify_i18n.js           # Verify translation coverage
    │   ├── i18n_finder.js           # Find hardcoded strings
    │   ├── extract-translations.js  # Extract from code
    │   ├── translate-with-gemini.js # Auto-translate with Gemini
    │   └── translate-with-llm.js    # Auto-translate with LLM
    │
    └── translate/                   # Translation automation
        ├── index.js                 # Main translation script
        └── finalize_translation.js  # Finalize translations
```

---

## 🎭 Mock Servers

### Purpose

Mock servers simulate real MCP servers for testing mcp-verify functionality.

### Available Servers

#### 1. ✅ simple-server.js - Valid Reference

**Purpose**: Clean reference implementation

**Characteristics**:

- Follows all MCP protocol specifications
- Well-documented tools with proper schemas
- No security vulnerabilities
- Excellent quality

**Expected Scores**:

- **Security**: 95-100% (Excellent)
- **Quality**: 95-100% (Excellent)
- **Status**: ✅ VALID

**Tools**:

- `get_weather` - Get weather for a location
- `calculate` - Perform math operations

**Usage**:

```bash
# Test validation
mcp-verify validate "node tools/mocks/servers/simple-server.js"

# Expected output:
# ✅ Status: VALID
# 🔒 Security: 100/100 (Excellent)
# ⭐ Quality: 100/100
```

---

#### 2. ⚠️ vulnerable-server.js - Security Test

**Purpose**: Test security rule detection

**Characteristics**:

- Contains **intentional** security vulnerabilities
- Protocol-compliant (schema valid)
- Used for regression testing security rules

**Vulnerabilities**:
| Vulnerability | Rule | Severity |
|--------------|------|----------|
| SQL Injection | SEC-001 | Critical |
| Command Injection | SEC-002 | Critical |
| SSRF | SEC-003 | High |
| Path Traversal | SEC-005 | High |
| Data Leakage | SEC-004 | Medium |
| Sensitive Data Exposure | SEC-010 | Critical |
| XXE Injection | SEC-006 | High |
| Insecure Deserialization | SEC-007 | High |

**Expected Scores**:

- **Security**: 20-40% (LOW)
- **Critical Findings**: 4+
- **High Findings**: 3+
- **Status**: ❌ INVALID

**Usage**:

```bash
# Test security detection
mcp-verify validate "node tools/mocks/servers/vulnerable-server.js"

# Expected output:
# ❌ Status: INVALID
# 🔒 Security: 35/100 (LOW)
# ⚠️  4 CRITICAL findings
# ⚠️  3 HIGH findings
```

**Use Cases**:

- Verify SEC-001 through SEC-010 rules work
- Test SARIF report generation
- CI/CD integration testing
- Baseline comparison testing

---

#### 3. ❌ broken-server.js - Protocol Test

**Purpose**: Test protocol validation

**Characteristics**:

- Contains MCP protocol violations
- Invalid JSON-RPC responses
- Schema errors
- Used for protocol compliance testing

**Issues**:

- Missing required fields (tool names, descriptions)
- Invalid JSON-RPC responses
- Wrong protocol version (`2023-01-01` instead of `2024-11-05`)
- Malformed schemas
- Invalid URI formats
- Inconsistent response structures

**Expected Results**:

- **Schema Valid**: ❌ false
- **Protocol Compliance**: Failed
- **Status**: ❌ INVALID

**Usage**:

```bash
# Test protocol validation
mcp-verify validate "node tools/mocks/servers/broken-server.js"

# Expected output:
# ❌ Status: INVALID
# ❌ Schema validation failed
# ❌ Protocol compliance issues detected
```

---

### Testing Workflow with Mocks

#### Workflow 1: Validate All Three Servers

```bash
# Valid server (baseline)
mcp-verify validate "node tools/mocks/servers/simple-server.js" \
  --output ./test-results/simple

# Vulnerable server (security testing)
mcp-verify validate "node tools/mocks/servers/vulnerable-server.js" \
  --output ./test-results/vulnerable

# Broken server (protocol testing)
mcp-verify validate "node tools/mocks/servers/broken-server.js" \
  --output ./test-results/broken
```

#### Workflow 2: Compare Security Scores

```bash
# Extract security scores
jq '.security.score' \
  ./test-results/simple/json/mcp-report-*.json \
  ./test-results/vulnerable/json/mcp-report-*.json

# Expected:
# 100  (simple)
# 35   (vulnerable)
```

#### Workflow 3: CI/CD Integration Testing

```bash
# Test exit codes
mcp-verify validate "node tools/mocks/servers/simple-server.js"
echo $?  # Expected: 0 (success)

mcp-verify validate "node tools/mocks/servers/vulnerable-server.js"
echo $?  # Expected: 2 (critical findings)

mcp-verify validate "node tools/mocks/servers/broken-server.js"
echo $?  # Expected: 1 (validation failure)
```

---

## 📜 Development Scripts

### Bundle Script (`scripts/bundle.js`)

**Purpose**: Bundle application for distribution

**Usage**:

```bash
node tools/scripts/bundle.js
```

**What it does**:

- Bundles CLI application
- Minifies code
- Creates distributable package

---

### Generate Report Preview (`scripts/generate-report-preview.ts`)

**Purpose**: Generate HTML preview of report

**Usage**:

```bash
npx tsx tools/scripts/generate-report-preview.ts
```

**What it does**:

- Loads sample report JSON
- Generates HTML preview
- Opens in browser for visual testing

**Use Case**: Testing HTML report generator changes

---

## 🌐 i18n Scripts

### Overview

Translation management scripts for maintaining English ↔ Spanish translations.

---

### Extract i18n Strings (`scripts/extract-i18n-strings.js`)

**Purpose**: Extract translatable strings from code

**Usage**:

```bash
node tools/scripts/extract-i18n-strings.js
```

**What it does**:

- Scans codebase for `t('key')` calls
- Lists all i18n keys used
- Identifies missing translations

**Output**:

```
Found keys:
- validation_complete
- server_found
- security_audit
...

Missing translations: 5
```

---

### Find Hardcoded Strings (`scripts/i18n_finder.js`)

**Purpose**: Find hardcoded strings that should use i18n

**Usage**:

```bash
node tools/scripts/i18n_finder.js
```

**What it does**:

- Scans source files for hardcoded strings
- Identifies user-facing messages
- Suggests keys for translation

**Output**:

```
Found hardcoded strings:

File: apps/cli-verifier/src/commands/validate.ts
Line 45: console.log('Validation complete');
Suggest: t('validation_complete')

File: libs/core/domain/security/rules/sql-injection.ts
Line 23: message: 'SQL injection detected'
Suggest: t('sql_injection_detected')
```

---

### Clean i18n (`scripts/clean-i18n.js`, `scripts/clean-i18n-v2.js`)

**Purpose**: Remove unused translation keys

**Usage**:

```bash
# Version 1 (basic cleanup)
node tools/scripts/clean-i18n.js

# Version 2 (advanced cleanup)
node tools/scripts/clean-i18n-v2.js
```

**What it does**:

- Scans codebase for `t('key')` usage
- Identifies unused keys in `i18n.ts`
- Removes orphaned translations

**Output**:

```
Scanning codebase for i18n usage...
Found 245 used keys
Found 312 total keys
Removing 67 unused keys...
✓ Done! Cleaned i18n.ts
```

---

### Verify i18n (`scripts/verify_i18n.js`)

**Purpose**: Verify translation coverage and consistency

**Usage**:

```bash
node tools/scripts/verify_i18n.js
```

**What it does**:

- Checks all keys have English translation
- Checks all keys have Spanish translation
- Validates parameter substitution consistency
- Reports coverage percentage

**Output**:

```
Checking i18n coverage...

✓ English: 312/312 keys (100%)
⚠️  Spanish: 305/312 keys (97.8%)

Missing Spanish translations:
- llm_analysis_using
- llm_semantic_check_deprecated
- llm_continuing_without
...

Parameter mismatch:
- server_found: EN uses {name}, ES uses {nombre}
```

---

### Auto-Translate (`scripts/translate-with-gemini.js`, `scripts/translate-with-llm.js`)

**Purpose**: Automatically translate missing keys using LLM

**Usage**:

```bash
# Using Gemini
GEMINI_API_KEY=xxx node tools/scripts/translate-with-gemini.js

# Using generic LLM
ANTHROPIC_API_KEY=xxx node tools/scripts/translate-with-llm.js
```

**What it does**:

- Identifies missing translations
- Uses LLM to translate keys
- Preserves parameter placeholders (`{name}`, etc.)
- Updates `i18n.ts` automatically

**Output**:

```
Found 7 keys to translate (EN → ES)...

Translating: llm_analysis_using
EN: "🧠 LLM analysis: {provider}"
ES: "🧠 Análisis LLM: {provider}"

Translating: llm_semantic_check_deprecated
EN: "⚠️  --semantic-check is deprecated..."
ES: "⚠️  --semantic-check está obsoleto..."

✓ Translated 7 keys
✓ Updated libs/core/domain/reporting/i18n.ts
```

---

### Finalize Translation (`scripts/translate/finalize_translation.js`)

**Purpose**: Review and finalize auto-translated keys

**Usage**:

```bash
node tools/scripts/translate/finalize_translation.js
```

**What it does**:

- Shows auto-translated keys for review
- Allows manual correction
- Commits final translations

---

## 🔧 Common Tasks

### Task 1: Add a New Mock Server

**Time**: ~1 hour
**Difficulty**: Intermediate

**Steps**:

#### 1. Create Server File

```bash
touch tools/mocks/servers/my-server.js
chmod +x tools/mocks/servers/my-server.js
```

#### 2. Implement MCP Protocol

```javascript
#!/usr/bin/env node

const readline = require("readline");

const serverInfo = {
  name: "my-test-server",
  version: "1.0.0",
};

const tools = [
  {
    name: "my_tool",
    description: "Clear description",
    inputSchema: {
      type: "object",
      properties: {
        param: { type: "string", description: "Param description" },
      },
      required: ["param"],
    },
  },
];

function handleMessage(message) {
  const { jsonrpc, id, method } = message;

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

    default:
      return {
        jsonrpc: "2.0",
        id,
        error: { code: -32601, message: "Method not found" },
      };
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

#### 3. Test Server

```bash
# Test manually
node tools/mocks/servers/my-server.js

# Send test message
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | node tools/mocks/servers/my-server.js

# Test with mcp-verify
mcp-verify validate "node tools/mocks/servers/my-server.js"
```

#### 4. Document in tools/mocks/servers/README.md

Add entry describing your server's purpose and expected results.

---

### Task 2: Create a Development Script

**Time**: ~30 minutes
**Difficulty**: Beginner

**Steps**:

#### 1. Create Script File

```javascript
// tools/scripts/my-script.js

#!/usr/bin/env node

/**
 * My Script - Brief description
 *
 * Usage: node tools/scripts/my-script.js [options]
 */

const fs = require('fs');
const path = require('path');

function main() {
  console.log('Running my script...');

  // Implementation
  const projectRoot = path.join(__dirname, '..', '..');
  const targetFile = path.join(projectRoot, 'target.json');

  // Do something useful
  const data = fs.readFileSync(targetFile, 'utf-8');
  const json = JSON.parse(data);

  console.log('Processed:', Object.keys(json).length, 'items');
}

// Run
main();
```

#### 2. Make Executable

```bash
chmod +x tools/scripts/my-script.js
```

#### 3. Test

```bash
node tools/scripts/my-script.js
```

#### 4. Document in tools/README.md

Add entry to the "Development Scripts" section.

---

## 🧪 Testing Tools

### Test Mock Server Manually

```bash
# Start server
node tools/mocks/servers/simple-server.js

# In another terminal, send JSON-RPC messages
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | node tools/mocks/servers/simple-server.js

# Expected response:
# {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05",...}}
```

### Test with mcp-verify

```bash
# Build first
npm run build

# Test validation
mcp-verify validate "node tools/mocks/servers/simple-server.js"

# Test with all options
mcp-verify validate "node tools/mocks/servers/vulnerable-server.js" \
  --html \
  --format sarif \
  --llm ollama:llama3.2 \
  --verbose
```

---

## 📊 Mock Server Testing Matrix

| Server                   | Schema     | Security | Quality | Exit Code |
| ------------------------ | ---------- | -------- | ------- | --------- |
| **simple-server.js**     | ✅ Valid   | 95-100   | 95-100  | 0         |
| **vulnerable-server.js** | ✅ Valid   | 20-40    | 60-80   | 2         |
| **broken-server.js**     | ❌ Invalid | N/A      | N/A     | 1         |

---

## 🔗 Related Documentation

- **[DEVELOPMENT.md](../DEVELOPMENT.md)** - Local development guide
- **[TESTING.md](../TESTING.md)** - Testing strategy
- **[CODE_MAP.md](../CODE_MAP.md)** - Codebase navigation
- **[tools/mocks/servers/README.md](./mocks/servers/README.md)** - Mock server details

---

## 💡 Tips & Best Practices

### Tip 1: Use Mock Servers for CI/CD

```yaml
# .github/workflows/test.yml
- name: Test with mock servers
  run: |
    npm run build
    mcp-verify validate "node tools/mocks/servers/simple-server.js"
    mcp-verify validate "node tools/mocks/servers/vulnerable-server.js" || true  # Expected to fail
```

---

### Tip 2: Keep i18n Clean

```bash
# Before committing i18n changes
node tools/scripts/verify_i18n.js
node tools/scripts/clean-i18n-v2.js

# Ensure 100% coverage
git diff libs/core/domain/reporting/i18n.ts
```

---

### Tip 3: Generate Report Previews

```bash
# After changing HTML generator
npx tsx tools/scripts/generate-report-preview.ts

# Opens browser with preview
# Check styling, layout, responsiveness
```

---

## 🆘 Common Issues

### Issue 1: Mock server won't start

**Cause**: Node.js version or permissions
**Solution**:

```bash
# Check Node version
node --version  # Requires 18.x+

# Make executable
chmod +x tools/mocks/servers/*.js

# Run directly
node tools/mocks/servers/simple-server.js
```

---

### Issue 2: i18n script fails

**Cause**: Missing dependencies or syntax errors
**Solution**:

```bash
# Reinstall dependencies
npm install

# Check syntax
node --check tools/scripts/verify_i18n.js

# Run with error output
node tools/scripts/verify_i18n.js 2>&1
```

---

### Issue 3: Translation parameter mismatch

**Problem**: English uses `{name}`, Spanish uses `{nombre}`
**Solution**: Use same parameter names in all languages

```typescript
// ❌ BAD
en: "Server found: {name}";
es: "Servidor encontrado: {nombre}";

// ✅ GOOD
en: "Server found: {name}";
es: "Servidor encontrado: {name}";
```

---
