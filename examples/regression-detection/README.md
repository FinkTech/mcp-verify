# 🔄 Regression Detection Examples

This directory contains practical examples showing how to use regression detection to catch security degradation between code changes.

## 📁 Files

| File                       | Description                                        |
| -------------------------- | -------------------------------------------------- |
| `demo-server.js`           | Simple MCP server (v1.0 - secure)                  |
| `demo-server-v2.js`        | Same server with vulnerabilities (v2.0 - insecure) |
| `demo.sh`                  | Interactive demo showing full workflow             |
| `1-create-baseline.sh`     | Create a baseline from v1.0                        |
| `2-detect-regression.sh`   | Detect regression in v2.0                          |
| `3-compare-scans.sh`       | Compare two scans manually                         |
| `4-view-history.sh`        | View scan history and trends                       |
| `ci-cd/github-actions.yml` | GitHub Actions example                             |
| `ci-cd/pre-commit-hook.sh` | Git pre-commit hook                                |

---

## 🚀 Quick Start

### Run the Full Demo

```bash
# From examples/regression-detection/
./demo.sh
```

This will:

1. Start the secure v1.0 server
2. Create a baseline scan
3. Switch to insecure v2.0
4. Detect regression automatically
5. Show comparison and history

---

## 📖 Step-by-Step Workflow

### Step 1: Create Baseline

```bash
# Start secure server
node demo-server.js &
SERVER_PID=$!

# Scan and mark as baseline
../../node_modules/.bin/ts-node ../../apps/cli-verifier/src/bin/index.ts validate stdio://node demo-server.js --set-baseline

# Or with built CLI:
node ../../dist/mcp-verify.js validate stdio://node demo-server.js --set-baseline

kill $SERVER_PID
```

**Output:**

```
✓ Scan saved as baseline: scan_2025-01-21T16-30-00_abc123
```

---

### Step 2: Detect Regression

```bash
# Start insecure server (v2.0 with vulnerabilities)
node demo-server-v2.js &
SERVER_PID=$!

# Compare against baseline
node ../../dist/mcp-verify.js validate stdio://node demo-server-v2.js --compare-baseline

kill $SERVER_PID
```

**Output:**

```
📊 Regression Analysis:
──────────────────────────────────────────────────
  ⛔ BLOCKING ISSUES DETECTED

Security score degraded from 95 to 45 (-50).
3 new CRITICAL issue(s) detected.

⚠️  New Issues (3):
  • [CRITICAL] Command injection in execute_command
  • [CRITICAL] Path traversal in read_file
  • [HIGH] Missing input validation

⛔ BLOCKING: Critical issues must be fixed before deployment
```

**Exit code:** `2` (blocking)

---

### Step 3: View History

```bash
# List all scans
node ../../dist/mcp-verify.js history

# Show trend analysis
node ../../dist/mcp-verify.js history --trend

# Filter by server
node ../../dist/mcp-verify.js history --server demo-mcp-server
```

**Output:**

```
📋 Scan History (2 scans)

1. scan_2025-01-21T16-30-00_abc123 [BASELINE]
   Server:   demo-mcp-server v1.0.0
   Security: 95/100  Quality: 90/100
   Findings: 0C 0H 1M 2L

2. scan_2025-01-21T16-35-00_def456
   Server:   demo-mcp-server v2.0.0
   Security: 45/100  Quality: 85/100
   Findings: 3C 1H 2M 1L

📈 Trend Analysis
Trend:             ↘ Degrading
Avg Security:      70.0/100
```

---

### Step 4: Compare Specific Scans

```bash
# Get scan IDs from history
node ../../dist/mcp-verify.js history

# Compare two specific scans
node ../../dist/mcp-verify.js diff scan_abc123 scan_def456
```

---

## 🔧 CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/mcp-security.yml
name: MCP Security Check

on: [pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-node@v2

      - name: Install mcp-verify
        run: npm install -g mcp-verify

      - name: Run Security Regression Check
        run: |
          mcp-verify validate ./mcp-server --compare-baseline
        continue-on-error: true

      - name: Comment on PR
        if: failure()
        run: echo "Security degradation detected!"
```

Full example: [ci-cd/github-actions.yml](./ci-cd/github-actions.yml)

---

### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

if git diff --cached --name-only | grep -q 'src/mcp-server'; then
  echo "🔍 Running MCP security check..."

  mcp-verify validate ./mcp-server --compare-baseline --quiet

  if [ $? -eq 2 ]; then
    echo "❌ BLOCKING: Critical security issues detected"
    exit 1
  fi
fi
```

Full example: [ci-cd/pre-commit-hook.sh](./ci-cd/pre-commit-hook.sh)

---

## 🎯 What Each Example Demonstrates

### `demo-server.js` (Secure)

- Proper input validation
- Safe command execution
- No path traversal
- **Security Score:** ~95/100

### `demo-server-v2.js` (Vulnerable)

- Missing input validation
- Command injection vulnerability
- Path traversal risk
- **Security Score:** ~45/100

**Purpose:** Show how regression detection catches these issues automatically.

---

## 💡 Best Practices

### 1. Set Baseline on Stable Releases

```bash
git tag v1.0.0
mcp-verify validate ./server --set-baseline
```

### 2. Always Compare in CI

```bash
# In your CI pipeline
mcp-verify validate ./server --compare-baseline || exit 1
```

### 3. Review History Regularly

```bash
# Weekly security review
mcp-verify history --trend
```

### 4. Use Exit Codes

```bash
mcp-verify validate ./server --compare-baseline
EXIT_CODE=$?

if [ $EXIT_CODE -eq 2 ]; then
  echo "Blocking issues - cannot deploy"
  exit 1
elif [ $EXIT_CODE -eq 1 ]; then
  echo "Warning - review required"
  # Optional: proceed with manual approval
fi
```

---

## 🐛 Troubleshooting

### "No baseline found"

```bash
# Create one first
mcp-verify validate ./server --set-baseline
```

### "Scan not found"

```bash
# List available scans
mcp-verify history

# Use correct scan ID
mcp-verify diff scan_2025-01-21T16-30-00_abc123 scan_2025-01-21T16-35-00_def456
```

### Clear history

```bash
rm -rf .mcp-verify/history/
```

---

## 📚 More Resources

- [Full Regression Detection Guide](../../REGRESSION-DETECTION.md)
- [Main Documentation](../../README.md)
- [CI/CD Best Practices](./ci-cd/)

---

## 🎉 Next Steps

1. Run `./demo.sh` to see it in action
2. Try creating your own baseline
3. Integrate into your CI/CD pipeline
4. Share feedback at [GitHub Issues](https://github.com/FinkTech/mcp-verify/issues)
