# 🛠️ Troubleshooting Guide

Central reference for diagnosing and resolving issues in `mcp-verify`. Before opening a GitHub issue, work through the relevant section below.

> **First step for any problem:** Run `mcp-verify doctor [target]` — it checks your Node.js version, Git, Deno, connectivity, and binary integrity in one pass. See the [Doctor Command section](#-the-doctor-command) for details.

---

## Table of Contents

- [🛠️ The Doctor Command](#-the-doctor-command)
- [🌐 Connection & Network Issues](#-connection--network-issues)
- [🤖 LLM & AI Integration](#-llm--ai-integration)
- [📜 Protocol & Schema Errors](#-protocol--schema-errors)
- [🔒 Sandbox & Environment](#-sandbox--environment)
- [🗂️ Permissions & File System](#️-permissions--file-system)
- [⚙️ CI/CD Failures](#️-cicd-failures)
- [🆘 Getting Help](#-getting-help)

---

## 🛠️ The Doctor Command

`mcp-verify doctor` is the primary diagnostic tool. It should be your **first action** when something isn't working. It runs a full environment check and, if a `target` is provided, also probes the server directly.

### Usage

```bash
# Check local environment only (Node, Git, Deno, binary integrity)
mcp-verify doctor

# Full check: local environment + connectivity to a specific server
mcp-verify doctor "node server.js"
mcp-verify doctor http://localhost:3000

# Real-time monitoring mode (re-runs checks every few seconds)
mcp-verify doctor "node server.js" --watch

# Verbose output (shows every diagnostic step)
mcp-verify doctor "node server.js" --verbose
```

### What Doctor Checks

| Check | What it verifies | Required |
|---|---|---|
| **Node.js Runtime** | Version ≥ 18 installed | ✅ Always |
| **Git CLI** | Installed for version control operations | Optional |
| **Deno Runtime** | Installed (needed for `--sandbox` mode) | Optional |
| **Python Runtime** | Installed (needed for Python-based MCP servers) | Optional |
| **Binary Integrity** | SHA-256 checksum matches the build manifest | ✅ Always |
| **Build Age** | Warns if the build is older than 30 days | ✅ Always |
| **Port / Connectivity** | Can the target server be reached? | When target given |
| **DNS Resolution** | Is the hostname resolvable? | When target given |

### Reading Doctor Output

```
✅  Node.js Runtime      Installed (v20.11.0)
✅  Git CLI              Installed (v2.43.0)
⚠️  Deno Runtime         Not found
    → Deno is optional. Required only for --sandbox mode.
    → Install Deno: https://deno.land/
✅  Binary Integrity     Binary is authentic
⚠️  Build Age            Build is older than 30 days
✅  Port 3000            Reachable
```

- ✅ = check passed
- ⚠️ = warning (non-critical, but worth reviewing)
- ❌ = failure (likely root cause of your issue)

### Integrity Breach

If `doctor` reports `INTEGRITY BREACH: Binary has been modified!`, the local binary does not match the expected SHA-256 hash. This means the installation may be corrupted or tampered with.

```bash
# Regenerate the integrity manifest without a full rebuild
mcp-verify doctor --fix-integrity

# View integrity check history (last 20 builds)
mcp-verify doctor --show-history

# Clean up old history, keep only last N entries
mcp-verify doctor --clean-history 5
```

---

## 🌐 Connection & Network Issues

### Error: `Connection Failed` / `ECONNREFUSED`

**What it means:** The TCP connection to the target port was actively refused. The server is not listening on that address and port.

**Symptoms:**
```
✗ Connection Failed
  Failed to connect to MCP server at http://localhost:3000
  Tips:
  → Check if the server is running: ps aux | grep node
  → Verify port number is correct
  → Try: mcp-verify doctor http://localhost:3000
```

**Solutions:**

```bash
# 1. Verify the server process is actually running
ps aux | grep node
ps aux | grep python

# 2. Check if anything is listening on the expected port
lsof -i :3000        # macOS / Linux
netstat -ano | findstr :3000  # Windows

# 3. Start your MCP server, then retry
node server.js
mcp-verify validate http://localhost:3000

# 4. Run doctor for a full connectivity diagnostic
mcp-verify doctor http://localhost:3000
```

---

### Error: `DNS Resolution Failed` / `ENOTFOUND`

**What it means:** The hostname in your target URL could not be resolved to an IP address.

**Symptoms:**
```
✗ DNS Resolution Failed
  Could not resolve hostname: my-server.example.com
  Tips:
  → Verify the URL is correct: my-server.example.com
  → Verify that host my-server.example.com is reachable (ping my-server.example.com)
  → Try using an IP address instead of hostname
```

**Solutions:**

```bash
# 1. Verify the hostname is correct and reachable
ping my-server.example.com

# 2. Test DNS directly
nslookup my-server.example.com
dig my-server.example.com

# 3. Try with the IP address instead
mcp-verify validate http://192.168.1.100:3000

# 4. Check /etc/hosts or VPN connection if using internal hostnames
cat /etc/hosts | grep my-server
```

---

### Error: `Connection Timeout` / `ETIMEDOUT`

**What it means:** The connection was established (or attempted) but the server did not respond within the allowed time window.

**Symptoms:**
```
✗ Connection Timeout
  The request timed out (http://localhost:3000)
  Tips:
  → The server might be slow or overloaded
  → Try increasing timeout: --timeout 30000
  → Check server logs for errors
```

**Solutions:**

```bash
# 1. Increase the timeout
mcp-verify validate "node server.js" --timeout 30000

# 2. Check server logs for initialization errors
tail -f /var/log/your-server.log

# 3. Check if the server is under load
top
htop

# 4. Use the doctor to get a measured response time
mcp-verify doctor "node server.js"
```

---

### Error Table: Network

| Error Code | Message | Most Likely Cause | First Fix |
|---|---|---|---|
| `ECONNREFUSED` | Connection Failed | Server not running | Start the server process |
| `ENOTFOUND` | DNS Resolution Failed | Wrong hostname / DNS misconfigured | Check URL, try IP address |
| `ETIMEDOUT` | Connection Timeout | Server slow, firewall blocking | Increase `--timeout` |
| `ECONNRESET` | Transport Error | Server crashed mid-handshake | Check server logs |

---

## 🤖 LLM & AI Integration

LLM semantic analysis is **optional** and requires the `--llm <provider:model>` flag and a valid API key. Without it, `mcp-verify` still runs all security rules — only deep semantic checks are skipped.

### General: Invalid Provider Spec

```
✗ Invalid LLM provider spec: anthropic
  → Use format: provider:model (e.g. anthropic:claude-haiku-4-5-20251001)
```

**Fix:** Always include both the provider and the model name:

```bash
# ❌ Incorrect
mcp-verify validate "node server.js" --llm anthropic

# ✅ Correct
mcp-verify validate "node server.js" --llm anthropic:claude-haiku-4-5-20251001
```

---

### 🔑 Anthropic

**Error:** `Anthropic API key not configured`

**Error:** `[Anthropic] Invalid API key format. Expected: sk-ant-...`

**Fix:**

```bash
# 1. Set the environment variable
export ANTHROPIC_API_KEY="sk-ant-api03-..."

# Persist it (Linux / macOS)
echo 'export ANTHROPIC_API_KEY="sk-ant-api03-..."' >> ~/.bashrc
source ~/.bashrc

# 2. Verify the key is set and has the correct format
echo $ANTHROPIC_API_KEY
# Must start with: sk-ant-api03-
```

**Valid models:**
```bash
mcp-verify validate "node server.js" --llm anthropic:claude-haiku-4-5-20251001  # Fastest, cheapest
mcp-verify validate "node server.js" --llm anthropic:claude-sonnet-4-20250514   # Balanced
mcp-verify validate "node server.js" --llm anthropic:claude-opus-4-5-20251101   # Most powerful
```

---

### 🔑 OpenAI

**Error:** `OpenAI API key not configured`

**Error:** `[OpenAI] Invalid API key format. Expected: sk-...`

**Fix:**

```bash
# 1. Set the environment variable
export OPENAI_API_KEY="sk-..."

# 2. Verify the format — must start with sk-
echo $OPENAI_API_KEY
```

**Valid models:**
```bash
mcp-verify validate "node server.js" --llm openai:gpt-4o-mini   # Recommended (fast, cheap)
mcp-verify validate "node server.js" --llm openai:gpt-4o        # More accurate
mcp-verify validate "node server.js" --llm openai:gpt-4-turbo
```

---

### 🔑 Google Gemini

**Error:** `Google API key not configured. Get free key at https://aistudio.google.com/apikey`

**Error:** `[Gemini] Invalid API key format. Expected: AIza...`

**Fix:**

```bash
# 1. Get a free API key at: https://aistudio.google.com/apikey
# 2. Set the environment variable
export GOOGLE_API_KEY="AIza..."

# 3. Verify it starts with AIza
echo $GOOGLE_API_KEY
```

**Valid models:**
```bash
mcp-verify validate "node server.js" --llm gemini:gemini-2.5-flash   # Free tier, fast
mcp-verify validate "node server.js" --llm gemini:gemini-2.5-pro     # Higher accuracy
mcp-verify validate "node server.js" --llm gemini:gemini-2.0-flash   # Stable alternative
```

**Free tier limits:** 15 requests/minute, 1,500 requests/day — more than enough for development.

---

### 🦙 Ollama (Local)

Ollama runs entirely on your machine. No API key is needed, but two things must be true: the Ollama service must be running, and the model must have been downloaded.

**Error:** `Ollama model not found`

```bash
# List models you have downloaded
ollama list

# Download the model you want to use
ollama pull llama3.2
ollama pull codellama
ollama pull mistral
```

**Error:** Ollama server not reachable / `Ollama API error`

```bash
# Start Ollama service
ollama serve

# Or as a system service (Linux)
systemctl start ollama

# Verify it's running
curl http://localhost:11434/api/tags
```

**Error:** `Ollama request timed out after {timeout}ms`

Ollama on older hardware can be slow. Use a smaller model or increase the timeout:

```bash
# Smaller, faster model
ollama pull llama3.2:3b
mcp-verify validate "node server.js" --llm ollama:llama3.2:3b

# Check system resources
htop  # ensure CPU/RAM is available
```

---

### LLM Error Reference Table

| Error | Provider | Root Cause | Fix |
|---|---|---|---|
| `Anthropic API key not configured` | Anthropic | `ANTHROPIC_API_KEY` not set | `export ANTHROPIC_API_KEY="sk-ant-api03-..."` |
| `Invalid API key format. Expected: sk-ant-...` | Anthropic | Wrong key prefix | Regenerate key at console.anthropic.com |
| `OpenAI API key not configured` | OpenAI | `OPENAI_API_KEY` not set | `export OPENAI_API_KEY="sk-..."` |
| `Invalid API key format. Expected: sk-...` | OpenAI | Wrong key prefix | Regenerate key at platform.openai.com |
| `Google API key not configured` | Gemini | `GOOGLE_API_KEY` not set | `export GOOGLE_API_KEY="AIza..."` |
| `Invalid API key format. Expected: AIza...` | Gemini | Wrong key format | Regenerate key at aistudio.google.com |
| `Ollama model not found` | Ollama | Model not downloaded | `ollama pull llama3.2` |
| `Ollama request timed out` | Ollama | Hardware too slow / model too large | Use a smaller model or increase timeout |
| `LLM analysis failed` | Any | Network / auth / quota | Check key, wait and retry, check billing |

---

## 📜 Protocol & Schema Errors

These errors occur when the target server does not comply with the MCP protocol standard.

### Error: `Handshake failed` / `Protocol handshake failed`

**What it means:** `mcp-verify` connected to the server but could not complete the MCP initialization sequence. Either the server isn't implementing MCP at all, or there's a version mismatch.

```
✗ Protocol Error
  The server response does not comply with MCP protocol.
  Tips:
  → The server might not implement MCP protocol correctly
  → Verify the server is an MCP server (not a plain HTTP API)
  → Use --verbose to see raw response
```

**Solutions:**

```bash
# 1. Confirm the target is actually an MCP server (not a plain REST API)
mcp-verify validate "node server.js" --verbose

# 2. Check what the server is actually sending back
curl -X POST http://localhost:3000 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"initialize","id":1,"params":{"protocolVersion":"2024-11-05","capabilities":{}}}'

# 3. Check server logs for initialization errors
node server.js --verbose
```

---

### Error: `Invalid JSON response from server` / `Unknown JSON-RPC error`

**What it means:** The server responded, but the response was not valid JSON-RPC 2.0.

**Diagnostic questions:**
- Is the transport type correct? (`--transport stdio` vs `--transport http`)
- Does the server produce any non-JSON output to stdout (e.g., log lines, banners)?
- Is the server returning an HTTP error before the MCP response?

**Solutions:**

```bash
# 1. Try explicitly setting the transport type
mcp-verify validate "node server.js" --transport stdio
mcp-verify validate http://localhost:3000 --transport http

# 2. Check for protocol compliance issues with verbose output
mcp-verify validate "node server.js" --verbose

# 3. Redirect non-JSON server output to stderr so it doesn't pollute stdout
# (Fix on the server side: all log output must go to stderr, not stdout)
```

---

### Protocol Compliance Issues (RPC Violations)

`mcp-verify` tests three protocol compliance rules during validation:

| Code | Description | What to fix on the server |
|---|---|---|
| `RPC-001` | Server did not return an error for a non-existent method | Return a proper `method not found` JSON-RPC error |
| `RPC-002` | Server returned an empty error object | Error objects must include at minimum a `code` and `message` |
| `RPC-003` | Server accepted a request missing the `jsonrpc` field | Reject malformed requests that omit required fields |

These violations are reported in the validation report but do not always block the scan. However, they indicate the server is not spec-compliant and may cause integration issues with MCP clients.

---

## 🔒 Sandbox & Environment

### Error: `Deno binary not found in PATH`

`--sandbox` mode isolates server execution in a Deno environment. Deno must be installed for this to work. It is **not required** for standard validation.

```bash
# Install Deno (Linux / macOS)
curl -fsSL https://deno.land/install.sh | sh

# Install Deno (Windows — PowerShell)
irm https://deno.land/install.ps1 | iex

# Verify installation
deno --version
```

---

### Error: `Deno version {current} is below minimum required {required}`

Your installed Deno version is too old for the sandbox to function correctly.

```bash
# Upgrade Deno
deno upgrade

# Verify the new version
deno --version
```

---

### Sandbox Limitation: Python / Go Servers

`--sandbox` only supports **Node.js and Deno** servers. If your server uses Python or Go, the sandbox cannot execute it.

```
⚠️  SANDBOX LIMITATION
   This sandbox only supports Node.js/Deno servers.
   Detected runtime: python3
   Future versions will support Python and Go.
Options:
   1. Run with --no-sandbox (for audit/static analysis only, no execution)
   2. Run WITHOUT sandbox (⚠️  RISKY - only for trusted servers)
```

**For Python/Go servers:**

```bash
# Static analysis only (no server execution)
mcp-verify validate "python server.py" --no-sandbox

# Or use the sandbox in Docker manually (outside mcp-verify)
docker run --rm -v $(pwd):/app python:3.12 python /app/server.py
```

---

### Error: `Temp directory is not writable`

The sandbox needs write access to the system's temp directory to stage the server.

```bash
# Check temp directory permissions (Linux / macOS)
ls -la /tmp

# Fix permissions if needed
chmod 1777 /tmp

# Verify the sandbox environment is ready
mcp-verify doctor --verbose
```

---

## 🗂️ Permissions & File System

### Error: `Invalid output path` / `Invalid baseline path`

`mcp-verify` enforces strict path validation to prevent path traversal attacks. Output and baseline paths must be within your project directory.

```
✗ Invalid output path: /etc/mcp-verify/report.json
  This could be a path traversal attack.
  Only paths within the output directory are permitted.
  Baselines must be stored within your project for security.
```

**Fix:** Always use relative paths or paths inside your project:

```bash
# ❌ Incorrect — absolute path outside project
mcp-verify validate "node server.js" --output /etc/reports/

# ✅ Correct — relative path within project
mcp-verify validate "node server.js" --output ./reports/
mcp-verify validate "node server.js" --save-baseline ./reports/baseline/main.json
```

---

### Error: Reports directory not writable

If `mcp-verify` cannot write to `reports/`, the output files will fail to save silently or with a filesystem error.

```bash
# Create the directory if it doesn't exist
mkdir -p reports/

# Fix permissions (Linux / macOS)
chmod -R 755 reports/

# Check current permissions
ls -la reports/

# Verify you can write to it
touch reports/test.txt && rm reports/test.txt
echo "Write OK"
```

---

### Binary Integrity Breach

If `doctor` reports a checksum mismatch, the installed binary may have been modified after installation. This is a security warning.

```
❌  Binary Integrity    INTEGRITY BREACH: Binary has been modified!
```

**What to do:**

```bash
# 1. Attempt to regenerate the manifest (if build is trusted)
mcp-verify doctor --fix-integrity

# 2. If in doubt, reinstall from scratch
npm uninstall -g mcp-verify
npm install -g mcp-verify

# 3. Verify the reinstalled binary
mcp-verify doctor
```

---

## ⚙️ CI/CD Failures

### Understanding Exit Codes

`mcp-verify` uses three distinct exit codes, each with a different meaning. Treating them as a single "error" will cause you to miss useful diagnostic information.

| Code | Meaning           | Action Required                                     |
|------|-------------------|-----------------------------------------------------|
| `0`  | ✅ Success        | None                                                |
| `1`  | ❌ Error          | Check server availability, CLI flags, or environment |
| `2`  | 🚨 Critical Issue | Review security findings or regression diff         |

**Critical distinction in CI/CD:**

```yaml
- name: Run mcp-verify
  run: mcp-verify validate "node server.js" --compare-baseline baseline.json --fail-on-degradation
  # Exit 1 → infrastructure problem (server didn't start, wrong flags)
  # Exit 2 → security regression (your code introduced a vulnerability)
  # These should trigger different alert channels
```

---

### Error: Exit code `1` in GitHub Actions

Exit code `1` is a command-level failure — the scan itself could not be completed. Common causes:

```
✗ Fatal error: Failed to connect to MCP server
```

**Checklist:**

```yaml
- name: Start MCP server (if needed)
  run: node server.js &
  # Give the server time to start before mcp-verify connects

- name: Wait for server to be ready
  run: npx wait-on http://localhost:3000 --timeout 30000

- name: Run mcp-verify
  run: mcp-verify validate http://localhost:3000 --format json --output reports/
```

Common causes of exit `1`:

- Server not started before `mcp-verify` runs (add a `wait-on` step)
- `ANTHROPIC_API_KEY` or other env vars not set as GitHub Secrets
- Wrong transport type (`--transport stdio` vs `--transport http`)
- Node.js version below 18 in the runner

---

### Error: Exit code `2` — Regression Detected

Exit code `2` means `--fail-on-degradation` was active and a security regression was detected. This is the intended behavior — a new `CRITICAL` finding appeared, or the security score dropped beyond the configured threshold.

```bash
# See exactly what changed
mcp-verify validate "node server.js" \
  --compare-baseline reports/baseline/main.json \
  --format json \
  --output reports/

# The report at reports/comparison-*.json will show:
# - "New Issues" (hashes present now but not in baseline)
# - "Resolved Issues" (hashes in baseline but fixed now)
# - Score delta per category
```

**If the regression is expected (intentional change):** update the baseline:

```bash
mcp-verify validate "node server.js" --save-baseline reports/baseline/main.json
git add reports/baseline/main.json
git commit -m "chore: accept new security baseline after intentional change"
```

**If the regression is a bug:** fix the underlying vulnerability and re-run.

---

### Common GitHub Actions Mistakes

| Mistake | Symptom | Fix |
|---|---|---|
| API key not in Secrets | `LLM analysis failed` | Add `ANTHROPIC_API_KEY` to repo Secrets |
| Server not started | Exit `1`, connection refused | Add a server startup + `wait-on` step before `mcp-verify` |
| Baseline not downloaded | Every run shows regressions | Use `actions/download-artifact` to fetch the baseline |
| Exit code not checked | Failures silently ignored | Ensure `fail-on-error: true` or check `$?` explicitly |
| Wrong Node.js version | `mcp-verify` install fails | Pin `node-version: '20'` in the `setup-node` step |

---

### Minimal Working GitHub Actions Example

```yaml
name: MCP Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install mcp-verify
        run: npm install -g mcp-verify

      - name: Start MCP server
        run: node server.js &

      - name: Wait for server
        run: npx wait-on http://localhost:3000 --timeout 30000

      - name: Download baseline (if exists)
        continue-on-error: true
        uses: actions/download-artifact@v4
        with:
          name: mcp-verify-baseline
          path: reports/baseline/

      - name: Run security scan
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          mcp-verify validate http://localhost:3000 \
            --compare-baseline reports/baseline/main.json \
            --fail-on-degradation \
            --allowed-score-drop 5 \
            --format json \
            --output reports/

      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: mcp-verify-report
          path: reports/
```

---

## 🆘 Getting Help

If you've worked through the relevant section and the problem persists:

1. **Run doctor with verbose output** and copy the result:
   ```bash
   mcp-verify doctor [target] --verbose
   ```

2. **Run validate with verbose output** to capture the raw error:
   ```bash
   mcp-verify validate [target] --verbose
   ```

3. **Check the examples** for working command patterns:
   ```bash
   mcp-verify examples
   ```

4. **Open an issue** with the verbose output attached:
   👉 https://github.com/FinkTech/mcp-verify/issues

5. **Join the discussion** for general questions:
   👉 https://github.com/FinkTech/mcp-verify/discussions

---

## 🔗 Related Documentation

- **[REGRESSION-DETECTION.md](./REGRESSION-DETECTION.md)** — Baseline and regression detection
- **[guides/LLM_SETUP.md](./guides/LLM_SETUP.md)** — Full LLM provider setup guide
- **[guides/CI_CD.md](./guides/CI_CD.md)** — GitHub Actions, GitLab CI, and more
- **[guides/EXAMPLES.md](./guides/EXAMPLES.md)** — Copy-paste commands for common workflows
- **[apps/cli-verifier/README.md](./apps/cli-verifier/README.md)** — Full CLI reference

---

*Part of the **mcp-verify** project — the open-source security scanner for Model Context Protocol servers.*
*Licensed under [AGPL-3.0](./LICENSE). © 2026 FinkTech.*
