# 🧠 LLM Semantic Analysis Setup Guide

**Last Updated**: 2026-02-03
**Target Audience**: All users (Persona 1, 2, 3)
**Time to Setup**: 2-5 minutes

---

## 🎯 What is LLM Semantic Analysis?

mcp-verify includes **optional** AI-powered semantic analysis that detects:

- **Description mismatches** - "Get weather for city" but requires lat/lon coordinates
- **Misleading names** - Tool called "read_file" that can also write/delete
- **Security concerns** - Tool descriptions that hide dangerous capabilities
- **Ambiguous parameters** - Unclear what inputs do

**Without LLM**: You get 12 OWASP security rules (SQL injection, command injection, etc.)
**With LLM**: You get those + deep semantic understanding

---

## ⚡ TL;DR - Quick Start by Provider

| Provider | Cost | Privacy | Speed | Setup Time | Best For |
|----------|------|---------|-------|------------|----------|
| **Gemini** | 💰 FREE tier! | ☁️ Cloud | ⚡⚡ Very Fast | 30 sec | New users, budget-conscious |
| **Ollama** | 💰 FREE | 🔒 100% Local | ⚡ Fast | 3 min | Open source devs, privacy-first |
| **Anthropic** | 💰 $0.0003/scan | ☁️ Cloud | ⚡⚡ Very Fast | 30 sec | Professional projects |
| **OpenAI** | 💰 $0.0002/scan | ☁️ Cloud | ⚡⚡ Very Fast | 30 sec | Existing OpenAI users |

**Recommendation**: Start with **Gemini** (free tier, fast setup) or **Ollama** (100% local, privacy-first).

---

## 🦙 Option 1: Ollama (Recommended for Beginners)

### Why Ollama?

✅ **100% Free** - No API costs, ever
✅ **Privacy-First** - All processing happens locally, no data sent to cloud
✅ **Offline Mode** - Works without internet
✅ **Open Models** - Llama 3.2, Mistral, CodeLlama, 100+ models

❌ **Requires Installation** - Need to install Ollama runtime
❌ **Slower on Old Hardware** - Needs decent CPU/GPU

### Setup (3 minutes)

**Step 1: Install Ollama**

```bash
# macOS / Linux
curl -fsSL https://ollama.com/install.sh | sh

# Windows
# Download installer from: https://ollama.com/download/windows
```

**Step 2: Pull a Model**

```bash
# Recommended: Llama 3.2 (fast, accurate)
ollama pull llama3.2

# Alternative: CodeLlama (optimized for code)
ollama pull codellama

# Alternative: Mistral (balanced)
ollama pull mistral
```

**Step 3: Verify Ollama is Running**

```bash
# Check if Ollama server is running
curl http://localhost:11434/api/tags
```

Expected output: List of installed models

**Step 4: Run mcp-verify with Ollama**

```bash
mcp-verify validate <target> --llm ollama:llama3.2
```

### Troubleshooting Ollama

**Problem**: `Error: Ollama server not running`

```bash
# Start Ollama service
ollama serve

# Or on macOS/Linux:
systemctl start ollama
```

**Problem**: `Model "llama3.2" not found`

```bash
# List available models
ollama list

# Pull the model
ollama pull llama3.2
```

**Problem**: Slow analysis (>30 seconds)

```bash
# Use smaller/faster model
ollama pull llama3.2:7b  # 7B parameter model (faster)

# Or check system resources
htop  # Ensure CPU/RAM available
```

---

## 🌟 Option 2: Google Gemini (FREE Tier Available!)

### Why Gemini?

✅ **FREE Tier** - 15 RPM, 1M tokens/min, 1500 requests/day (no credit card!)
✅ **Very Fast** - ~1-2 seconds per analysis
✅ **Large Context** - 1-2M token context window
✅ **Easy Setup** - Just get an API key

❌ **Cloud-Based** - Data sent to Google servers
❌ **Rate Limited** - Free tier has usage limits

### Free Tier Limits (as of 2024)

| Limit | Value |
|-------|-------|
| Requests per minute | 15 |
| Tokens per minute | 1,000,000 |
| Requests per day | 1,500 |

More than enough for most projects!

### Setup (30 seconds)

**Step 1: Get API Key**

1. Go to https://aistudio.google.com/apikey
2. Sign in with your Google account
3. Click **Create API Key**
4. Copy the key (starts with `AIza...`)

**Step 2: Set Environment Variable**

```bash
# Linux / macOS (add to ~/.bashrc or ~/.zshrc for persistence)
export GOOGLE_API_KEY="AIza..."

# Windows (PowerShell)
$env:GOOGLE_API_KEY="AIza..."

# Windows (Command Prompt)
set GOOGLE_API_KEY=AIza...
```

**Step 3: Run mcp-verify with Gemini**

```bash
# Recommended: Gemini 2.5 Flash (fastest, free)
mcp-verify validate <target> --llm gemini:gemini-2.5-flash

# Alternative: Gemini 3.0 Flash (latest, free)
mcp-verify validate <target> --llm gemini:gemini-3.0-flash

# Alternative: Gemini 3.0 Pro (most accurate)
mcp-verify validate <target> --llm gemini:gemini-3.0-pro
```

### Troubleshooting Gemini

**Problem**: `Error: Google API key not configured`

```bash
# Verify environment variable is set
echo $GOOGLE_API_KEY  # Linux/macOS
echo %GOOGLE_API_KEY%  # Windows

# If empty, export it again
export GOOGLE_API_KEY="AIza..."
```

**Problem**: `Error: API key is invalid`

- Check key format: Must start with `AIza`
- Regenerate key in https://aistudio.google.com/apikey
- Ensure key has Generative Language API enabled

**Problem**: `Error: Rate limit exceeded (429)`

- Free tier: 15 requests per minute max
- Wait 60 seconds and retry
- Or upgrade to paid tier

---

## 🤖 Option 3: Anthropic Claude (Best Quality)

### Why Anthropic?

✅ **Best Quality** - Claude is optimized for analysis tasks
✅ **Very Fast** - ~1-2 seconds per analysis
✅ **Built for the AI-First Era** - `mcp-verify`'s architecture is designed for robust integration with modern AI agents, including Anthropic's Claude.

❌ **Costs Money** - ~$0.0003 per scan (~300 scans per $1)
❌ **Requires API Key** - Need Anthropic account
❌ **Cloud-Based** - Data sent to Anthropic servers

### Setup (30 seconds)

**Step 1: Get API Key**

1. Go to https://console.anthropic.com/
2. Sign up / Log in
3. Navigate to **API Keys** section
4. Click **Create Key**
5. Copy the key (starts with `sk-ant-api03-...`)

**Step 2: Set Environment Variable**

```bash
# Linux / macOS (add to ~/.bashrc or ~/.zshrc for persistence)
export ANTHROPIC_API_KEY="sk-ant-api03-..."

# Windows (PowerShell)
$env:ANTHROPIC_API_KEY="sk-ant-api03-..."

# Windows (Command Prompt)
set ANTHROPIC_API_KEY=sk-ant-api03-...
```

**Step 3: Run mcp-verify with Anthropic**

```bash
# Recommended: Claude Haiku 4.5 (fastest, cheapest)
mcp-verify validate <target> --llm anthropic:claude-haiku-4-5-20251001

# Alternative: Claude Sonnet 4 (more accurate)
mcp-verify validate <target> --llm anthropic:claude-sonnet-4-20250514

# Alternative: Claude Opus 4.5 (most powerful)
mcp-verify validate <target> --llm anthropic:claude-opus-4-5-20251101
```

### Troubleshooting Anthropic

**Problem**: `Error: Anthropic API key not configured`

```bash
# Verify environment variable is set
echo $ANTHROPIC_API_KEY  # Linux/macOS
echo %ANTHROPIC_API_KEY%  # Windows

# If empty, export it again
export ANTHROPIC_API_KEY="sk-ant-api03-..."
```

**Problem**: `Error: API key is invalid or expired`

- Check key format: Must start with `sk-ant-api03-`
- Regenerate key in https://console.anthropic.com/
- Check billing: Ensure account has credits

**Problem**: `Error: Rate limit exceeded`

- Wait 60 seconds and retry
- Upgrade to paid tier for higher limits
- Use Ollama as fallback

---

## 🚀 Option 4: OpenAI (For Existing Users)

### Why OpenAI?

✅ **Reuse Credits** - If you already have OpenAI subscription
✅ **Fast** - Similar speed to Anthropic
✅ **Widely Available** - Most accessible cloud API

❌ **Costs Money** - ~$0.0002 per scan
❌ **Cloud-Based** - Data sent to OpenAI servers
❌ **Lower Quality** - Not as specialized for analysis as Claude

### Setup (30 seconds)

**Step 1: Get API Key**

1. Go to https://platform.openai.com/
2. Sign up / Log in
3. Navigate to **API Keys**
4. Click **Create new secret key**
5. Copy the key (starts with `sk-...`)

**Step 2: Set Environment Variable**

```bash
# Linux / macOS
export OPENAI_API_KEY="sk-..."

# Windows (PowerShell)
$env:OPENAI_API_KEY="sk-..."
```

**Step 3: Run mcp-verify with OpenAI**

```bash
# Recommended: GPT-4o-mini (fast, cheap)
mcp-verify validate <target> --llm openai:gpt-4o-mini

# Alternative: GPT-4o (more accurate)
mcp-verify validate <target> --llm openai:gpt-4o

# Alternative: GPT-4 Turbo
mcp-verify validate <target> --llm openai:gpt-4-turbo
```

### Troubleshooting OpenAI

**Problem**: `Error: OpenAI API key not configured`

```bash
# Verify environment variable
echo $OPENAI_API_KEY

# Re-export if needed
export OPENAI_API_KEY="sk-..."
```

**Problem**: `Error: Invalid API key format`

- Key must start with `sk-`
- No spaces or quotes in key
- Regenerate key if necessary

---

## 🔄 Comparison: Which Provider Should I Use?

### Use Case Matrix

| Scenario | Recommended Provider | Why |
|----------|---------------------|-----|
| **First time trying semantic analysis** | Ollama | Free, no commitment, privacy-first |
| **Open source project** | Ollama | Free forever, community-friendly |
| **Sensitive codebase** | Ollama | 100% local, no data leaves your machine |
| **Professional project** | Anthropic | Best quality, fast, reliable |
| **CI/CD pipeline** | Anthropic or OpenAI | Cloud-based, no local dependencies |
| **Already use OpenAI** | OpenAI | Reuse existing credits |
| **Budget-conscious** | Ollama | Free forever |
| **Air-gapped environment** | Ollama | Works offline |

### Cost Comparison (1000 scans)

| Provider | Cost | Equivalent to |
|----------|------|---------------|
| Ollama | **$0** | FREE |
| Anthropic (Haiku) | **$0.30** | 1 coffee ☕ |
| OpenAI (GPT-4o-mini) | **$0.20** | 1 snack 🍫 |

---

## 🎨 Usage Examples

### Example 1: Validate with Ollama

```bash
mcp-verify validate \
  --server "node my-server.js" \
  --llm ollama:llama3.2 \
  --output ./reports
```

**Output:**
```
✓ Testing handshake
✓ Discovering capabilities
✓ Running security audit
🧠 Running LLM semantic analysis (ollama:llama3.2)...

Security Score: 85/100
Quality Score: 92/100

LLM Findings:
  [HIGH] Tool "get_weather" description says "Get weather for city"
         but requires lat/lon coordinates instead of city name.
         Suggestion: Update description to match actual parameters.
```

### Example 2: CI/CD with Anthropic

```yaml
# .github/workflows/security.yml
- name: Validate MCP Server
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
  run: |
    mcp-verify validate \
      --server "node server.js" \
      --llm anthropic:claude-haiku-4-5-20251001 \
      --fail-on-critical
```

### Example 3: Compare Providers

```bash
# Test with Ollama (free)
mcp-verify validate --server "node server.js" --llm ollama:llama3.2

# Test with Anthropic (paid)
mcp-verify validate --server "node server.js" --llm anthropic:claude-haiku-4-5-20251001

# Test with OpenAI (paid)
mcp-verify validate --server "node server.js" --llm openai:gpt-4o-mini
```

---

## 🔐 Security Considerations

### API Key Storage

**✅ DO:**
- Store API keys in environment variables
- Use CI/CD secrets (GitHub Secrets, GitLab Variables)
- Use `.env` files (added to `.gitignore`)

**❌ DON'T:**
- Hardcode API keys in code
- Commit API keys to Git
- Share API keys in public forums

### Data Privacy

| Provider | Data Sent to Cloud | Retention Policy |
|----------|-------------------|------------------|
| **Ollama** | ❌ Nothing | N/A (100% local) |
| **Anthropic** | ✅ Tool descriptions/schemas | 30 days (per Anthropic policy) |
| **OpenAI** | ✅ Tool descriptions/schemas | 30 days (per OpenAI policy) |

**Important**: If analyzing **sensitive/proprietary code**, use **Ollama** to keep everything local.

---

## 🚫 Running Without LLM

LLM semantic analysis is **completely optional**. You can use mcp-verify without any LLM:

```bash
# Without LLM (still runs 12 OWASP security rules)
mcp-verify validate --server "node server.js"
```

**What you still get:**
- ✅ 12 OWASP security rules (SQL injection, command injection, etc.)
- ✅ Protocol compliance validation
- ✅ Quality scoring
- ✅ JSON/HTML/SARIF reports

**What you miss:**
- ❌ Deep semantic understanding
- ❌ Description mismatch detection
- ❌ Misleading name detection

---

## 📊 Performance Comparison

| Provider | Avg Analysis Time | Accuracy | Cost per 100 Scans |
|----------|------------------|----------|-------------------|
| Ollama (llama3.2) | 5-10s | ⭐⭐⭐⭐ | FREE |
| Ollama (mistral) | 3-7s | ⭐⭐⭐ | FREE |
| Anthropic (Haiku) | 1-2s | ⭐⭐⭐⭐⭐ | $0.03 |
| Anthropic (Sonnet) | 2-3s | ⭐⭐⭐⭐⭐ | $0.15 |
| OpenAI (GPT-4o-mini) | 1-2s | ⭐⭐⭐⭐ | $0.02 |

*Performance measured on: MacBook Pro M1, 16GB RAM*

---

## ❓ FAQ

**Q: Can I switch providers later?**
A: Yes! Just change the `--llm` flag. No migration needed.

**Q: Can I use multiple providers?**
A: Not simultaneously, but you can run separate scans with different providers.

**Q: Does LLM analysis affect my security score?**
A: Yes, LLM findings can lower the quality score if issues are found.

**Q: Is my code sent to LLM providers?**
A: No, only tool **descriptions and schemas** are sent (not your actual code).

**Q: How accurate is LLM analysis?**
A: ~90-95% accuracy. Always review findings before acting.

**Q: Can I customize the LLM prompt?**
A: Not yet. This feature is planned for a future release.

---

## 🆘 Getting Help

**Problem not listed here?**

- Check [TROUBLESHOOTING.md](../TROUBLESHOOTING.md)
- Open issue: https://github.com/FinkTech/mcp-verify/issues
- Ask in discussions: https://github.com/FinkTech/mcp-verify/discussions

---

## 📚 Related Documentation

- [Examples](./EXAMPLES.md) - Copy-paste commands
- [Security Scoring](../SECURITY_SCORING.md) - How scoring works
- [CI/CD Integration](./CI_CD.md) - GitHub Actions, GitLab CI
- [Contributing](../CONTRIBUTING.md) - Development guide

