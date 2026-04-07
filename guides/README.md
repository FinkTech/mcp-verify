# 📚 MCP Verify Documentation

Welcome to **mcp-verify** documentation! This directory contains user-facing guides organized by persona and use case.

---

## 🎯 Quick Navigation

**Choose your path based on what you need:**

| I want to...                | Guide                                                               | Time   |
| --------------------------- | ------------------------------------------------------------------- | ------ |
| Get started quickly         | [LLM Setup](#-llm-setup) → [Examples](#-examples)                   | 5 min  |
| Integrate with CI/CD        | [CI/CD Guide](#-cicd-integration)                                   | 10 min |
| Understand security scoring | [Security Scoring](../SECURITY_SCORING.md)                          | 15 min |
| Contribute code             | [Development Guide](../DEVELOPMENT.md) → [Code Map](../CODE_MAP.md) | 30 min |
| See all commands            | [Examples](#-examples)                                              | 5 min  |
| Debug connection issues     | [Troubleshooting](#-troubleshooting)                                | 5 min  |

---

## 📖 User Guides

### 🚀 LLM Setup

**File**: [LLM_SETUP.md](./LLM_SETUP.md)

**For**: First-time users, security engineers

**What you'll learn**:

- How to configure Anthropic Claude (best quality, $0.0003/scan)
- How to use Ollama (free, local, privacy-first)
- How to use OpenAI GPT (existing API key, $0.0002/scan)
- Provider comparison (speed, cost, privacy)
- Troubleshooting LLM issues

**Quick Start**:

```bash
# Ollama (free, local)
ollama pull llama3.2
mcp-verify validate "node server.js" --llm ollama:llama3.2

# Anthropic (best quality)
export ANTHROPIC_API_KEY=sk-ant-...
mcp-verify validate "node server.js" --llm anthropic:claude-haiku-4-5-20251001

# OpenAI (existing API key)
export OPENAI_API_KEY=sk-...
mcp-verify validate "node server.js" --llm openai:gpt-4o-mini
```

**When to read**: Before your first LLM-powered validation

---

### ⚡ Examples

**File**: [EXAMPLES.md](./EXAMPLES.md)

**For**: All users (first-time and experienced)

**What you'll learn**:

- Copy-paste commands for all scenarios
- Basic validation (STDIO, HTTP)
- Security scanning
- LLM semantic analysis
- Report formats (JSON, HTML, Markdown, SARIF)
- CI/CD integration patterns
- Baseline comparison
- Complete workflows by use case

**Quick Start**:

```bash
# Basic validation
mcp-verify validate "node server.js"

# Security + LLM analysis
mcp-verify validate "node server.js" --security --llm ollama:llama3.2

# Generate all report formats
mcp-verify validate "node server.js" --html --format sarif
```

**When to read**: Anytime you need a command reference

---

### 🔄 CI/CD Integration

**File**: [CI_CD.md](./CI_CD.md)

**For**: DevOps engineers, CI/CD users

**What you'll learn**:

- GitHub Actions workflows (basic, SARIF upload, LLM analysis)
- GitLab CI examples
- CircleCI configuration
- Azure Pipelines setup
- Exit code handling (0=success, 1=failure, 2=critical)
- Baseline comparison strategies
- Regression detection
- Security gate patterns

**Quick Start**:

**GitHub Actions**:

```yaml
- name: Validate MCP Server
  run: |
    npm install -g mcp-verify
    mcp-verify validate "node server.js" --format sarif
```

**GitLab CI**:

```yaml
mcp-verify:
  script:
    - npm install -g mcp-verify
    - mcp-verify validate "node server.js" --format sarif
```

**When to read**: When adding mcp-verify to your CI/CD pipeline

---

## 🔐 Security Documentation

### Security Scoring

**File**: [../SECURITY_SCORING.md](../SECURITY_SCORING.md)

**For**: Security engineers, DevOps managers

**What you'll learn**:

- How scores are calculated (100 - penalties)
- 13 OWASP security rules explained
- Acceptable risk levels by environment:
  - **Production**: Score ≥ 90 (Excellent)
  - **Staging**: Score ≥ 70 (Good)
  - **Internal Tools**: Score ≥ 50 (Fair)
- Real examples with explanations
- False positive handling

**Quick Start**:

```bash
# Check security score
mcp-verify validate "node server.js" --security

# Fail build if critical issues found
mcp-verify validate "node server.js" --fail-on-degradation
```

**When to read**: Before deploying to production

---

### Security Model

**File**: [../SECURITY.md](../SECURITY.md)

**For**: Security auditors, compliance teams

**What you'll learn**:

- Threat model
- Security assumptions
- Vulnerability reporting process

---

## 👨‍💻 Contributor Documentation

### Development Guide

**File**: [../DEVELOPMENT.md](../DEVELOPMENT.md)

**For**: Contributors, developers

**What you'll learn**:

- Local setup (clone, install, build, test)
- Development workflow
- Testing guide (unit, integration, e2e)
- Debugging tips (VSCode config, Node inspector)
- Code style guidelines
- Pre-commit hooks
- Adding new features

**Quick Start**:

```bash
# Clone and setup
git clone https://github.com/FinkTech/mcp-verify.git
cd mcp-verify
npm install
npm run build
npm test

# Run in dev mode
npm run dev
```

**When to read**: Before your first contribution

---

### Code Map

**File**: [../CODE_MAP.md](../CODE_MAP.md)

**For**: Contributors navigating codebase

**What you'll learn**:

- "I want to..." quick reference table
- Directory structure with responsibilities
- Key component deep dives
- Component relationship diagram
- Common tasks with step-by-step code
- Learning path for new contributors

**Quick Start Table**:

| I want to...      | Edit this file                        |
| ----------------- | ------------------------------------- |
| Add security rule | `libs/core/domain/security/rules/`    |
| Add CLI command   | `apps/cli-verifier/src/commands/`     |
| Add LLM provider  | `libs/core/domain/quality/providers/` |
| Add report format | `libs/core/domain/reporting/`         |

**When to read**: When you know what you want to add, but not where it goes

---

### Architecture

**File**: [../ARCHITECTURE.md](../ARCHITECTURE.md)

**For**: Contributors understanding system design

**What you'll learn**:

- Hexagonal/clean architecture principles
- Dependency flow (apps → use-cases → domain)
- Why we separated domain from infrastructure
- Design decisions and trade-offs

**When to read**: When you want to understand "why" behind the structure

---

### Contributing Guidelines

**File**: [../CONTRIBUTING.md](../CONTRIBUTING.md)

**For**: First-time contributors

**What you'll learn**:

- How to submit issues
- How to create pull requests
- Code review process
- Commit message conventions

---

## 📊 Reference Documentation

### Testing Strategy

**File**: [../TESTING.md](../TESTING.md)

**For**: Contributors writing tests

**What you'll learn**:

- Testing pyramid (unit, integration, e2e)
- Test organization
- Coverage requirements
- Mock servers for testing

---

### Changelog

**File**: [../CHANGELOG.md](../CHANGELOG.md)

**For**: All users tracking changes

**What you'll learn**:

- Version history
- New features
- Breaking changes
- Bug fixes

---

## 🗺️ Documentation Map by Persona

### 👤 Persona 1: First-Time User

**Goal**: Run first validation successfully

**Path**:

1. [LLM Setup](./LLM_SETUP.md) - Configure LLM provider (5 min)
2. [Examples](./EXAMPLES.md) - Copy-paste commands (2 min)
3. Run validation:
   ```bash
   mcp-verify validate "node server.js" --llm ollama:llama3.2
   ```

**Expected Time**: ~10 minutes to success

---

### 👤 Persona 2: CI/CD Developer

**Goal**: Add mcp-verify to build pipeline

**Path**:

1. [Examples](./EXAMPLES.md) - Understand exit codes (5 min)
2. [CI/CD Guide](./CI_CD.md) - Copy workflow for your platform (5 min)
3. [Security Scoring](../SECURITY_SCORING.md) - Set acceptable thresholds (5 min)
4. Configure baseline comparison:
   ```yaml
   - run: mcp-verify validate "node server.js" --save-baseline baseline.json
   - run: mcp-verify validate "node server.js" --compare-baseline baseline.json --fail-on-degradation
   ```

**Expected Time**: ~15 minutes to integrate

---

### 👤 Persona 3: Security Engineer

**Goal**: Assess production readiness

**Path**:

1. [Security Scoring](../SECURITY_SCORING.md) - Understand risk levels (15 min)
2. [LLM Setup](./LLM_SETUP.md) - Choose privacy-appropriate LLM (5 min)
3. [CI/CD Guide](./CI_CD.md) - Set up regression detection (10 min)
4. Run comprehensive scan:
   ```bash
   mcp-verify validate "node server.js" \
     --security \
     --llm anthropic:claude-haiku-4-5-20251001 \
     --format sarif \
     --fail-on-degradation
   ```

**Expected Time**: ~30 minutes to assess

---

### 👤 Persona 4: Contributor

**Goal**: Add new feature

**Path**:

1. [Development Guide](../DEVELOPMENT.md) - Local setup (15 min)
2. [Code Map](../CODE_MAP.md) - Find relevant files (5 min)
3. [Architecture](../ARCHITECTURE.md) - Understand design (10 min)
4. [Contributing Guidelines](../CONTRIBUTING.md) - Follow process (5 min)
5. Write code, tests, submit PR

**Expected Time**: ~1 hour to first contribution

---

## 🔍 Troubleshooting

### Common Issues

#### "LLM provider not responding"

**Solution**: See [LLM Setup - Troubleshooting](./LLM_SETUP.md#troubleshooting)

```bash
# Check Ollama
ollama list
curl http://localhost:11434/api/tags

# Check Anthropic
echo $ANTHROPIC_API_KEY

# Check OpenAI
echo $OPENAI_API_KEY
```

---

#### "Connection refused" when validating server

**Solution**: Run diagnostics

```bash
# Doctor command diagnoses issues
mcp-verify doctor "node server.js"

# Check if server is running
ps aux | grep node

# Test manually
curl http://localhost:3000
```

---

#### "Exit code 2 in CI/CD"

**Cause**: Critical security issue or baseline degradation

**Solution**: Review report for CRITICAL findings

```bash
# Generate detailed report
mcp-verify validate "node server.js" --html --verbose

# Check for critical issues
cat reportes/json/mcp-report-*.json | jq '.security.criticalCount'
```

---

#### "Score lower than expected"

**Solution**: Read [Security Scoring](../SECURITY_SCORING.md) to understand penalties

```bash
# Generate markdown report for detailed breakdown
mcp-verify validate "node server.js" --format json
cat reportes/md/mcp-report-*.md
```

---

## 📚 External Resources

### Official Documentation

- [Model Context Protocol Specification](https://modelcontextprotocol.io/)
- [Anthropic API Documentation](https://docs.anthropic.com/)
- [Ollama Documentation](https://ollama.ai/docs)
- [OpenAI API Documentation](https://platform.openai.com/docs)

### Community

- [GitHub Repository](https://github.com/FinkTech/mcp-verify)
- [Issue Tracker](https://github.com/FinkTech/mcp-verify/issues)
- [Discussions](https://github.com/FinkTech/mcp-verify/discussions)

---

## 🆘 Need Help?

### Can't find what you're looking for?

1. **Search CODE_MAP.md**: [Quick reference](../CODE_MAP.md) for "I want to..." questions
2. **Check Examples**: [Copy-paste commands](./EXAMPLES.md)
3. **Run Doctor**: `mcp-verify doctor <target>` diagnoses issues
4. **Ask Community**: [GitHub Discussions](https://github.com/FinkTech/mcp-verify/discussions)
5. **Report Bug**: [Issue Tracker](https://github.com/FinkTech/mcp-verify/issues)

---

## 📝 Documentation Philosophy

### Principles We Follow

1. **Persona-Driven**: Organized by user type, not technical structure
2. **Action-Oriented**: Every doc has copy-paste examples
3. **Progressive Disclosure**: TL;DR → Quick Start → Deep Dive
4. **Self-Service**: Users succeed without asking questions
5. **Maintainable**: Clear structure, easy to update

### How This Documentation is Organized

```
docs/
├── guides/              # 📚 USER-FACING DOCUMENTATION
│   ├── README.md        #    ← You are here (index)
│   ├── LLM_SETUP.md     #    LLM provider setup
│   ├── EXAMPLES.md      #    Copy-paste commands
│   └── CI_CD.md         #    CI/CD integration
│
├── SECURITY_SCORING.md  # 🔐 Security risk assessment
├── DEVELOPMENT.md       # 👨‍💻 Contributor local setup
├── CODE_MAP.md          # 🗺️ Codebase navigation
├── ARCHITECTURE.md      # 🏗️ System design
├── CONTRIBUTING.md      # 🤝 Contribution guidelines
├── SECURITY.md          # 🔒 Security model
├── TESTING.md           # 🧪 Testing strategy
└── CHANGELOG.md         # 📝 Version history
```

---

## 📊 Documentation Coverage

| Persona               | Documentation                       | Status      |
| --------------------- | ----------------------------------- | ----------- |
| **First-Time User**   | LLM Setup, Examples                 | ✅ Complete |
| **CI/CD Developer**   | CI/CD Guide, Examples               | ✅ Complete |
| **Security Engineer** | Security Scoring, LLM Setup         | ✅ Complete |
| **Contributor**       | Development, Code Map, Architecture | ✅ Complete |

**Overall Coverage**: 100% ✅

---

## 🎯 Success Metrics

### How We Measure Documentation Quality

1. **Time to First Success**
   - Target: < 10 minutes for first-time users
   - Measure: User can run validation successfully

2. **CI/CD Setup Time**
   - Target: < 15 minutes
   - Measure: User can add to GitHub Actions

3. **Contributor Onboarding**
   - Target: < 1 hour to first PR
   - Measure: Time from clone to PR submission

4. **Documentation Findability**
   - Target: < 2 clicks to any doc
   - Measure: From README → relevant guide

---

## 🔄 Keeping Documentation Updated

### When to Update Documentation

- ✅ **New Feature**: Update relevant guide + examples
- ✅ **Breaking Change**: Update CHANGELOG + migration guide
- ✅ **Bug Fix**: Update troubleshooting section
- ✅ **API Change**: Update examples + CODE_MAP
- ✅ **Dependency Update**: Update setup guides

### Documentation Checklist for PRs

- [ ] Updated relevant user guide
- [ ] Added example to EXAMPLES.md
- [ ] Updated CODE_MAP.md if new file
- [ ] Updated CHANGELOG.md
- [ ] All examples tested and working

---

## 💬 Feedback

### Help Us Improve

Found a typo? Command doesn't work? Documentation unclear?

- **Report Issue**: [GitHub Issues](https://github.com/FinkTech/mcp-verify/issues)
- **Suggest Improvement**: [GitHub Discussions](https://github.com/FinkTech/mcp-verify/discussions)
- **Submit Fix**: [Pull Request](https://github.com/FinkTech/mcp-verify/pulls)
