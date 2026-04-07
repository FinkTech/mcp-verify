# 🦙 Ollama Support & Security Storage Architecture

This document explains:

1. How to add **Ollama** and other open-source LLM support
2. How **security findings are currently stored**
3. Recommendations for improved security tracking

---

## 📊 Current State (v1.0)

### LLM Integration

- **Provider**: Anthropic Claude API only (hardcoded)
- **Model**: `claude-haiku-4-5-20251001`
- **File**: `libs/core/domain/quality/llm-semantic-analyzer.ts`
- **API Key**: Environment variable `ANTHROPIC_API_KEY`

### Security Storage

- **Format**: JSON, HTML, Markdown, SARIF
- **Location**: `./reportes/{format}/{timestamp}.{ext}`
- **Baselines**: Stored via `BaselineManager` (path traversal protected)
- **Persistence**: File system only (no database)

---

## 🦙 Part 1: Adding Ollama Support

### Architecture Proposal

```
Current (v1.0):
┌────────────────────────────────────┐
│   LLMSemanticAnalyzer              │
│   (hardcoded Anthropic)            │
└────────────────────────────────────┘

Proposed (v1.1+):
┌────────────────────────────────────┐
│   LLMSemanticAnalyzer              │
│   (orchestrator)                   │
└────────────────────────────────────┘
                │
       ┌────────┴────────┬──────────┬──────────┐
       │                 │          │          │
┌──────▼──────┐   ┌──────▼───┐  ┌──▼───┐  ┌───▼────┐
│  Anthropic  │   │  Ollama  │  │ GPT  │  │ Custom │
│   Provider  │   │ Provider │  │ API  │  │ OpenAI │
└─────────────┘   └──────────┘  └──────┘  └────────┘
```

### Implementation Plan

#### Step 1: Create Provider Interface

```typescript
// libs/core/domain/quality/providers/llm-provider.interface.ts

export interface LLMMessage {
  role: "user" | "assistant";
  content: string;
}

export interface LLMResponse {
  text: string;
  usage: {
    inputTokens: number;
    outputTokens: number;
  };
}

export interface LLMProviderConfig {
  apiKey?: string;
  baseUrl?: string;
  model: string;
  timeout?: number;
}

export interface ILLMProvider {
  /**
   * Check if provider is available (API key or local server)
   */
  isAvailable(): Promise<boolean>;

  /**
   * Send message and get response
   */
  complete(
    messages: LLMMessage[],
    options?: {
      maxTokens?: number;
      temperature?: number;
      timeout?: number;
    },
  ): Promise<LLMResponse>;

  /**
   * Estimate cost for input/output tokens
   * Returns 0 for free models (Ollama)
   */
  estimateCost(inputTokens: number, outputTokens: number): number;

  /**
   * Get provider name for display
   */
  getName(): string;
}
```

#### Step 2: Implement Anthropic Provider

```typescript
// libs/core/domain/quality/providers/anthropic-provider.ts

import Anthropic from "@anthropic-ai/sdk";
import {
  ILLMProvider,
  LLMMessage,
  LLMResponse,
  LLMProviderConfig,
} from "./llm-provider.interface";

export class AnthropicProvider implements ILLMProvider {
  private client: Anthropic | null = null;
  private config: LLMProviderConfig;

  // Pricing (Jan 2025)
  private readonly INPUT_COST_PER_MTK = 0.25 / 1_000_000;
  private readonly OUTPUT_COST_PER_MTK = 1.25 / 1_000_000;

  constructor(config: LLMProviderConfig) {
    this.config = config;
  }

  async isAvailable(): Promise<boolean> {
    return this.config.apiKey !== undefined && this.config.apiKey.length > 0;
  }

  private async initClient(): Promise<Anthropic> {
    if (this.client) return this.client;

    if (!this.config.apiKey) {
      throw new Error("Anthropic API key not configured");
    }

    this.client = new Anthropic({ apiKey: this.config.apiKey });
    return this.client;
  }

  async complete(
    messages: LLMMessage[],
    options?: { maxTokens?: number; temperature?: number; timeout?: number },
  ): Promise<LLMResponse> {
    const client = await this.initClient();

    const response = await client.messages.create({
      model: this.config.model || "claude-haiku-4-5-20251001",
      max_tokens: options?.maxTokens || 2000,
      temperature: options?.temperature || 0.2,
      messages: messages.map((m) => ({ role: m.role, content: m.content })),
    });

    const text =
      response.content[0].type === "text" ? response.content[0].text : "";

    return {
      text,
      usage: {
        inputTokens: response.usage.input_tokens,
        outputTokens: response.usage.output_tokens,
      },
    };
  }

  estimateCost(inputTokens: number, outputTokens: number): number {
    return (
      inputTokens * this.INPUT_COST_PER_MTK +
      outputTokens * this.OUTPUT_COST_PER_MTK
    );
  }

  getName(): string {
    return "Anthropic Claude";
  }
}
```

#### Step 3: Implement Ollama Provider

```typescript
// libs/core/domain/quality/providers/ollama-provider.ts

import {
  ILLMProvider,
  LLMMessage,
  LLMResponse,
  LLMProviderConfig,
} from "./llm-provider.interface";

/**
 * Ollama Provider - Local LLM execution
 *
 * Requires:
 * - Ollama installed locally (https://ollama.com/)
 * - Model pulled: `ollama pull llama3.2`
 *
 * API Docs: https://github.com/ollama/ollama/blob/main/docs/api.md
 */
export class OllamaProvider implements ILLMProvider {
  private config: LLMProviderConfig;
  private baseUrl: string;

  constructor(config: LLMProviderConfig) {
    this.config = config;
    this.baseUrl = config.baseUrl || "http://localhost:11434";
  }

  async isAvailable(): Promise<boolean> {
    try {
      const response = await fetch(`${this.baseUrl}/api/tags`, {
        signal: AbortSignal.timeout(5000),
      });
      return response.ok;
    } catch {
      return false;
    }
  }

  async complete(
    messages: LLMMessage[],
    options?: { maxTokens?: number; temperature?: number; timeout?: number },
  ): Promise<LLMResponse> {
    // Convert messages to Ollama format
    const prompt = messages
      .map((m) => `${m.role === "user" ? "User" : "Assistant"}: ${m.content}`)
      .join("\n\n");

    const response = await fetch(`${this.baseUrl}/api/generate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: this.config.model || "llama3.2",
        prompt,
        stream: false,
        options: {
          temperature: options?.temperature || 0.2,
          num_predict: options?.maxTokens || 2000,
        },
      }),
      signal: AbortSignal.timeout(options?.timeout || 60000),
    });

    if (!response.ok) {
      throw new Error(
        `Ollama API error: ${response.status} ${response.statusText}`,
      );
    }

    const data = await response.json();

    return {
      text: data.response,
      usage: {
        inputTokens: data.prompt_eval_count || 0,
        outputTokens: data.eval_count || 0,
      },
    };
  }

  estimateCost(inputTokens: number, outputTokens: number): number {
    // Ollama is free (local execution)
    return 0;
  }

  getName(): string {
    return `Ollama (${this.config.model || "llama3.2"})`;
  }
}
```

#### Step 4: Implement OpenAI Provider

```typescript
// libs/core/domain/quality/providers/openai-provider.ts

import OpenAI from "openai";
import {
  ILLMProvider,
  LLMMessage,
  LLMResponse,
  LLMProviderConfig,
} from "./llm-provider.interface";

export class OpenAIProvider implements ILLMProvider {
  private client: OpenAI | null = null;
  private config: LLMProviderConfig;

  // Pricing (Jan 2025) - GPT-4o-mini
  private readonly INPUT_COST_PER_MTK = 0.15 / 1_000_000;
  private readonly OUTPUT_COST_PER_MTK = 0.6 / 1_000_000;

  constructor(config: LLMProviderConfig) {
    this.config = config;
  }

  async isAvailable(): Promise<boolean> {
    return this.config.apiKey !== undefined && this.config.apiKey.length > 0;
  }

  private async initClient(): Promise<OpenAI> {
    if (this.client) return this.client;

    if (!this.config.apiKey) {
      throw new Error("OpenAI API key not configured");
    }

    this.client = new OpenAI({ apiKey: this.config.apiKey });
    return this.client;
  }

  async complete(
    messages: LLMMessage[],
    options?: { maxTokens?: number; temperature?: number; timeout?: number },
  ): Promise<LLMResponse> {
    const client = await this.initClient();

    const response = await client.chat.completions.create({
      model: this.config.model || "gpt-4o-mini",
      max_tokens: options?.maxTokens || 2000,
      temperature: options?.temperature || 0.2,
      messages: messages.map((m) => ({ role: m.role, content: m.content })),
    });

    const text = response.choices[0].message.content || "";

    return {
      text,
      usage: {
        inputTokens: response.usage?.prompt_tokens || 0,
        outputTokens: response.usage?.completion_tokens || 0,
      },
    };
  }

  estimateCost(inputTokens: number, outputTokens: number): number {
    return (
      inputTokens * this.INPUT_COST_PER_MTK +
      outputTokens * this.OUTPUT_COST_PER_MTK
    );
  }

  getName(): string {
    return "OpenAI GPT";
  }
}
```

#### Step 5: Update LLMSemanticAnalyzer

```typescript
// libs/core/domain/quality/llm-semantic-analyzer.ts (REFACTORED)

import { ILLMProvider } from "./providers/llm-provider.interface";
import { AnthropicProvider } from "./providers/anthropic-provider";
import { OllamaProvider } from "./providers/ollama-provider";
import { OpenAIProvider } from "./providers/openai-provider";

export class LLMSemanticAnalyzer {
  private provider: ILLMProvider | null = null;

  /**
   * Auto-detect available provider based on environment
   */
  async initializeProvider(): Promise<ILLMProvider | null> {
    if (this.provider) return this.provider;

    // Priority order: Anthropic > OpenAI > Ollama
    const providers: Array<{ name: string; provider: ILLMProvider }> = [
      {
        name: "anthropic",
        provider: new AnthropicProvider({
          apiKey: process.env.ANTHROPIC_API_KEY,
          model: "claude-haiku-4-5-20251001",
        }),
      },
      {
        name: "openai",
        provider: new OpenAIProvider({
          apiKey: process.env.OPENAI_API_KEY,
          model: "gpt-4o-mini",
        }),
      },
      {
        name: "ollama",
        provider: new OllamaProvider({
          baseUrl: process.env.OLLAMA_URL || "http://localhost:11434",
          model: process.env.OLLAMA_MODEL || "llama3.2",
        }),
      },
    ];

    // Check which provider is available
    for (const { name, provider } of providers) {
      if (await provider.isAvailable()) {
        console.log(`✓ Using LLM provider: ${provider.getName()}`);
        this.provider = provider;
        return provider;
      }
    }

    return null;
  }

  async analyze(
    discovery: DiscoveryResult,
    options: LLMAnalysisOptions = {},
  ): Promise<LLMSemanticResult> {
    const provider = await this.initializeProvider();

    if (!provider) {
      return {
        enabled: false,
        findings: [],
        error:
          "No LLM provider available. Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or run Ollama locally.",
      };
    }

    const prompt = this.buildAnalysisPrompt(discovery);

    const response = await provider.complete(
      [{ role: "user", content: prompt }],
      {
        maxTokens: options.maxTokens || 2000,
        temperature: options.temperature || 0.2,
        timeout: options.timeout || 30000,
      },
    );

    const findings = this.parseFindings(response.text);

    return {
      enabled: true,
      findings,
      cost: {
        inputTokens: response.usage.inputTokens,
        outputTokens: response.usage.outputTokens,
        estimatedCostUSD: provider.estimateCost(
          response.usage.inputTokens,
          response.usage.outputTokens,
        ),
      },
    };
  }
}
```

#### Step 6: CLI Configuration

```bash
# User can choose provider via environment variables

# Option 1: Anthropic (cloud, paid)
export ANTHROPIC_API_KEY="sk-ant-api03-..."

# Option 2: OpenAI (cloud, paid)
export OPENAI_API_KEY="sk-..."

# Option 3: Ollama (local, free)
ollama pull llama3.2
export OLLAMA_MODEL="llama3.2"  # Optional, defaults to llama3.2

# Option 4: Custom Ollama URL (remote server)
export OLLAMA_URL="http://192.168.1.100:11434"
export OLLAMA_MODEL="codellama:7b"
```

#### Step 7: Update Documentation

````markdown
# README.md - Add LLM Configuration Section

## 🤖 LLM-Powered Semantic Analysis

mcp-verify supports multiple LLM providers for deep semantic validation:

| Provider             | Type      | Cost                | Setup                                   |
| -------------------- | --------- | ------------------- | --------------------------------------- |
| **Anthropic Claude** | Cloud API | ~$0.0003/validation | `export ANTHROPIC_API_KEY=...`          |
| **OpenAI GPT**       | Cloud API | ~$0.0002/validation | `export OPENAI_API_KEY=...`             |
| **Ollama**           | Local     | Free                | Install Ollama + `ollama pull llama3.2` |

### Quick Start with Ollama (Free)

```bash
# 1. Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# 2. Pull model
ollama pull llama3.2

# 3. Run validation
mcp-verify validate http://localhost:3000 --security
```
````

The tool will auto-detect available providers in this order:

1. Anthropic (if `ANTHROPIC_API_KEY` set)
2. OpenAI (if `OPENAI_API_KEY` set)
3. Ollama (if running on localhost:11434)

### Recommended Models

| Provider  | Model              | Speed          | Quality    | Cost    |
| --------- | ------------------ | -------------- | ---------- | ------- |
| Anthropic | `claude-haiku-4-5` | ⚡ Fast        | ⭐⭐⭐⭐⭐ | $0.0003 |
| OpenAI    | `gpt-4o-mini`      | ⚡ Fast        | ⭐⭐⭐⭐   | $0.0002 |
| Ollama    | `llama3.2` (3B)    | ⚡⚡ Very Fast | ⭐⭐⭐     | Free    |
| Ollama    | `codellama:13b`    | 🐌 Slow        | ⭐⭐⭐⭐   | Free    |

```

---

## 🔒 Part 2: Security Storage Architecture

### Current Implementation (v1.0)

```

┌─────────────────────────────────────────────────────┐
│ mcp-verify validate │
└─────────────────────────────────────────────────────┘
│
▼
┌─────────────────────────────────────────────────────┐
│ Validation Engine │
│ (discovers, validates, applies security rules) │
└─────────────────────────────────────────────────────┘
│
▼
┌─────────────────────────────────────────────────────┐
│ Generate Report │
│ (JSON, HTML, Markdown, SARIF) │
└─────────────────────────────────────────────────────┘
│
▼
┌─────────────────────────────────────────────────────┐
│ Write to File System │
│ │
│ ./reportes/ │
│ ├── json/2026-02-03_10-30-00.json │
│ ├── html/2026-02-03_10-30-00.html │
│ ├── markdown/2026-02-03_10-30-00.md │
│ └── sarif/2026-02-03_10-30-00.sarif │
└─────────────────────────────────────────────────────┘

````

**File**: `apps/cli-verifier/src/commands/validate.ts:206-227`

```typescript
// Current storage implementation
const outputDir = PathValidator.validateOutputPath(
  String(options.output || './reportes'),
  './reportes'
);

const jsonDir = path.join(outputDir, 'json');
const htmlDir = path.join(outputDir, 'html');
const mdDir = path.join(outputDir, 'markdown');
const sarifDir = path.join(outputDir, 'sarif');

fs.mkdirSync(jsonDir, { recursive: true });
fs.mkdirSync(htmlDir, { recursive: true });
fs.mkdirSync(mdDir, { recursive: true });

const reportPath = path.join(jsonDir, `${filenameBase}.json`);
fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));

const htmlContent = HtmlReportGenerator.generate(report);
fs.writeFileSync(path.join(htmlDir, `${filenameBase}.html`), htmlContent);

const mdContent = MarkdownReportGenerator.generate(report);
fs.writeFileSync(path.join(mdDir, `${filenameBase}.md`), mdContent);
````

### Security Report Structure

```json
{
  "metadata": {
    "timestamp": "2026-02-03T10:30:00Z",
    "target": "http://localhost:3000",
    "duration": 4532,
    "mcpVerifyVersion": "1.0.0"
  },
  "summary": {
    "score": 82,
    "rulesApplied": 47,
    "passed": 42,
    "failed": 5,
    "warnings": 3
  },
  "security": {
    "criticalFindings": [
      {
        "rule": "command-injection",
        "tool": "execute_shell",
        "severity": "critical",
        "description": "Tool allows arbitrary command execution with shell metacharacters",
        "evidence": "Parameter 'cmd' allows ';', '|', '&&'",
        "recommendation": "Use allowlist of safe commands"
      }
    ],
    "highFindings": [...],
    "mediumFindings": [...]
  },
  "toolDetails": [...]
}
```

### Baseline Storage

**File**: `libs/core/infrastructure/reporting/baseline-manager.ts` (assumed)

```typescript
// Baseline saved to user-specified path
BaselineManager.saveBaseline(report, "./baselines/prod-v1.0.json");

// Comparison loads both files and diffs
const diff = BaselineManager.compare(
  "./baselines/prod-v1.0.json",
  currentReport,
);
```

### Limitations of Current Approach

1. **No Historical Tracking**
   - Each report is independent
   - No trend analysis (is security improving over time?)
   - No easy way to query "all validations for server X"

2. **No Metadata Index**
   - To list all reports, must scan directory
   - No filtering by date, target, score
   - No search functionality

3. **No Audit Trail**
   - Who ran the validation?
   - What CLI arguments were used?
   - Was it triggered manually or by CI?

4. **No Deduplication**
   - Same finding appears in every report
   - No "this is a known issue" marking

5. **No Persistence of "Resolved" Status**
   - Can't mark finding as "accepted risk"
   - Can't assign ownership
   - Can't track remediation

---

## 🚀 Proposed: Enhanced Security Storage (v1.2+)

### Architecture

```
┌─────────────────────────────────────────────────────┐
│         Security Findings Database                  │
│              (SQLite3)                              │
│                                                     │
│  Tables:                                           │
│  - validations (id, timestamp, target, score)      │
│  - findings (id, validation_id, rule, severity)    │
│  - baselines (id, target, approved_by)             │
│  - suppressions (finding_hash, reason, expires)    │
│  - audit_log (user, action, timestamp)             │
└─────────────────────────────────────────────────────┘
```

### Schema Design

```sql
-- Validations (one per mcp-verify run)
CREATE TABLE validations (
  id TEXT PRIMARY KEY,
  timestamp INTEGER NOT NULL,
  target TEXT NOT NULL,
  score INTEGER NOT NULL,
  duration_ms INTEGER,
  cli_version TEXT,
  user TEXT,
  ci_context TEXT, -- GitHub Actions, Jenkins, etc.
  exit_code INTEGER,
  created_at INTEGER DEFAULT (strftime('%s', 'now'))
);

-- Security Findings (many per validation)
CREATE TABLE findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  validation_id TEXT NOT NULL REFERENCES validations(id),
  finding_hash TEXT UNIQUE, -- SHA256 of normalized finding
  type TEXT, -- 'tool' | 'resource' | 'prompt'
  name TEXT,
  rule TEXT, -- 'command-injection', 'sql-injection', etc.
  severity TEXT, -- 'critical' | 'high' | 'medium' | 'low'
  description TEXT,
  evidence TEXT,
  recommendation TEXT,
  first_seen INTEGER, -- Timestamp of first occurrence
  last_seen INTEGER,  -- Timestamp of last occurrence
  occurrence_count INTEGER DEFAULT 1,
  status TEXT DEFAULT 'open', -- 'open' | 'accepted_risk' | 'fixed' | 'false_positive'
  assigned_to TEXT,
  notes TEXT
);

-- Suppressions (ignore specific findings)
CREATE TABLE suppressions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  finding_hash TEXT NOT NULL,
  reason TEXT NOT NULL,
  suppressed_by TEXT,
  suppressed_at INTEGER DEFAULT (strftime('%s', 'now')),
  expires_at INTEGER, -- NULL = permanent
  UNIQUE(finding_hash)
);

-- Audit Log (who did what, when)
CREATE TABLE audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user TEXT,
  action TEXT, -- 'validate', 'suppress', 'baseline_update'
  target TEXT,
  timestamp INTEGER DEFAULT (strftime('%s', 'now')),
  metadata TEXT -- JSON blob
);

-- Indexes for fast queries
CREATE INDEX idx_findings_validation ON findings(validation_id);
CREATE INDEX idx_findings_rule ON findings(rule);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_status ON findings(status);
CREATE INDEX idx_validations_target ON validations(target);
CREATE INDEX idx_validations_timestamp ON validations(timestamp);
```

### CLI Commands (Proposed)

```bash
# List all validations
mcp-verify history
mcp-verify history --target http://localhost:3000 --last 30days

# Show findings from specific validation
mcp-verify findings abc123

# Suppress a specific finding
mcp-verify suppress <finding-hash> --reason "False positive - uses ORM"

# Mark finding as accepted risk
mcp-verify accept <finding-hash> --reason "Legacy code, low priority"

# Show trend analysis
mcp-verify trends http://localhost:3000 --since 2026-01-01

# Export security audit report
mcp-verify audit --output audit-report.pdf --from 2026-01-01 --to 2026-02-01
```

### Benefits

1. **Historical Analysis**
   - "Is security improving over time?"
   - "Which findings keep reappearing?"
   - "How long did it take to fix critical issues?"

2. **Deduplication**
   - Finding hash prevents duplicates
   - Track when finding first/last seen
   - Count occurrences

3. **Workflow Integration**
   - Assign findings to developers
   - Track status (open → in progress → fixed)
   - Accept risks with justification

4. **Audit Trail**
   - Who suppressed which finding?
   - Who approved baselines?
   - When was last validation run?

5. **CI/CD Integration**
   - Fail build if NEW critical findings (not just any critical)
   - Allow "inherited" issues from baseline
   - Generate compliance reports

---

## 📊 Comparison: Current vs Proposed

| Feature                 | v1.0 (Files)         | v1.2+ (SQLite)       |
| ----------------------- | -------------------- | -------------------- |
| **Storage**             | JSON files           | SQLite DB            |
| **Historical tracking** | ❌ No                | ✅ Yes               |
| **Deduplication**       | ❌ No                | ✅ Yes (by hash)     |
| **Trend analysis**      | ❌ No                | ✅ Yes               |
| **Suppressions**        | ❌ No                | ✅ Yes (with expiry) |
| **Audit trail**         | ❌ No                | ✅ Yes               |
| **Query performance**   | 🐌 Slow (scan files) | ⚡ Fast (indexed)    |
| **Collaboration**       | ⚠️ Git only          | ✅ DB can be shared  |
| **CI/CD integration**   | ⚠️ Basic             | ✅ Advanced          |

---

## 📝 Notes

### Why SQLite?

- **Single file** (portable, easy backup)
- **No server** (zero config)
- **Fast** (50,000+ reads/sec)
- **Reliable** (ACID compliant)
- **Universal** (works on all platforms)

### Why Not PostgreSQL/MySQL?

- Overkill for local CLI tool
- Requires server setup
- Not portable (can't commit to git)
- mcp-verify should be **zero-config**

### Privacy Considerations

- Database stored locally (not uploaded)
- User controls retention (can delete old validations)
- No telemetry sent to cloud
- Compatible with air-gapped environments

---

## 🤝 Contributing

To implement these features:

1. **Ollama Support**: Start with `OllamaProvider` + tests
2. **SQLite Schema**: Review schema with team before implementation
3. **Migration**: Write tool to migrate existing JSON reports to DB

Questions? Open a GitHub Discussion or contact [@maintainer].
