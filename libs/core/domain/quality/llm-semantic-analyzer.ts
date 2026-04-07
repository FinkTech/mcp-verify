/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * LLM Semantic Analyzer - Multi-Provider Support
 *
 * Purpose: Deep semantic validation using LLMs to detect:
 * - Description vs. behavior mismatches
 * - Misleading tool names
 * - Unclear or ambiguous descriptions
 * - Security concerns in tool capabilities
 *
 * Features:
 * - Multi-provider support (Anthropic, Gemini, Ollama, OpenAI)
 * - User must explicitly choose provider (no defaults)
 * - Graceful degradation (works without LLM)
 * - Structured analysis with reasoning
 * - Integration with existing SemanticAnalyzer
 *
 * @module libs/core/domain/quality/llm-semantic-analyzer
 */

import * as crypto from "crypto";
import { t } from "@mcp-verify/shared";
import type { DiscoveryResult } from "../mcp-server/entities/validation.types";
import type { McpTool, McpResource, McpPrompt } from "../shared/common.types";
import type {
  ILLMProvider,
  LLMMessage,
} from "./providers/llm-provider.interface";
import { AnthropicProvider } from "./providers/anthropic-provider";
import { GeminiProvider } from "./providers/gemini-provider";
import { OllamaProvider } from "./providers/ollama-provider";
import { OpenAIProvider } from "./providers/openai-provider";

export interface LLMSemanticFinding {
  type: "tool" | "resource" | "prompt";
  name: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  issue: string;
  reasoning: string;
  recommendation?: string;
}

export interface LLMSemanticResult {
  enabled: boolean;
  findings: LLMSemanticFinding[];
  error?: string;
  provider?: string;
  usage?: {
    inputTokens: number;
    outputTokens: number;
  };
}

export interface LLMAnalysisOptions {
  maxTokens?: number;
  temperature?: number;
  timeout?: number;
  bypassCache?: boolean;
  /**
   * LLM provider specification
   * Format: "provider:model"
   *
   * Examples:
   * - "anthropic:claude-haiku-4-5-20251001"
   * - "ollama:llama3.2"
   * - "openai:gpt-4o-mini"
   *
   * REQUIRED: User must explicitly specify which LLM to use
   */
  llmProvider?: string;
}

/**
 * Cache entry for LLM analysis results
 */
interface CacheEntry {
  result: LLMSemanticResult;
  timestamp: number;
}

/**
 * LLM-powered semantic analyzer with multi-provider support
 */
export class LLMSemanticAnalyzer {
  private provider: ILLMProvider | null = null;

  // In-memory cache for LLM analysis results
  private readonly cache: Map<string, CacheEntry> = new Map();
  private readonly CACHE_TTL_MS = 1000 * 60 * 60 * 24; // 24 hours

  /**
   * Check if LLM analysis is available
   * NOTE: Always returns true now. Actual availability is checked per provider.
   */
  async isAvailable(): Promise<boolean> {
    return true;
  }

  /**
   * Initialize LLM provider from user specification
   *
   * @param providerSpec - Format: "provider:model" (e.g., "anthropic:claude-haiku-4-5")
   * @returns ILLMProvider instance or null if unavailable
   */
  async initializeProvider(
    providerSpec?: string,
  ): Promise<ILLMProvider | null> {
    if (!providerSpec) {
      return null;
    }

    // Parse provider specification
    const [providerName, model] = providerSpec.split(":");

    if (!providerName || !model) {
      throw new Error(t("llm_invalid_spec", { spec: providerSpec }));
    }

    // Create provider based on name
    try {
      let provider: ILLMProvider;

      switch (providerName.toLowerCase()) {
        case "anthropic": {
          const apiKey = process.env.ANTHROPIC_API_KEY;

          // Validate API key format
          if (!apiKey) {
            throw new Error(t("llm_env_not_set", { provider: "ANTHROPIC" }));
          }
          if (!apiKey.startsWith("sk-ant-")) {
            throw new Error(
              t("llm_key_invalid_format", { provider: "ANTHROPIC" }),
            );
          }
          if (apiKey.length < 20) {
            throw new Error(t("llm_key_too_short", { provider: "ANTHROPIC" }));
          }

          provider = new AnthropicProvider({
            apiKey: apiKey,
            model: model,
          });
          break;
        }

        case "ollama":
          provider = new OllamaProvider({
            baseUrl: process.env.OLLAMA_URL || "http://localhost:11434",
            model: model,
          });
          break;

        case "openai": {
          const apiKey = process.env.OPENAI_API_KEY;

          // Validate API key format
          if (!apiKey) {
            throw new Error(t("llm_env_not_set", { provider: "OPENAI" }));
          }
          if (!apiKey.startsWith("sk-")) {
            throw new Error(
              t("llm_key_invalid_format", { provider: "OPENAI" }),
            );
          }
          if (apiKey.length < 20) {
            throw new Error(t("llm_key_too_short", { provider: "OPENAI" }));
          }

          provider = new OpenAIProvider({
            apiKey: apiKey,
            model: model,
          });
          break;
        }

        case "gemini":
        case "google": {
          const apiKey =
            process.env.GOOGLE_API_KEY || process.env.GEMINI_API_KEY;

          // Validate API key format
          if (!apiKey) {
            throw new Error(t("llm_env_not_set", { provider: "GOOGLE" }));
          }
          if (!apiKey.startsWith("AIza")) {
            throw new Error(
              t("llm_key_invalid_format", { provider: "GOOGLE" }),
            );
          }
          if (apiKey.length < 20) {
            throw new Error(t("llm_key_too_short", { provider: "GOOGLE" }));
          }

          provider = new GeminiProvider({
            apiKey: apiKey,
            model: model,
          });
          break;
        }

        default:
          throw new Error(
            t("llm_unknown_provider", { provider: providerName }),
          );
      }

      // Check if provider is available
      const isAvailable = await provider.isAvailable();

      if (!isAvailable) {
        return null;
      }

      this.provider = provider;
      return provider;
    } catch (error: unknown) {
      throw new Error(
        t("llm_init_failed", { provider: providerName, error: (error as Error).message }),
      );
    }
  }

  /**
   * Generate cache key from discovery result
   */
  private generateCacheKey(discovery: DiscoveryResult): string {
    // Create a stable hash of the discovery content
    const content = JSON.stringify({
      tools: discovery.tools?.map((t) => ({
        name: t.name,
        description: t.description,
        inputSchema: t.inputSchema,
      })),
      resources: discovery.resources?.map((r) => ({
        name: r.name,
        uri: r.uri,
        description: r.description,
      })),
      prompts: discovery.prompts?.map((p) => ({
        name: p.name,
        description: p.description,
        arguments: p.arguments,
      })),
    });

    return crypto.createHash("sha256").update(content).digest("hex");
  }

  /**
   * Get cached result if available and not expired
   */
  private getCachedResult(cacheKey: string): LLMSemanticResult | null {
    const entry = this.cache.get(cacheKey);
    if (!entry) {
      return null;
    }

    // Check if cache entry is expired
    const age = Date.now() - entry.timestamp;
    if (age > this.CACHE_TTL_MS) {
      this.cache.delete(cacheKey);
      return null;
    }

    return entry.result;
  }

  /**
   * Store result in cache
   */
  private setCachedResult(cacheKey: string, result: LLMSemanticResult): void {
    this.cache.set(cacheKey, {
      result,
      timestamp: Date.now(),
    });
  }

  /**
   * Analyze discovery results using LLM (with caching)
   */
  async analyze(
    discovery: DiscoveryResult,
    options: LLMAnalysisOptions = {},
  ): Promise<LLMSemanticResult> {
    const {
      maxTokens = 2000,
      temperature = 0.2,
      timeout = 30000,
      bypassCache = false,
    } = options;

    // Check cache first (unless bypassed)
    if (!bypassCache) {
      const cacheKey = this.generateCacheKey(discovery);
      const cachedResult = this.getCachedResult(cacheKey);
      if (cachedResult) {
        return cachedResult;
      }
    }

    // Initialize provider if specified
    if (options.llmProvider) {
      try {
        await this.initializeProvider(options.llmProvider);
      } catch (error: unknown) {
        return {
          enabled: false,
          findings: [],
          error: (error as Error).message,
        };
      }
    }

    // Check if provider is initialized
    if (!this.provider) {
      return {
        enabled: false,
        findings: [],
        error:
          t("llm_no_provider_specified") + "\n\n" + t("llm_examples_block"),
      };
    }

    try {
      // Build prompt with anti-injection measures
      const prompt = this.buildAnalysisPrompt(discovery);

      // Call LLM
      const response = await this.provider.complete(
        [{ role: "user", content: prompt }],
        {
          maxTokens,
          temperature,
          timeout,
        },
      );

      // Parse findings
      const findings = this.parseFindings(response.text);

      const result: LLMSemanticResult = {
        enabled: true,
        findings,
        provider: this.provider.getName(),
        usage: {
          inputTokens: response.usage.inputTokens,
          outputTokens: response.usage.outputTokens,
        },
      };

      // Cache the result
      if (!bypassCache) {
        const cacheKey = this.generateCacheKey(discovery);
        this.setCachedResult(cacheKey, result);
      }

      return result;
    } catch (error: unknown) {
      // Handle provider-specific errors gracefully
      if ((error as Error).message.includes("timeout")) {
        return {
          enabled: false,
          findings: [],
          error: t("llm_request_timeout"),
        };
      }

      const errorMessage = (error as Error).message;

      if (errorMessage.includes("authentication") || errorMessage.includes("401")) {
        return {
          enabled: false,
          findings: [],
          error: t("llm_api_key_invalid"),
        };
      }

      if (errorMessage.includes("rate limit") || errorMessage.includes("429")) {
        return {
          enabled: false,
          findings: [],
          error: t("llm_rate_limit"),
        };
      }

      // Generic error
      return {
        enabled: false,
        findings: [],
        error: t("llm_analysis_failed", { error: errorMessage }),
      };
    }
  }

  /**
   * Build structured prompt for LLM with enhanced security analysis
   */
  private buildAnalysisPrompt(discovery: DiscoveryResult): string {
    const toolsSection =
      discovery.tools && discovery.tools.length > 0
        ? this.formatTools(discovery.tools)
        : t("llm_no_tools");

    const resourcesSection =
      discovery.resources && discovery.resources.length > 0
        ? this.formatResources(discovery.resources)
        : t("llm_no_resources");

    const promptsSection =
      discovery.prompts && discovery.prompts.length > 0
        ? this.formatPrompts(discovery.prompts)
        : t("llm_no_prompts");

    // Detect potential tool chains for indirect injection analysis
    const toolChainAnalysis = this.buildToolChainAnalysisSection(
      discovery.tools || [],
    );

    return `You are a senior security engineer specialized in LLM security (OWASP LLM Top 10) reviewing an MCP (Model Context Protocol) server.

Your task: Perform deep semantic analysis focusing on security vulnerabilities, especially Prompt Injection risks.

# PRIMARY FOCUS AREAS

## 1. Direct Prompt Injection
- Parameters accepting free-form text that will be processed by an LLM
- Missing input validation (maxLength, pattern) on text inputs
- Parameters named: prompt, message, instruction, query, text, content

## 2. Indirect Prompt Injection (CRITICAL - OWASP LLM01)
Identify tool chains where external content flows to LLM processing:
- Tool A fetches URL/file/email → Tool B summarizes/translates/analyzes content
- Single tools that BOTH fetch AND process: "fetch_and_summarize", "read_url_then_reply"
- Resources that read external content which is later processed

Example dangerous patterns:
- "fetch_webpage" + "summarize_text" = Attacker embeds injection in webpage
- "read_email" + "reply_to_email" = Attacker sends email with hidden instructions
- "load_document" where description says "extracts key points" = Document contains injection

## 3. Description vs. Behavior Mismatch
- Tool claims to "read" but can also write/delete
- Description mentions "safe" but accepts arbitrary commands
- Name suggests limited scope but parameters allow more

## 4. Input Validation Gaps
- String parameters without maxLength (prompt stuffing attacks)
- URL parameters without domain restrictions (SSRF + indirect injection)
- File path parameters without path validation

# MCP Server Capabilities
${toolChainAnalysis}
## Tools
${toolsSection}

## Resources
${resourcesSection}

## Prompts
${promptsSection}

# Response Format

For each finding, output in this EXACT format:

FINDING:
Type: [tool|resource|prompt]
Name: [name]
Severity: [critical|high|medium|low|info]
Issue: [one-line issue description]
Reasoning: [detailed explanation with evidence from the schema/description]
Recommendation: [specific, actionable fix with example code/config if applicable]

IMPORTANT:
- Mark CRITICAL: Any indirect prompt injection chain (fetch → process)
- Mark HIGH: Direct prompt injection vectors without validation
- Mark MEDIUM: Missing input limits on text fields
- Mark LOW: Minor description clarity issues

If no issues found, respond with: "NO_FINDINGS"

Begin your analysis:`;
  }

  /**
   * Analyze tools for potential injection chains
   */
  private buildToolChainAnalysisSection(tools: McpTool[]): string {
    if (tools.length === 0) return "";

    const fetchTools: string[] = [];
    const processTools: string[] = [];
    const combinedTools: string[] = [];

    const fetchKeywords = [
      "fetch",
      "read",
      "load",
      "download",
      "get_url",
      "scrape",
      "crawl",
      "import",
      "email",
      "file",
    ];
    const processKeywords = [
      "summarize",
      "translate",
      "analyze",
      "extract",
      "parse",
      "respond",
      "reply",
      "generate",
      "process",
    ];

    for (const tool of tools) {
      const text = `${tool.name} ${tool.description || ""}`.toLowerCase();

      const hasFetch = fetchKeywords.some((kw) => text.includes(kw));
      const hasProcess = processKeywords.some((kw) => text.includes(kw));

      if (hasFetch && hasProcess) {
        combinedTools.push(tool.name);
      } else if (hasFetch) {
        fetchTools.push(tool.name);
      } else if (hasProcess) {
        processTools.push(tool.name);
      }
    }

    if (
      combinedTools.length === 0 &&
      (fetchTools.length === 0 || processTools.length === 0)
    ) {
      return "";
    }

    let section = "## ⚠️ Potential Indirect Injection Vectors\n\n";

    if (combinedTools.length > 0) {
      section += `**CRITICAL RISK - Combined Fetch+Process Tools:**\n`;
      section += combinedTools.map((t) => `- ${t}`).join("\n");
      section +=
        "\n\nThese tools BOTH fetch external content AND process it. High risk of indirect injection.\n\n";
    }

    if (fetchTools.length > 0 && processTools.length > 0) {
      section += `**HIGH RISK - Tool Chain:**\n`;
      section += `- Fetch tools: ${fetchTools.join(", ")}\n`;
      section += `- Process tools: ${processTools.join(", ")}\n`;
      section +=
        "\nIf these tools can be chained (output of fetch → input of process), indirect injection is possible.\n\n";
    }

    return section;
  }

  /**
   * Format tools for prompt
   */
  private formatTools(tools: McpTool[]): string {
    return tools
      .map(
        (tool) => `
**${tool.name}**
Description: ${tool.description || t("llm_no_description")}
Input Schema: ${JSON.stringify(tool.inputSchema || {}, null, 2)}
`,
      )
      .join("\n---\n");
  }

  /**
   * Format resources for prompt
   */
  private formatResources(resources: McpResource[]): string {
    return resources
      .map(
        (resource) => `
**${resource.name}**
URI: ${resource.uri}
Description: ${resource.description || t("llm_no_description")}
MIME Type: ${resource.mimeType || "Not specified"}
`,
      )
      .join("\n---\n");
  }

  /**
   * Format prompts for prompt (meta!)
   */
  private formatPrompts(prompts: McpPrompt[]): string {
    return prompts
      .map(
        (prompt) => `
**${prompt.name}**
Description: ${prompt.description || t("llm_no_description")}
Arguments: ${JSON.stringify(prompt.arguments || [], null, 2)}
`,
      )
      .join("\n---\n");
  }

  /**
   * Parse structured findings from LLM's response
   */
  private parseFindings(text: string): LLMSemanticFinding[] {
    if (text.includes("NO_FINDINGS")) {
      return [];
    }

    const findings: LLMSemanticFinding[] = [];
    const findingBlocks = text.split("FINDING:").slice(1); // Skip first empty split

    for (const block of findingBlocks) {
      try {
        const lines = block.trim().split("\n");
        const finding: Partial<LLMSemanticFinding> = {};

        for (const line of lines) {
          const [key, ...valueParts] = line.split(":");
          const value = valueParts.join(":").trim();

          if (!key || !value) continue;

          const normalizedKey = key.trim().toLowerCase();

          if (normalizedKey === "type") {
            const type = value.toLowerCase();
            if (type === "tool" || type === "resource" || type === "prompt") {
              finding.type = type;
            }
          } else if (normalizedKey === "name") {
            finding.name = value;
          } else if (normalizedKey === "severity") {
            const severity = value.toLowerCase();
            if (
              severity === "critical" ||
              severity === "high" ||
              severity === "medium" ||
              severity === "low" ||
              severity === "info"
            ) {
              finding.severity = severity;
            }
          } else if (normalizedKey === "issue") {
            finding.issue = value;
          } else if (normalizedKey === "reasoning") {
            finding.reasoning = value;
          } else if (normalizedKey === "recommendation") {
            finding.recommendation = value;
          }
        }

        // Validate required fields
        if (
          finding.type &&
          finding.name &&
          finding.severity &&
          finding.issue &&
          finding.reasoning
        ) {
          findings.push(finding as LLMSemanticFinding);
        }
      } catch (error) {
        // Skip malformed findings
        continue;
      }
    }

    return findings;
  }
}
