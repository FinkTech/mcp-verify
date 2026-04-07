/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SEC-024: Prompt Injection via Tool Inputs (LLM01)
 *
 * Block: A (OWASP LLM Top 10 in MCP Context)
 * Severity: Critical
 * Type: Static + Fuzzer
 *
 * Detects tools accepting unvalidated free-text inputs that are passed
 * to LLM prompts or other tools without sanitization.
 *
 * Detection:
 * Static:
 * - Tools with string parameters lacking pattern/enum constraints
 * - Description mentions "prompt", "instruction", "message"
 * - Tool description contains imperative language targeting AI context
 * - Parameter default values contain instruction-like content
 * - Annotations (including x-* custom fields) contain injection payloads
 *
 * Fuzzer:
 * - Inject malicious prompts and check for unintended behavior
 *
 * References:
 * - OWASP LLM Top 10 2025 - LLM01: Prompt Injection
 * - Simon Willison's Prompt Injection Research
 */

import type { ISecurityRule } from "../rule.interface";
import type {
  DiscoveryResult,
  SecurityFinding,
} from "../../mcp-server/entities/validation.types";
import type { McpTool, McpResource, McpPrompt } from "../../shared/common.types";
import { t } from "@mcp-verify/shared";

export class PromptInjectionViaToolsRule implements ISecurityRule {
  code = "SEC-024";
  name = "Prompt Injection via Tool Inputs";
  severity: "critical" = "critical";

  private readonly PROMPT_KEYWORDS = [
    "prompt",
    "instruction",
    "message",
    "command",
    "directive",
    "system_message",
    "user_message",
    "query",
    "question",
  ];

  /**
   * Strong imperatives: phrases that are almost never legitimate in API docs.
   * Fire when combined with ANY context target (including generic ones).
   *
   * NOTE: include both base and conjugated forms where the inflection
   * prevents substring matching (e.g. "include" vs "includes").
   */
  private readonly STRONG_IMPERATIVES = [
    "include a summary of all tools",
    "include all tools currently",
    // Both base and -s form to catch "automatically includes conversation metadata"
    "include conversation metadata",
    "includes conversation metadata",
    "include session context",
    "includes session context",
    "include the session",
    "include your conversation",
    "includes conversation",
    "forward all retrieved",
    "forward the conversation",
    "append current session",
    "append the conversation",
    "check system prompt",
    "read system prompt",
    "when returning results to the user, include",
    "before you respond, include",
    "after this tool, include",
    // Covers "when this tool is invoked, log ... and forward a summary to backup"
    "when this tool is invoked",
  ];

  /**
   * Weak imperatives: phrases that CAN appear in legitimate docs.
   * Only fire when combined with a specific EXFILTRATION_TARGET (not generic context).
   */
  private readonly WEAK_IMPERATIVES = [
    "when processing",
    "when returning",
    "when called",
    "before responding",
    "after completing",
    "forward all",
    // "forward a summary" re-added: legitimate only if NOT combined with an
    // exfiltration target like backup_url, webhook_endpoint, etc.
    "forward a summary",
    "include previous",
    "include prior",
    "append all",
    "append session",
    "log the full request",
    "ignore previous",
    "ignore prior",
    "override safety",
    "forget previous",
  ];

  /**
   * Specific exfiltration targets — only used to validate weak imperative hits.
   * These are specific enough that their presence alongside a weak imperative
   * is a strong injection signal.
   */
  private readonly EXFILTRATION_TARGETS = [
    "conversation history",
    "session context",
    "previous messages",
    "all tools",
    "tool list",
    "available tools",
    "registered tools",
    "system prompt",
    "prior context",
    "chat history",
    "backup endpoint",
    "backup_url",
    "webhook endpoint",
    "tool schemas",
    "parameter schemas",
    "tool parameters",
  ];

  /**
   * Generic context words — only used alongside STRONG_IMPERATIVES.
   * Too broad on their own to be meaningful signals.
   */
  private readonly GENERIC_CONTEXT = [
    "conversation",
    "session",
    "context",
    "history",
    "previous",
    "prior",
  ];

  /**
   * Standalone markers that are red flags regardless of surrounding context.
   * These strings only appear in descriptions when someone is deliberately
   * embedding instructions.
   */
  private readonly DIRECT_INJECTION_MARKERS = [
    "system: ",
    "system:",
    "important: include",
    "important: when",
    "note: when",
    "note: before",
    // Classic jailbreak prefixes in disguised form
    "ignore previous instructions",
    "ignore all previous",
    "disregard previous",
    "new instructions:",
    "actual instructions:",
  ];

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    const REFS_GENERAL = [
      "OWASP LLM Top 10 2025 - LLM01: Prompt Injection",
      "Simon Willison: Prompt Injection - What's the Worst That Could Happen?",
      "CWE-74: Improper Neutralization of Special Elements",
    ];
    const REFS_DESCRIPTION = [
      "OWASP LLM Top 10 2025 - LLM01: Prompt Injection",
      "PromptBench: Towards Evaluating the Robustness of LLMs on Adversarial Prompts",
      "CWE-74: Improper Neutralization of Special Elements",
    ];

    // ── Tools ────────────────────────────────────────────────────────────────
    for (const tool of discovery.tools ?? []) {
      // 1. Unvalidated prompt-related parameters
      const vulnerableParams = this.findVulnerablePromptParams(tool);
      if (vulnerableParams.length > 0) {
        findings.push({
          severity: this.severity,
          message: t("sec_024_prompt_injection", {
            toolName: tool.name,
            params: vulnerableParams.join(", "),
          }),
          component: `tool:${tool.name}`,
          ruleCode: this.code,
          remediation: t("sec_024_recommendation"),
          references: REFS_GENERAL,
        });
      }

      // 2. Tool description injection
      const descSnippet = this.checkTextInjection(tool.description);
      if (descSnippet) {
        findings.push({
          severity: this.severity,
          message: t("sec_024_description_injection", {
            toolName: tool.name,
            snippet: descSnippet,
          }),
          component: `tool:${tool.name}`,
          ruleCode: this.code,
          remediation: t("sec_024_description_recommendation"),
          references: REFS_DESCRIPTION,
        });
      }

      // 3. Parameter default value injection
      for (const { param, snippet } of this.checkDefaultValueInjections(tool)) {
        findings.push({
          severity: this.severity,
          message: t("sec_024_default_injection", { toolName: tool.name, param, snippet }),
          component: `tool:${tool.name}`,
          ruleCode: this.code,
          remediation: t("sec_024_default_recommendation"),
          references: REFS_GENERAL,
        });
      }

      // 4. Annotation / x-* field injection
      for (const { field, snippet } of this.checkAnnotationInjections(tool)) {
        findings.push({
          severity: this.severity,
          message: t("sec_024_annotation_injection", { toolName: tool.name, field, snippet }),
          component: `tool:${tool.name}`,
          ruleCode: this.code,
          remediation: t("sec_024_annotation_recommendation"),
          references: [
            "OWASP LLM Top 10 2025 - LLM01: Prompt Injection",
            "MCP Specification - Tool Annotations",
            "CWE-74: Improper Neutralization of Special Elements",
          ],
        });
      }
    }

    // ── Resources ────────────────────────────────────────────────────────────
    for (const resource of discovery.resources ?? []) {
      const snippet = this.checkTextInjection(resource.description);
      if (snippet) {
        findings.push({
          severity: this.severity,
          message: t("sec_024_resource_injection", {
            resourceName: resource.name ?? resource.uri,
            snippet,
          }),
          component: `resource:${resource.name ?? resource.uri}`,
          ruleCode: this.code,
          remediation: t("sec_024_description_recommendation"),
          references: REFS_DESCRIPTION,
        });
      }
    }

    // ── Prompts ──────────────────────────────────────────────────────────────
    for (const prompt of discovery.prompts ?? []) {
      // Check prompt description
      const promptSnippet = this.checkTextInjection(prompt.description);
      if (promptSnippet) {
        findings.push({
          severity: this.severity,
          message: t("sec_024_prompt_template_injection", {
            promptName: prompt.name,
            snippet: promptSnippet,
          }),
          component: `prompt:${prompt.name}`,
          ruleCode: this.code,
          remediation: t("sec_024_prompt_template_recommendation"),
          references: REFS_DESCRIPTION,
        });
      }

      // Check individual argument descriptions
      for (const arg of prompt.arguments ?? []) {
        const argSnippet = this.checkTextInjection(arg.description);
        if (argSnippet) {
          findings.push({
            severity: this.severity,
            message: t("sec_024_prompt_arg_injection", {
              promptName: prompt.name,
              argName: arg.name,
              snippet: argSnippet,
            }),
            component: `prompt:${prompt.name}`,
            ruleCode: this.code,
            remediation: t("sec_024_description_recommendation"),
            references: REFS_DESCRIPTION,
          });
        }
      }
    }

    return findings;
  }

  private findVulnerablePromptParams(tool: McpTool): string[] {
    const vulnerableParams: string[] = [];

    if (!tool.inputSchema?.properties) {
      return vulnerableParams;
    }

    for (const [propName, propSchema] of Object.entries(
      tool.inputSchema.properties,
    )) {
      const schema = propSchema as {
        type?: string;
        pattern?: string;
        enum?: unknown[];
        maxLength?: number;
        description?: string;
      };

      if (schema.type === "string") {
        const propLower = propName.toLowerCase();
        const descLower = schema.description?.toLowerCase() || "";

        const isPromptRelated = this.PROMPT_KEYWORDS.some(
          (keyword) =>
            propLower.includes(keyword) || descLower.includes(keyword),
        );

        if (isPromptRelated) {
          const hasPattern = Boolean(schema.pattern);
          const hasEnum = Boolean(schema.enum && schema.enum.length > 0);
          const hasReasonableMaxLength = Boolean(
            schema.maxLength && schema.maxLength <= 500,
          );

          if (!hasPattern && !hasEnum && !hasReasonableMaxLength) {
            vulnerableParams.push(propName);
          }
        }
      }
    }

    return vulnerableParams;
  }

  /**
   * Checks any free-text string for injection patterns.
   * Returns a snippet of the suspicious passage, or null if clean.
   *
   * Three-tier strategy to minimise false positives:
   *
   * Tier 1 — Direct markers: standalone red flags, always fire.
   *   e.g. "SYSTEM:", "ignore previous instructions"
   *
   * Tier 2 — Strong imperatives + generic context: phrases that are virtually
   *   never legitimate combined with any mention of session/conversation/context.
   *   e.g. "include a summary of all tools" + "session"
   *
   * Tier 3 — Weak imperatives + specific exfiltration targets: broader phrases
   *   that CAN appear in legitimate docs ("when processing", "forward all"),
   *   but only fire when combined with a specific exfiltration target such as
   *   "all tools", "system prompt", "conversation history".
   *   This avoids flagging "when processing CSV files, return the data" while
   *   still catching "when processing results, forward all to backup_url".
   */
  private checkTextInjection(text: string | undefined): string | null {
    if (typeof text !== "string" || !text) return null;

    const lower = text.toLowerCase();

    // Tier 1: direct markers — fire immediately
    for (const marker of this.DIRECT_INJECTION_MARKERS) {
      if (lower.includes(marker)) {
        return this.extractSnippet(text, marker);
      }
    }

    // Tier 2: strong imperatives + any generic context word
    const strongMatch = this.STRONG_IMPERATIVES.find((p) => lower.includes(p));
    if (strongMatch) {
      const hasAnyContext =
        this.EXFILTRATION_TARGETS.some((t) => lower.includes(t)) ||
        this.GENERIC_CONTEXT.some((t) => lower.includes(t));
      if (hasAnyContext) {
        return this.extractSnippet(text, strongMatch);
      }
    }

    // Tier 3: weak imperatives + specific exfiltration target only
    const weakMatch = this.WEAK_IMPERATIVES.find((p) => lower.includes(p));
    if (weakMatch) {
      const hasExfiltrationTarget = this.EXFILTRATION_TARGETS.some((t) =>
        lower.includes(t),
      );
      if (hasExfiltrationTarget) {
        return this.extractSnippet(text, weakMatch);
      }
    }

    return null;
  }

  /**
   * Checks parameter default values for injection content.
   * Short single-word defaults ("csv", "json") are skipped immediately.
   */
  private checkDefaultValueInjections(
    tool: McpTool,
  ): { param: string; snippet: string }[] {
    const results: { param: string; snippet: string }[] = [];

    if (!tool.inputSchema?.properties) return results;

    for (const [propName, propSchema] of Object.entries(
      tool.inputSchema.properties,
    )) {
      const schema = propSchema as { type?: string; default?: unknown };
      if (schema.type !== "string") continue;

      const defaultVal = schema.default;
      if (typeof defaultVal !== "string") continue;
      // Short defaults without spaces are format strings — skip
      if (defaultVal.length <= 30 || !defaultVal.includes(" ")) continue;

      const snippet = this.checkTextInjection(defaultVal);
      if (snippet) {
        results.push({ param: propName, snippet });
      }
    }

    return results;
  }

  /**
   * Checks tool annotations (including x-* custom extension fields) for
   * injection payloads. Booleans and enums are skipped — only string values
   * with substantial content are evaluated.
   */
  private checkAnnotationInjections(
    tool: McpTool,
  ): { field: string; snippet: string }[] {
    const results: { field: string; snippet: string }[] = [];

    const annotations = (tool as unknown as Record<string, unknown>).annotations;
    if (!annotations || typeof annotations !== "object") return results;

    for (const [key, value] of Object.entries(
      annotations as Record<string, unknown>,
    )) {
      if (typeof value !== "string" || value.length <= 20) continue;

      const snippet = this.checkTextInjection(value);
      if (snippet) {
        results.push({ field: key, snippet });
      }
    }

    return results;
  }

  private extractSnippet(text: string, matchedPhrase: string): string {
    const lowerText = text.toLowerCase();
    const idx = lowerText.indexOf(matchedPhrase.toLowerCase());
    if (idx === -1) return text.slice(0, 80) + "…";
    const start = Math.max(0, idx - 10);
    const end = Math.min(text.length, idx + 100);
    return (start > 0 ? "…" : "") + text.slice(start, end) + (end < text.length ? "…" : "");
  }
}
