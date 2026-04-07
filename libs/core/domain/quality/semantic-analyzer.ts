/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import { t } from "@mcp-verify/shared";
import type {
  DiscoveryResult,
  QualityReport,
  QualityIssue,
  McpTool,
} from "../mcp-server/entities/validation.types";
import { LLMSemanticAnalyzer } from "./llm-semantic-analyzer";
import type { LLMSemanticResult } from "./llm-semantic-analyzer";

export class SemanticAnalyzer {
  private llmAnalyzer?: LLMSemanticAnalyzer;
  private llmProvider?: string;

  constructor(llmAnalyzer?: LLMSemanticAnalyzer, llmProvider?: string) {
    this.llmAnalyzer = llmAnalyzer;
    this.llmProvider = llmProvider;
  }

  async analyze(discovery: DiscoveryResult): Promise<QualityReport> {
    const issues: QualityIssue[] = [];
    let totalItems = 0;
    let perfectItems = 0;

    // Analyze Tools
    if (discovery.tools) {
      for (const tool of discovery.tools) {
        totalItems++;
        const toolIssues = this.checkTool(tool);
        issues.push(...toolIssues);
        if (toolIssues.length === 0) perfectItems++;
      }
    }

    // Analyze Resources
    if (discovery.resources) {
      for (const resource of discovery.resources) {
        totalItems++;
        if (!resource.mimeType) {
          issues.push({
            severity: "warning",
            message: t("resource_missing_mimetype"),
            component: `resource:${resource.name}`,
            suggestion: t("quality_mimetype_suggestion"),
          });
        } else {
          perfectItems++;
        }
      }
    }

    // Calculate Score (Simple percentage of "perfect" items, penalized by issues)
    // If there are no items, score is 100 (neutral)
    let score =
      totalItems === 0 ? 100 : Math.round((perfectItems / totalItems) * 100);

    // Penalize score for warnings
    const warningPenalty = issues.length * 2;
    score = Math.max(0, score - warningPenalty);

    // Run LLM analysis if available
    let llmResult: LLMSemanticResult | undefined;
    if (this.llmAnalyzer) {
      llmResult = await this.llmAnalyzer.analyze(discovery, {
        llmProvider: this.llmProvider,
      });

      // Merge LLM findings into issues
      if (llmResult.enabled && llmResult.findings) {
        for (const finding of llmResult.findings) {
          // Map LLM severity to quality issue severity
          const severity = this.mapLLMSeverity(finding.severity);

          issues.push({
            severity,
            message: `[LLM] ${finding.issue}`,
            component: `${finding.type}:${finding.name}`,
            suggestion: finding.recommendation || finding.reasoning,
          });

          // Apply additional penalty for critical/high LLM findings
          if (finding.severity === "critical") {
            score = Math.max(0, score - 15);
          } else if (finding.severity === "high") {
            score = Math.max(0, score - 10);
          } else if (finding.severity === "medium") {
            score = Math.max(0, score - 5);
          }
        }
      }
    }

    return {
      score,
      issues,
      llmAnalysis: llmResult,
    };
  }

  /**
   * Map LLM severity to quality issue severity
   */
  private mapLLMSeverity(
    llmSeverity: "critical" | "high" | "medium" | "low" | "info",
  ): "warning" | "info" {
    if (llmSeverity === "critical" || llmSeverity === "high") {
      return "warning"; // Critical semantic issues are warnings (not blocking)
    } else if (llmSeverity === "medium") {
      return "warning";
    } else {
      return "info";
    }
  }

  private checkTool(tool: McpTool): QualityIssue[] {
    const issues: QualityIssue[] = [];

    // 1. Description Existence
    if (!tool.description || tool.description.trim().length === 0) {
      issues.push({
        severity: "warning",
        message: t("missing_description"),
        component: `tool:${tool.name}`,
        suggestion: t("add_a_clear_description_explaining_what_the_tool_d"),
      });
      return issues; // Can't check length if missing
    }

    // 2. Description Length (Too short)
    if (tool.description.length < 20) {
      issues.push({
        severity: "info",
        message: t("description_is_very_short"),
        component: `tool:${tool.name}`,
        suggestion: t("expand_description_to_at_least_20_characters_to_pr"),
      });
    }

    // 3. Parameter Descriptions
    if (tool.inputSchema?.properties) {
      for (const [param, config] of Object.entries(
        tool.inputSchema.properties,
      ) as [string, any][]) {
        if (!config.description) {
          issues.push({
            severity: "info",
            message: t("quality_param_missing_desc", { param }),
            component: `tool:${tool.name}`,
            suggestion: t("quality_param_desc_suggestion", { param }),
          });
        }
      }
    }

    return issues;
  }
}
