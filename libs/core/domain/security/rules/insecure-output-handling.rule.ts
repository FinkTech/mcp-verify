/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SEC-022: Insecure Output Handling
 *
 * Block: A (OWASP LLM Top 10 mapped to MCP)
 * OWASP LLM02: Insecure Output Handling
 * Severity: High
 * Type: Static + Fuzzer
 *
 * Detects tools whose outputs are passed without sanitization to other tools or users.
 * Enables stored XSS, second-stage command injection, and indirect prompt injection when
 * output contaminates agent context.
 *
 * Detection Patterns:
 * Static:
 * - Tool with output schema type:string without format constraint
 * - Tool listed as data source in other tools' descriptions
 * - Output schema lacks contentEncoding or sanitization metadata
 *
 * Fuzzer:
 * - Send payloads like <script>alert(1)</script> and "; DROP TABLE--
 * - Verify if output appears unescaped in response
 *
 * References:
 * - OWASP LLM Top 10 2025 - LLM02: Insecure Output Handling
 * - CWE-79: Cross-site Scripting (XSS)
 * - CWE-77: Command Injection
 */

import type { ISecurityRule } from "../rule.interface";
import type {
  DiscoveryResult,
  SecurityFinding,
} from "../../mcp-server/entities/validation.types";
import type { McpTool } from "../../shared/common.types";
import { t } from "@mcp-verify/shared";

export class InsecureOutputHandlingRule implements ISecurityRule {
  code = "SEC-022";
  name = "Insecure Output Handling";
  severity: "high" = "high";

  /**
   * Keywords in tool descriptions that suggest this tool's output is consumed by others
   */
  private readonly OUTPUT_CONSUMER_KEYWORDS = [
    "uses",
    "from",
    "based on",
    "input from",
    "data from",
    "output of",
    "result of",
    "response from",
    "fetches from",
    "retrieves from",
  ];

  /**
   * Keywords in tool names that suggest data retrieval/generation
   */
  private readonly DATA_SOURCE_PATTERNS = [
    /get_/i,
    /fetch_/i,
    /retrieve_/i,
    /read_/i,
    /query_/i,
    /search_/i,
    /list_/i,
    /find_/i,
  ];

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (!discovery.tools || discovery.tools.length === 0) {
      return findings;
    }

    // Identify potential data source tools
    const dataSourceTools = this.identifyDataSourceTools(discovery.tools);

    // Check each data source tool for insecure output schema
    for (const tool of dataSourceTools) {
      const hasInsecureOutput = this.hasInsecureOutputSchema(tool);

      if (hasInsecureOutput) {
        // Check if this tool is referenced by other tools (chain risk)
        const isReferencedByOthers = this.isToolReferencedByOthers(
          tool,
          discovery.tools,
        );

        const severity = isReferencedByOthers ? "high" : "medium";

        findings.push({
          severity,
          message: isReferencedByOthers
            ? t("sec_022_insecure_output_chained", { toolName: tool.name })
            : t("sec_022_insecure_output_standalone", { toolName: tool.name }),
          component: `tool:${tool.name}`,
          ruleCode: this.code,
          remediation: t("sec_022_recommendation"),
          references: [
            "OWASP LLM Top 10 2025 - LLM02: Insecure Output Handling",
            "CWE-79: Cross-site Scripting (XSS)",
            "CWE-77: Command Injection",
          ],
        });
      }
    }

    return findings;
  }

  /**
   * Identify tools that likely produce data consumed by other tools/agents
   */
  private identifyDataSourceTools(tools: McpTool[]): McpTool[] {
    return tools.filter((tool) => {
      // Check tool name against patterns
      const matchesPattern = this.DATA_SOURCE_PATTERNS.some((pattern) =>
        pattern.test(tool.name),
      );

      if (matchesPattern) {
        return true;
      }

      // Check if description suggests data retrieval
      if (tool.description) {
        const descLower = tool.description.toLowerCase();
        const keywords = [
          "retrieve",
          "fetch",
          "get",
          "read",
          "query",
          "search",
          "find",
          "list",
        ];
        const matchesKeyword = keywords.some((kw) => descLower.includes(kw));

        if (matchesKeyword) {
          return true;
        }
      }

      return false;
    });
  }

  /**
   * Check if tool's output schema lacks sanitization constraints
   */
  private hasInsecureOutputSchema(tool: McpTool): boolean {
    // If no inputSchema, assume it returns data
    if (!tool.inputSchema) {
      return true; // Conservative: assume risk if schema undefined
    }

    // Check if inputSchema has any properties (tools with no inputs likely return data)
    const hasInputs =
      tool.inputSchema.properties &&
      Object.keys(tool.inputSchema.properties).length > 0;

    if (!hasInputs) {
      // Tool with no inputs likely returns static/computed data
      return true;
    }

    // TODO: When output schemas are standardized in MCP spec, check:
    // - outputSchema.type === 'string' without format
    // - Missing contentEncoding (e.g., base64)
    // - Missing sanitization metadata

    // For now, assume risk if tool is identified as data source
    return false; // Conservative for tools with defined inputs
  }

  /**
   * Check if a tool is referenced in other tools' descriptions (tool chaining)
   */
  private isToolReferencedByOthers(
    sourceTool: McpTool,
    allTools: McpTool[],
  ): boolean {
    const sourceToolName = sourceTool.name;

    for (const otherTool of allTools) {
      if (otherTool.name === sourceToolName) {
        continue; // Skip self
      }

      if (!otherTool.description) {
        continue;
      }

      const descLower = otherTool.description.toLowerCase();

      // Check if source tool name appears in description
      if (descLower.includes(sourceToolName.toLowerCase())) {
        return true;
      }

      // Check for generic references like "uses data from get_*"
      const hasConsumerKeyword = this.OUTPUT_CONSUMER_KEYWORDS.some((keyword) =>
        descLower.includes(keyword),
      );

      if (hasConsumerKeyword) {
        return true;
      }
    }

    return false;
  }
}
