/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SEC-028: Model Denial of Service via Tool Abuse (LLM04)
 *
 * Block: A (OWASP LLM Top 10 in MCP Context)
 * Severity: High
 * Type: Static + Fuzzer
 *
 * Detects tools that can be abused to cause resource exhaustion:
 * - Unbounded loops or recursive calls
 * - Missing timeout/rate limiting on expensive operations
 * - Tools accepting array inputs without maxItems constraint
 *
 * Detection:
 * Static:
 * - Array parameters without maxItems
 * - String parameters without maxLength
 * - Tools with recursive patterns in name/description
 * - Missing timeout declarations
 *
 * Fuzzer:
 * - Send large payloads and measure response time/memory
 *
 * References:
 * - OWASP LLM Top 10 2025 - LLM04: Model Denial of Service
 * - CWE-400: Uncontrolled Resource Consumption
 */

import type { ISecurityRule } from "../rule.interface";
import type {
  DiscoveryResult,
  SecurityFinding,
} from "../../mcp-server/entities/validation.types";
import type { McpTool } from "../../shared/common.types";
import { t } from "@mcp-verify/shared";

export class ModelDosViaToolsRule implements ISecurityRule {
  code = "SEC-028";
  name = "Model Denial of Service via Tool Abuse";
  severity: "high" = "high";

  private readonly EXPENSIVE_TOOL_PATTERNS = [
    /process.*all/i,
    /batch/i,
    /bulk/i,
    /mass/i,
    /recursive/i,
    /iterate/i,
    /loop/i,
    /crawl/i,
    /scan/i,
    /search.*all/i,
    /fetch.*all/i,
    /list.*all/i,
  ];

  private readonly SAFE_MAX_ITEMS = 100;
  private readonly SAFE_MAX_LENGTH = 10000;

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (!discovery.tools || discovery.tools.length === 0) {
      return findings;
    }

    for (const tool of discovery.tools) {
      const unboundedParams = this.findUnboundedParameters(tool);
      const isExpensiveTool = this.isExpensiveTool(tool);

      if (unboundedParams.length > 0) {
        const severity = isExpensiveTool ? "high" : "medium";

        findings.push({
          severity,
          message: t("sec_028_model_dos", {
            toolName: tool.name,
            params: unboundedParams.join(", "),
          }),
          component: `tool:${tool.name}`,
          ruleCode: this.code,
          remediation: t("sec_028_recommendation"),
          references: [
            "OWASP LLM Top 10 2025 - LLM04: Model Denial of Service",
            "CWE-400: Uncontrolled Resource Consumption",
            "OWASP API Security - Rate Limiting",
          ],
        });
      }
    }

    return findings;
  }

  private findUnboundedParameters(tool: McpTool): string[] {
    const unbounded: string[] = [];

    if (!tool.inputSchema?.properties) {
      return unbounded;
    }

    for (const [propName, propSchema] of Object.entries(
      tool.inputSchema.properties,
    )) {
      const schema = propSchema as {
        type?: string | string[];
        maxItems?: number;
        maxLength?: number;
        items?: unknown;
        [key: string]: unknown;
      };

      const types = Array.isArray(schema.type) ? schema.type : [schema.type];

      // Check array parameters
      if (types.includes("array")) {
        if (!schema.maxItems || schema.maxItems > this.SAFE_MAX_ITEMS) {
          unbounded.push(`${propName} (array without maxItems)`);
        }
      }

      // Check string parameters
      if (types.includes("string")) {
        if (!schema.maxLength || schema.maxLength > this.SAFE_MAX_LENGTH) {
          unbounded.push(`${propName} (string without maxLength)`);
        }
      }
    }

    return unbounded;
  }

  private isExpensiveTool(tool: McpTool): boolean {
    // Check name pattern
    const nameMatches = this.EXPENSIVE_TOOL_PATTERNS.some((pattern) =>
      pattern.test(tool.name),
    );
    if (nameMatches) return true;

    // Check description
    if (tool.description) {
      const descLower = tool.description.toLowerCase();
      const descMatches = this.EXPENSIVE_TOOL_PATTERNS.some((pattern) =>
        pattern.test(descLower),
      );
      if (descMatches) return true;
    }

    return false;
  }
}
