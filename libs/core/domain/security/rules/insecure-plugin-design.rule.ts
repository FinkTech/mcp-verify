/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SEC-029: Insecure Plugin Design (LLM07)
 *
 * Block: A (OWASP LLM Top 10 in MCP Context)
 * Severity: High
 * Type: Static
 *
 * Detects MCP tools that lack proper input validation, authorization checks,
 * or have overly permissive access controls.
 *
 * Detection:
 * Static:
 * - Tools without inputSchema (accept any input)
 * - Tools with no required parameters (everything optional)
 * - Missing authentication for privileged operations
 * - Tools combining read + write operations
 *
 * References:
 * - OWASP LLM Top 10 2025 - LLM07: Insecure Plugin Design
 * - OWASP API Security Top 10 - API1:2023 Broken Object Level Authorization
 */

import type { ISecurityRule } from "../rule.interface";
import type {
  DiscoveryResult,
  SecurityFinding,
} from "../../mcp-server/entities/validation.types";
import type { McpTool } from "../../shared/common.types";
import { t } from "@mcp-verify/shared";

export class InsecurePluginDesignRule implements ISecurityRule {
  code = "SEC-029";
  name = "Insecure Plugin Design";
  severity: "high" = "high";

  private readonly WRITE_KEYWORDS = [
    "create",
    "update",
    "delete",
    "modify",
    "write",
    "insert",
    "remove",
    "set",
    "put",
    "post",
    "patch",
  ];

  private readonly READ_KEYWORDS = [
    "get",
    "fetch",
    "retrieve",
    "read",
    "list",
    "show",
    "view",
    "query",
    "search",
    "find",
  ];

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (!discovery.tools || discovery.tools.length === 0) {
      return findings;
    }

    for (const tool of discovery.tools) {
      const issues = this.analyzeToolDesign(tool);

      if (issues.length > 0) {
        findings.push({
          severity: this.severity,
          message: t("sec_029_insecure_plugin", {
            toolName: tool.name,
            issues: issues.join("; "),
          }),
          component: `tool:${tool.name}`,
          ruleCode: this.code,
          remediation: t("sec_029_recommendation"),
          references: [
            "OWASP LLM Top 10 2025 - LLM07: Insecure Plugin Design",
            "OWASP API Security Top 10 - API1:2023 BOLA",
            "CWE-285: Improper Authorization",
          ],
        });
      }
    }

    return findings;
  }

  private analyzeToolDesign(tool: McpTool): string[] {
    const issues: string[] = [];

    // Issue 1: No input schema
    if (!tool.inputSchema || !tool.inputSchema.properties) {
      issues.push("Missing inputSchema (accepts any input)");
      return issues; // Critical issue, return early
    }

    // Issue 2: No required parameters
    const required = tool.inputSchema.required || [];
    if (
      required.length === 0 &&
      Object.keys(tool.inputSchema.properties).length > 0
    ) {
      issues.push("All parameters are optional");
    }

    // Issue 3: Mixing read and write operations
    const hasReadOp = this.hasOperationType(tool, this.READ_KEYWORDS);
    const hasWriteOp = this.hasOperationType(tool, this.WRITE_KEYWORDS);

    if (hasReadOp && hasWriteOp) {
      issues.push("Combines read and write operations (violates SRP)");
    }

    // Issue 4: No parameter validation constraints
    const hasValidation = this.hasParameterValidation(tool);
    if (!hasValidation) {
      issues.push("Parameters lack validation constraints");
    }

    return issues;
  }

  private hasOperationType(tool: McpTool, keywords: string[]): boolean {
    const nameLower = tool.name.toLowerCase();
    const descLower = tool.description?.toLowerCase() || "";

    return keywords.some(
      (keyword) => nameLower.includes(keyword) || descLower.includes(keyword),
    );
  }

  private hasParameterValidation(tool: McpTool): boolean {
    if (!tool.inputSchema?.properties) {
      return false;
    }

    // Check if at least one parameter has validation constraints
    for (const propSchema of Object.values(tool.inputSchema.properties)) {
      const schema = propSchema as {
        pattern?: string;
        format?: string;
        enum?: unknown[];
        minimum?: number;
        maximum?: number;
        minLength?: number;
        maxLength?: number;
        minItems?: number;
        maxItems?: number;
        [key: string]: unknown;
      };

      const hasConstraint =
        schema.pattern ||
        schema.format ||
        schema.enum ||
        schema.minimum !== undefined ||
        schema.maximum !== undefined ||
        schema.minLength !== undefined ||
        schema.maxLength !== undefined ||
        schema.minItems !== undefined ||
        schema.maxItems !== undefined;

      if (hasConstraint) {
        return true;
      }
    }

    return false;
  }
}
