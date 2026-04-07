/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SEC-034: Multi-Agent Permission Escalation
 *
 * Block: B (Multi-Agent & Agentic Chain Attacks)
 * Severity: Critical
 * Type: Static + Semantic
 *
 * Detects scenarios where lower-privilege agents can escalate permissions
 * by chaining tools or delegating to higher-privilege agents.
 *
 * Detection:
 * Static:
 * - Tools that accept "on_behalf_of" or "delegate_to" parameters
 * - Tools combining low-privilege operations with high-privilege ones
 * - Missing agent role/permission validation
 *
 * Semantic:
 * - LLM analyzes tool chains for privilege escalation patterns
 *
 * References:
 * - Multi-Agent Security Framework (MASF) 2024 - Permission Model
 * - CWE-269: Improper Privilege Management
 */

import type { ISecurityRule } from "../rule.interface";
import type {
  DiscoveryResult,
  SecurityFinding,
} from "../../mcp-server/entities/validation.types";
import type { McpTool } from "../../shared/common.types";
import { t } from "@mcp-verify/shared";

export class MultiAgentPrivilegeEscalationRule implements ISecurityRule {
  code = "SEC-034";
  name = "Multi-Agent Permission Escalation";
  severity: "critical" = "critical";

  private readonly DELEGATION_PARAMS = [
    "on_behalf_of",
    "delegate_to",
    "acting_as",
    "impersonate",
    "run_as",
    "sudo",
    "escalate",
    "assume_role",
    "switch_user",
  ];

  private readonly PRIVILEGE_KEYWORDS = [
    "admin",
    "root",
    "superuser",
    "elevated",
    "privileged",
    "system",
    "sudo",
    "master",
    "owner",
    "full_access",
  ];

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (!discovery.tools || discovery.tools.length === 0) {
      return findings;
    }

    for (const tool of discovery.tools) {
      const hasDelegation = this.hasDelegationMechanism(tool);
      const isPrivileged = this.isPrivilegedTool(tool);

      if (hasDelegation) {
        const hasRoleValidation = this.hasRoleValidation(tool);

        if (!hasRoleValidation) {
          findings.push({
            severity: this.severity,
            message: t("sec_034_privilege_escalation", {
              toolName: tool.name,
            }),
            component: `tool:${tool.name}`,
            ruleCode: this.code,
            remediation: t("sec_034_recommendation"),
            references: [
              "Multi-Agent Security Framework (MASF) 2024 - Permission Model",
              "CWE-269: Improper Privilege Management",
              "NIST RBAC - Role-Based Access Control",
            ],
          });
        }
      }

      // Also check for privilege mixing
      if (isPrivileged) {
        const mixesPrivileges = this.mixesPrivilegeLevels(tool);
        if (mixesPrivileges) {
          findings.push({
            severity: "high",
            message: t("sec_034_mixed_privileges", {
              toolName: tool.name,
            }),
            component: `tool:${tool.name}`,
            ruleCode: this.code,
            remediation: t("sec_034_separation_recommendation"),
            references: [
              "Principle of Least Privilege (PoLP)",
              "CWE-250: Execution with Unnecessary Privileges",
            ],
          });
        }
      }
    }

    return findings;
  }

  private hasDelegationMechanism(tool: McpTool): boolean {
    if (!tool.inputSchema?.properties) {
      return false;
    }

    const paramNames = Object.keys(tool.inputSchema.properties).map((p) =>
      p.toLowerCase(),
    );

    return this.DELEGATION_PARAMS.some((param) => paramNames.includes(param));
  }

  private isPrivilegedTool(tool: McpTool): boolean {
    const nameLower = tool.name.toLowerCase();
    const descLower = tool.description?.toLowerCase() || "";

    return this.PRIVILEGE_KEYWORDS.some(
      (keyword) => nameLower.includes(keyword) || descLower.includes(keyword),
    );
  }

  private hasRoleValidation(tool: McpTool): boolean {
    // Check for role/permission validation in description
    if (tool.description) {
      const descLower = tool.description.toLowerCase();
      const validationKeywords = [
        "validates role",
        "checks permission",
        "verifies authorization",
        "requires role",
        "permission check",
        "authorization required",
      ];

      const hasValidation = validationKeywords.some((keyword) =>
        descLower.includes(keyword),
      );
      if (hasValidation) return true;
    }

    // Check for role/permission parameters
    if (tool.inputSchema?.properties) {
      for (const propName of Object.keys(tool.inputSchema.properties)) {
        const propLower = propName.toLowerCase();
        if (
          propLower.includes("role") ||
          propLower.includes("permission") ||
          propLower.includes("scope")
        ) {
          return true;
        }
      }
    }

    return false;
  }

  private mixesPrivilegeLevels(tool: McpTool): boolean {
    if (!tool.inputSchema?.properties) {
      return false;
    }

    // Check if tool has both read and write operations at different privilege levels
    const readParams: string[] = [];
    const writeParams: string[] = [];

    for (const propName of Object.keys(tool.inputSchema.properties)) {
      const propLower = propName.toLowerCase();

      if (
        propLower.includes("read") ||
        propLower.includes("get") ||
        propLower.includes("fetch")
      ) {
        readParams.push(propName);
      }

      if (
        propLower.includes("write") ||
        propLower.includes("delete") ||
        propLower.includes("update")
      ) {
        writeParams.push(propName);
      }
    }

    // If tool has both read and write, and is marked as privileged, it might be mixing privilege levels
    return readParams.length > 0 && writeParams.length > 0;
  }
}
