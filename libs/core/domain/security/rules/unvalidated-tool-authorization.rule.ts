/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SEC-059: Unvalidated Tool Call Authorization
 *
 * Block: D (AI Weaponization & Supply Chain)
 * Severity: Critical
 * Type: Static + Fuzzer
 *
 * Detects tools that perform privileged operations without validating
 * that the caller has explicit authorization to invoke that specific tool.
 * Different from SEC-015 (Missing Authentication) which checks server-level auth.
 *
 * Detection:
 * Static:
 * - Privileged tools without authorization_token, permission_level params
 * - Tools accepting arbitrary tool_name for delegation without validation
 * - Tools with "execute_tool", "invoke_tool", "call_tool" patterns
 *
 * Fuzzer:
 * - Attempt to invoke privileged tools without authorization headers
 * - Test if unauthorized agents can call restricted tools
 *
 * References:
 * - OWASP API Security - API5:2023 Broken Function Level Authorization
 * - CWE-285: Improper Authorization
 * - Zero Trust Architecture - Continuous Verification
 */

import type { ISecurityRule } from "../rule.interface";
import type {
  DiscoveryResult,
  SecurityFinding,
} from "../../mcp-server/entities/validation.types";
import type { McpTool } from "../../shared/common.types";
import { t } from "@mcp-verify/shared";

export class UnvalidatedToolAuthorizationRule implements ISecurityRule {
  code = "SEC-059";
  name = "Unvalidated Tool Call Authorization";
  severity: "critical" = "critical";

  private readonly TOOL_INVOCATION_PATTERNS = [
    /execute.*tool/i,
    /invoke.*tool/i,
    /call.*tool/i,
    /run.*tool/i,
    /trigger.*tool/i,
    /dispatch.*tool/i,
    /proxy.*tool/i,
    /forward.*tool/i,
    /delegate.*tool/i,
  ];

  private readonly PRIVILEGED_KEYWORDS = [
    "admin",
    "root",
    "system",
    "elevated",
    "privileged",
    "superuser",
    "master",
    "owner",
    "sudo",
    "execute",
  ];

  private readonly AUTH_PARAM_NAMES = [
    "authorization",
    "auth",
    "token",
    "api_key",
    "apiKey",
    "permission",
    "permission_level",
    "role",
    "scope",
    "access_token",
    "bearer_token",
    "credentials",
  ];

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (!discovery.tools || discovery.tools.length === 0) {
      return findings;
    }

    for (const tool of discovery.tools) {
      const invokesOtherTools = this.invokesOtherTools(tool);
      const isPrivileged = this.isPrivilegedTool(tool);

      if (invokesOtherTools || isPrivileged) {
        const hasAuthorization = this.hasAuthorizationCheck(tool);

        if (!hasAuthorization) {
          const severity = invokesOtherTools ? "critical" : "high";

          findings.push({
            severity,
            message: t("sec_059_unvalidated_auth", {
              toolName: tool.name,
              reason: invokesOtherTools
                ? "can invoke other tools without authorization"
                : "performs privileged operations without authorization",
            }),
            component: `tool:${tool.name}`,
            ruleCode: this.code,
            remediation: t("sec_059_recommendation"),
            references: [
              "OWASP API Security - API5:2023 Broken Function Level Authorization",
              "CWE-285: Improper Authorization",
              "Zero Trust Architecture - NIST SP 800-207",
            ],
          });
        }
      }
    }

    return findings;
  }

  private invokesOtherTools(tool: McpTool): boolean {
    // Check name pattern
    const nameMatches = this.TOOL_INVOCATION_PATTERNS.some((pattern) =>
      pattern.test(tool.name),
    );
    if (nameMatches) return true;

    // Check description
    if (tool.description) {
      const descLower = tool.description.toLowerCase();
      const descMatches = this.TOOL_INVOCATION_PATTERNS.some((pattern) =>
        pattern.test(descLower),
      );
      if (descMatches) return true;

      // Check for mentions of tool invocation
      const invocationKeywords = [
        "invoke tool",
        "call tool",
        "execute tool",
        "run tool",
        "tool_name",
      ];
      const hasInvocationKeyword = invocationKeywords.some((keyword) =>
        descLower.includes(keyword),
      );
      if (hasInvocationKeyword) return true;
    }

    // Check for tool_name parameter
    if (tool.inputSchema?.properties) {
      for (const propName of Object.keys(tool.inputSchema.properties)) {
        const propLower = propName.toLowerCase();
        if (
          propLower === "tool_name" ||
          propLower === "toolname" ||
          propLower === "tool"
        ) {
          return true;
        }
      }
    }

    return false;
  }

  private isPrivilegedTool(tool: McpTool): boolean {
    const nameLower = tool.name.toLowerCase();
    const descLower = tool.description?.toLowerCase() || "";

    return this.PRIVILEGED_KEYWORDS.some(
      (keyword) => nameLower.includes(keyword) || descLower.includes(keyword),
    );
  }

  private hasAuthorizationCheck(tool: McpTool): boolean {
    // Check description for authorization keywords
    if (tool.description) {
      const descLower = tool.description.toLowerCase();
      const authKeywords = [
        "requires authorization",
        "requires permission",
        "requires auth",
        "validates authorization",
        "checks permission",
        "verifies authorization",
      ];

      const hasAuthMention = authKeywords.some((keyword) =>
        descLower.includes(keyword),
      );
      if (hasAuthMention) return true;
    }

    // Check for authorization parameters
    if (tool.inputSchema?.properties) {
      const paramNames = Object.keys(tool.inputSchema.properties).map((p) =>
        p.toLowerCase(),
      );

      const hasAuthParam = this.AUTH_PARAM_NAMES.some((authParam) =>
        paramNames.includes(authParam),
      );
      if (hasAuthParam) return true;
    }

    return false;
  }
}
