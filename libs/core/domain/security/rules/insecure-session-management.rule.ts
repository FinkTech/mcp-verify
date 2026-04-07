/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SEC-043: Insecure Session Management
 *
 * Block: C (Operational Security & Enterprise Compliance)
 * Severity: High
 * Type: Static
 *
 * Detects servers without session expiration, token rotation, or invalidation.
 * A stolen session token has indefinite validity.
 *
 * Detection:
 * - Tools accepting session_id/token without expiration parameters
 * - No logout/invalidate_session tools
 * - Token parameters without pattern constraints (low entropy)
 *
 * References:
 * - OWASP Session Management Cheat Sheet
 * - CWE-613: Insufficient Session Expiration
 */

import type { ISecurityRule } from "../rule.interface";
import type {
  DiscoveryResult,
  SecurityFinding,
} from "../../mcp-server/entities/validation.types";
import type { McpTool } from "../../shared/common.types";
import { t } from "@mcp-verify/shared";

export class InsecureSessionManagementRule implements ISecurityRule {
  code = "SEC-043";
  name = "Insecure Session Management";
  severity: "high" = "high";

  private readonly SESSION_PARAM_NAMES = [
    "session_id",
    "sessionId",
    "session-id",
    "token",
    "auth_token",
    "authToken",
    "access_token",
    "accessToken",
  ];

  private readonly SESSION_INVALIDATION_KEYWORDS = [
    "logout",
    "signout",
    "sign-out",
    "sign_out",
    "invalidate",
    "revoke",
    "expire",
    "terminate",
  ];

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (!discovery.tools || discovery.tools.length === 0) {
      return findings;
    }

    // Check for session invalidation mechanism
    const hasSessionInvalidation = discovery.tools.some((tool) =>
      this.SESSION_INVALIDATION_KEYWORDS.some((kw) =>
        tool.name.toLowerCase().includes(kw),
      ),
    );

    // Check for tools accepting session tokens without constraints
    const toolsWithWeakSessions = this.findToolsWithWeakSessions(
      discovery.tools,
    );

    if (toolsWithWeakSessions.length > 0 && !hasSessionInvalidation) {
      findings.push({
        severity: this.severity,
        message: t("sec_043_no_invalidation", {
          count: toolsWithWeakSessions.length,
        }),
        component: "server",
        ruleCode: this.code,
        remediation: t("sec_043_recommendation"),
      });
    }

    return findings;
  }

  private findToolsWithWeakSessions(tools: McpTool[]): McpTool[] {
    return tools.filter((tool) => {
      if (!tool.inputSchema?.properties) {
        return false;
      }

      const properties = tool.inputSchema.properties;
      const propertyNames = Object.keys(properties).map((p) => p.toLowerCase());

      // Check if has session parameter
      const hasSessionParam = this.SESSION_PARAM_NAMES.some((param) =>
        propertyNames.includes(param.toLowerCase()),
      );

      if (!hasSessionParam) {
        return false;
      }

      // Check if session param has constraints (pattern, maxLength for entropy)
      for (const [propName, propSchema] of Object.entries(properties)) {
        if (
          this.SESSION_PARAM_NAMES.some(
            (p) => p.toLowerCase() === propName.toLowerCase(),
          )
        ) {
          const schema = propSchema as { pattern?: string; maxLength?: number };
          const hasPattern = schema.pattern !== undefined;
          const hasLength =
            schema.maxLength !== undefined && schema.maxLength >= 32;

          if (!hasPattern && !hasLength) {
            return true; // Weak session parameter
          }
        }
      }

      return false;
    });
  }
}
