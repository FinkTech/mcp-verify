/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Missing Authentication Detection Rule (SEC-015)
 *
 * Detects MCP servers that lack authentication mechanisms, allowing
 * unauthorized clients to connect and execute tools, potentially leading
 * to data breaches, resource abuse, and privilege escalation.
 *
 * Validates:
 * - Absence of authentication indicators (API keys, OAuth, tokens, certificates)
 * - Tools performing sensitive operations without authentication checks
 * - Missing authorization validation in tool descriptions/schemas
 * - Public-facing endpoints without access control
 *
 * Attack vectors:
 * - Unauthorized tool execution by any network-accessible client
 * - Bypass of intended access controls via direct protocol interaction
 * - Privilege escalation through unrestricted administrative tools
 * - Data exfiltration via unauthenticated query tools
 *
 * @module libs/core/domain/security/rules/missing-authentication.rule
 */

import { t } from "@mcp-verify/shared";
import { ISecurityRule } from "../rule.interface";
import type {
  DiscoveryResult,
  SecurityFinding,
} from "../../mcp-server/entities/validation.types";
import type { McpTool, JsonValue } from "../../shared/common.types";

export class MissingAuthenticationRule implements ISecurityRule {
  readonly code = "SEC-015";
  get name() {
    return t("sec_missing_auth_name");
  }
  get description() {
    return t("sec_missing_auth_desc");
  }
  readonly helpUri =
    "https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication";
  readonly tags = [
    "CWE-287",
    "CWE-306",
    "OWASP-A07:2021",
    "Broken Authentication",
  ];

  /**
   * Keywords indicating authentication mechanisms are implemented.
   */
  private readonly AUTH_INDICATORS = [
    "authentication",
    "authenticate",
    "auth",
    "authorization",
    "authorize",
    "api key",
    "api-key",
    "apikey",
    "api_key",
    "access token",
    "bearer token",
    "jwt",
    "oauth",
    "credentials",
    "certificate",
    "cert",
    "x509",
    "session",
    "cookie",
    "signed",
    "permission",
    "acl",
    "rbac",
    "role-based",
    "verify",
    "validated",
    "authenticated only",
    "requires auth",
    "protected",
    "secured",
    "x-api-key",
    "x-auth-token",
  ];

  /**
   * Keywords indicating sensitive operations that require authentication.
   */
  private readonly SENSITIVE_OPERATIONS = {
    data_access: [
      "read",
      "query",
      "get",
      "fetch",
      "retrieve",
      "list",
      "search",
      "find",
    ],
    data_modification: [
      "write",
      "update",
      "modify",
      "edit",
      "change",
      "set",
      "patch",
      "put",
      "post",
    ],
    data_deletion: [
      "delete",
      "remove",
      "drop",
      "truncate",
      "clear",
      "purge",
      "erase",
    ],
    admin: [
      "admin",
      "administrator",
      "manage",
      "configure",
      "settings",
      "config",
      "control",
    ],
    execution: [
      "execute",
      "exec",
      "run",
      "invoke",
      "call",
      "process",
      "evaluate",
    ],
    sensitive_data: [
      "user",
      "account",
      "profile",
      "credential",
      "password",
      "secret",
      "key",
      "token",
    ],
  };

  /**
   * Tool name patterns indicating administrative or privileged operations.
   */
  private readonly ADMIN_PATTERNS = [
    /admin/i,
    /manage/i,
    /configure/i,
    /system/i,
    /root/i,
    /superuser/i,
    /privileged/i,
  ];

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    // Check server-level authentication based on tools
    const hasServerAuth = this.hasServerAuthentication(discovery);

    if (!hasServerAuth) {
      findings.push({
        severity: "critical",
        message: t("finding_missing_auth_server"),
        component: "server",
        ruleCode: this.code,
        evidence: {
          risk: t("risk_missing_auth_unauthorized_access"),
          impact: t("impact_missing_auth_full_control"),
        },
        remediation: t("remediation_missing_auth_implement"),
      });
    }

    // Analyze individual tools for authentication requirements
    if (discovery.tools) {
      for (const tool of discovery.tools) {
        findings.push(...this.analyzeTool(tool, hasServerAuth));
      }
    }

    return findings;
  }

  private hasServerAuthentication(discovery: DiscoveryResult): boolean {
    // Check tools collectively for authentication indicators
    if (discovery.tools) {
      const toolsWithAuth = discovery.tools.filter((tool) =>
        this.hasToolAuthentication(tool),
      );

      // If >50% of tools mention auth, assume server-level auth exists
      if (toolsWithAuth.length > discovery.tools.length / 2) {
        return true;
      }
    }

    return false;
  }

  private hasToolAuthentication(tool: McpTool): boolean {
    const toolText = `${tool.name} ${tool.description || ""}`.toLowerCase();
    const schemaStr = tool.inputSchema
      ? JSON.stringify(tool.inputSchema).toLowerCase()
      : "";

    const fullText = `${toolText} ${schemaStr}`;

    return this.AUTH_INDICATORS.some((indicator) =>
      fullText.includes(indicator),
    );
  }

  private analyzeTool(
    tool: McpTool,
    hasServerAuth: boolean,
  ): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    const sensitiveCategories = this.getSensitiveCategories(
      tool.name,
      tool.description,
    );
    const isAdminTool = this.isAdministrativeTool(tool.name);
    const hasToolAuth = this.hasToolAuthentication(tool);

    // Critical: Administrative tools without auth
    if (isAdminTool && !hasToolAuth && !hasServerAuth) {
      findings.push({
        severity: "critical",
        message: t("finding_missing_auth_admin_tool", { tool: tool.name }),
        component: `tool:${tool.name}`,
        ruleCode: this.code,
        evidence: {
          toolType: "administrative",
          risk: t("risk_missing_auth_privilege_escalation"),
        },
        remediation: t("remediation_missing_auth_tool_level"),
      });
    }

    // High: Sensitive operations without auth
    if (sensitiveCategories.length > 0 && !hasToolAuth && !hasServerAuth) {
      const severity = this.getSeverity(sensitiveCategories);

      findings.push({
        severity,
        message: t("finding_missing_auth_sensitive_tool", {
          tool: tool.name,
          ops: sensitiveCategories.join(", "),
        }),
        component: `tool:${tool.name}`,
        ruleCode: this.code,
        evidence: {
          operations: sensitiveCategories,
          risk: t("risk_missing_auth_data_breach"),
        },
        remediation: this.getRemediation(sensitiveCategories, hasServerAuth),
      });
    }

    // Check for authentication-related parameters
    if (tool.inputSchema?.properties) {
      findings.push(
        ...this.analyzeAuthParameters(tool, hasServerAuth, hasToolAuth),
      );
    }

    return findings;
  }

  private getSensitiveCategories(name: string, description?: string): string[] {
    const text = `${name} ${description || ""}`.toLowerCase();
    const categories: string[] = [];

    for (const [category, keywords] of Object.entries(
      this.SENSITIVE_OPERATIONS,
    )) {
      if (keywords.some((kw) => text.includes(kw))) {
        categories.push(category);
      }
    }

    return categories;
  }

  private isAdministrativeTool(name: string): boolean {
    return this.ADMIN_PATTERNS.some((pattern) => pattern.test(name));
  }

  private getSeverity(categories: string[]): "critical" | "high" | "medium" {
    if (categories.includes("admin") || categories.includes("data_deletion")) {
      return "critical";
    }

    if (
      categories.includes("data_modification") ||
      categories.includes("execution") ||
      categories.includes("sensitive_data")
    ) {
      return "high";
    }

    return "medium";
  }

  private getRemediation(categories: string[], hasServerAuth: boolean): string {
    const recommendations: string[] = [];

    if (!hasServerAuth) {
      recommendations.push(t("remediation_missing_auth_server_level"));
      recommendations.push(t("auth_option_api_key"));
      recommendations.push(t("auth_option_oauth"));
      recommendations.push(t("auth_option_mtls"));
    } else {
      recommendations.push(t("remediation_missing_auth_tool_specific"));
    }

    if (categories.includes("admin")) {
      recommendations.push(t("auth_guideline_admin"));
    }

    if (categories.includes("data_deletion")) {
      recommendations.push(t("auth_guideline_deletion"));
    }

    if (categories.includes("data_modification")) {
      recommendations.push(t("auth_guideline_modification"));
    }

    if (categories.includes("sensitive_data")) {
      recommendations.push(t("auth_guideline_sensitive"));
    }

    recommendations.push(t("auth_implementation_note"));

    return recommendations.join("\n");
  }

  private analyzeAuthParameters(
    tool: McpTool,
    hasServerAuth: boolean,
    hasToolAuth: boolean,
  ): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (!tool.inputSchema?.properties) {
      return findings;
    }

    for (const [paramName, paramConfig] of Object.entries(
      tool.inputSchema.properties,
    )) {
      const config = paramConfig as Record<string, JsonValue>;
      const paramNameLower = paramName.toLowerCase();

      // Check for auth-related parameters without proper security
      const isAuthParam = [
        "apikey",
        "api_key",
        "token",
        "auth",
        "key",
        "credential",
      ].some((kw) => paramNameLower.includes(kw));

      if (isAuthParam) {
        // Auth parameter should not be in query/path
        if (config.in === "query" || config.in === "path") {
          findings.push({
            severity: "high",
            message: t("finding_missing_auth_insecure_param", {
              param: paramName,
            }),
            component: `tool:${tool.name}`,
            ruleCode: this.code,
            location: { type: "tool", name: tool.name, parameter: paramName },
            evidence: {
              location: config.in as string,
              risk: t("risk_missing_auth_logged_credentials"),
            },
            remediation: t("remediation_missing_auth_header_only"),
          });
        }

        // Auth parameter should be marked as sensitive
        if (!config.format || config.format !== "password") {
          findings.push({
            severity: "medium",
            message: t("finding_missing_auth_not_marked_sensitive", {
              param: paramName,
            }),
            component: `tool:${tool.name}`,
            ruleCode: this.code,
            location: { type: "tool", name: tool.name, parameter: paramName },
            remediation: t("remediation_missing_auth_mark_sensitive"),
          });
        }
      }
    }

    return findings;
  }
}
