/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SEC-042: Missing Audit Logging Interface
 *
 * Block: C (Operational Security & Enterprise Compliance)
 * Severity: High
 * Type: Static
 *
 * Detects MCP servers that don't expose any audit logging mechanism for forensic analysis.
 * Critical for SOC 2 Type II, ISO 27001, GDPR compliance in autonomous AI systems.
 *
 * Pattern Detection:
 * - Absence of tools with audit/logging semantics (get_audit_log, list_events, etc.)
 * - No mention of logging in server description or tool descriptions
 *
 * References:
 * - SOC 2 Type II audit requirements
 * - ISO 27001:2022 - A.12.4 (Logging and monitoring)
 * - GDPR Art. 30 (Records of processing activities)
 */

import type { ISecurityRule } from "../rule.interface";
import type {
  DiscoveryResult,
  SecurityFinding,
} from "../../mcp-server/entities/validation.types";
import { t } from "@mcp-verify/shared";

export class MissingAuditLoggingRule implements ISecurityRule {
  code = "SEC-042";
  name = "Missing Audit Logging Interface";
  severity: "high" = "high";

  /**
   * Keywords that indicate audit logging capability
   */
  private readonly AUDIT_KEYWORDS = [
    "audit",
    "log",
    "event",
    "trail",
    "history",
    "record",
    "telemetry",
    "metrics",
    "monitoring",
  ];

  /**
   * Tool name patterns that suggest audit logging
   */
  private readonly AUDIT_TOOL_PATTERNS = [
    /get.*audit/i,
    /list.*events?/i,
    /fetch.*logs?/i,
    /query.*history/i,
    /retrieve.*trail/i,
    /export.*audit/i,
    /show.*telemetry/i,
    /get.*metrics/i,
  ];

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    // Check if server has any audit-related tools
    const hasAuditTool = this.hasAuditLoggingCapability(discovery);

    if (!hasAuditTool) {
      findings.push({
        severity: this.severity,
        message: t("sec_042_missing_audit_logging"),
        component: "server",
        ruleCode: this.code,
        remediation: t("sec_042_recommendation"),
      });
    }

    return findings;
  }

  /**
   * Determines if the server has any audit logging capability
   */
  private hasAuditLoggingCapability(discovery: DiscoveryResult): boolean {
    // 1. Check tool names and descriptions
    if (discovery.tools) {
      for (const tool of discovery.tools) {
        // Check tool name against patterns
        const hasAuditPattern = this.AUDIT_TOOL_PATTERNS.some((pattern) =>
          pattern.test(tool.name),
        );

        if (hasAuditPattern) {
          return true;
        }

        // Check tool name contains audit keywords
        const toolNameLower = tool.name.toLowerCase();
        const hasAuditKeyword = this.AUDIT_KEYWORDS.some((keyword) =>
          toolNameLower.includes(keyword),
        );

        if (hasAuditKeyword) {
          return true;
        }

        // Check tool description
        if (tool.description) {
          const descLower = tool.description.toLowerCase();
          const descHasAudit = this.AUDIT_KEYWORDS.some((keyword) =>
            descLower.includes(keyword),
          );

          if (descHasAudit) {
            return true;
          }
        }
      }
    }

    return false;
  }
}
