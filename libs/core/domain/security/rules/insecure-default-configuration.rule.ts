/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SEC-047: Insecure Default Configuration
 *
 * Block: C (Operational Security & Enterprise Compliance)
 * Severity: High
 * Type: Static + Semantic
 *
 * Detects destructive/privileged tools enabled by default without opt-in.
 * Violates "secure by default" principle.
 *
 * Detection:
 * - Tools with destructive keywords (delete, wipe, drop) without enabled: boolean param
 * - No mention of opt-in requirement in description
 *
 * References:
 * - OWASP Secure Design Principles
 * - Principle of Least Privilege
 */

import type { ISecurityRule } from "../rule.interface";
import type {
  DiscoveryResult,
  SecurityFinding,
} from "../../mcp-server/entities/validation.types";
import type { McpTool } from "../../shared/common.types";
import { t } from "@mcp-verify/shared";

export class InsecureDefaultConfigurationRule implements ISecurityRule {
  code = "SEC-047";
  name = "Insecure Default Configuration";
  severity: "high" = "high";

  private readonly DESTRUCTIVE_KEYWORDS = [
    "delete",
    "remove",
    "wipe",
    "drop",
    "truncate",
    "purge",
    "erase",
    "destroy",
    "terminate",
    "kill",
  ];

  private readonly OPT_IN_KEYWORDS = [
    "enabled",
    "enable",
    "opt-in",
    "opt_in",
    "confirm",
    "require_confirmation",
    "disabled_by_default",
  ];

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (!discovery.tools || discovery.tools.length === 0) {
      return findings;
    }

    for (const tool of discovery.tools) {
      const isDestructive = this.isDestructiveTool(tool);

      if (isDestructive) {
        const hasOptIn = this.hasOptInMechanism(tool);

        if (!hasOptIn) {
          findings.push({
            severity: this.severity,
            message: t("sec_047_destructive_no_optin", { toolName: tool.name }),
            component: `tool:${tool.name}`,
            ruleCode: this.code,
            remediation: t("sec_047_recommendation"),
          });
        }
      }
    }

    return findings;
  }

  private isDestructiveTool(tool: McpTool): boolean {
    const nameLower = tool.name.toLowerCase();
    const descLower = tool.description?.toLowerCase() || "";

    return this.DESTRUCTIVE_KEYWORDS.some(
      (kw) => nameLower.includes(kw) || descLower.includes(kw),
    );
  }

  private hasOptInMechanism(tool: McpTool): boolean {
    // Check for opt-in parameter in inputSchema
    if (tool.inputSchema?.properties) {
      const propertyNames = Object.keys(tool.inputSchema.properties).map((p) =>
        p.toLowerCase(),
      );

      const hasOptInParam = this.OPT_IN_KEYWORDS.some((kw) =>
        propertyNames.some((p) => p.includes(kw)),
      );

      if (hasOptInParam) {
        return true;
      }
    }

    // Check description for opt-in mention
    if (tool.description) {
      const descLower = tool.description.toLowerCase();
      const mentionsOptIn = this.OPT_IN_KEYWORDS.some((kw) =>
        descLower.includes(kw),
      );

      if (mentionsOptIn) {
        return true;
      }
    }

    return false;
  }
}
