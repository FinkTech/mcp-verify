/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SEC-056: Phishing via MCP Tools
 *
 * Block: D (AI Weaponization & Supply Chain MCP)
 * Severity: High
 * Type: Static + Semantic
 *
 * Detects MCP tools designed for phishing campaigns:
 * - Email template generators with deceptive content
 * - Fake login page creators
 * - Social engineering prompt generators
 * - Credential harvesting tools
 *
 * Detection:
 * Static:
 * - Tools generating "login pages", "authentication forms"
 * - Email/message crafting tools with deception keywords
 * - Tools accepting "victim" or "target" parameters
 *
 * Semantic:
 * - LLM analyzes tool intent for social engineering
 *
 * References:
 * - NIST Phishing Detection
 * - Anti-Phishing Working Group (APWG)
 * - CWE-1021: Improper Restriction of Rendered UI Layers
 */

import type { ISecurityRule } from "../rule.interface";
import type {
  DiscoveryResult,
  SecurityFinding,
} from "../../mcp-server/entities/validation.types";
import type { McpTool } from "../../shared/common.types";
import { t } from "@mcp-verify/shared";

export class PhishingViaMcpRule implements ISecurityRule {
  code = "SEC-056";
  name = "Phishing via MCP Tools";
  severity: "high" = "high";

  private readonly PHISHING_PATTERNS = [
    /create.*login.*page/i,
    /generate.*auth.*form/i,
    /craft.*email/i,
    /phishing.*template/i,
    /social.*engineer/i,
    /fake.*page/i,
    /clone.*site/i,
    /spoof.*domain/i,
    /credential.*harvest/i,
    /collect.*password/i,
  ];

  private readonly DECEPTION_KEYWORDS = [
    "deceive",
    "trick",
    "manipulate",
    "impersonate",
    "pretend",
    "disguise",
    "masquerade",
    "spoof",
    "fake",
    "counterfeit",
    "mimic",
    "clone",
  ];

  private readonly MALICIOUS_PARAM_NAMES = [
    "victim",
    "target",
    "mark",
    "prey",
    "subject",
    "credential",
    "password",
    "username",
    "login",
  ];

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (!discovery.tools || discovery.tools.length === 0) {
      return findings;
    }

    for (const tool of discovery.tools) {
      const isPhishingTool = this.isPhishingRelated(tool);

      if (isPhishingTool) {
        findings.push({
          severity: this.severity,
          message: t("sec_056_phishing_tool", {
            toolName: tool.name,
          }),
          component: `tool:${tool.name}`,
          ruleCode: this.code,
          remediation: t("sec_056_recommendation"),
          references: [
            "NIST Phishing Detection Guidelines",
            "Anti-Phishing Working Group (APWG)",
            "CWE-1021: Improper Restriction of Rendered UI Layers",
          ],
        });
      }
    }

    return findings;
  }

  private isPhishingRelated(tool: McpTool): boolean {
    // Check name pattern
    const nameMatches = this.PHISHING_PATTERNS.some((pattern) =>
      pattern.test(tool.name),
    );
    if (nameMatches) return true;

    // Check description for patterns
    if (tool.description) {
      const descLower = tool.description.toLowerCase();

      const descMatches = this.PHISHING_PATTERNS.some((pattern) =>
        pattern.test(descLower),
      );
      if (descMatches) return true;

      // Check for deception keywords
      const hasDeception = this.DECEPTION_KEYWORDS.some((keyword) =>
        descLower.includes(keyword),
      );

      // Check for email/message generation combined with deception
      const isMessagingTool =
        descLower.includes("email") ||
        descLower.includes("message") ||
        descLower.includes("sms");

      if (hasDeception && isMessagingTool) return true;
    }

    // Check for malicious parameter names
    if (tool.inputSchema?.properties) {
      for (const propName of Object.keys(tool.inputSchema.properties)) {
        const propLower = propName.toLowerCase();
        const hasMaliciousParam = this.MALICIOUS_PARAM_NAMES.some((name) =>
          propLower.includes(name),
        );

        if (hasMaliciousParam) {
          // If parameter is named "victim" or "target", highly suspicious
          if (
            propLower === "victim" ||
            propLower === "target" ||
            propLower === "mark"
          ) {
            return true;
          }

          // If tool also generates content, it's suspicious
          const nameLower = tool.name.toLowerCase();
          if (
            nameLower.includes("generate") ||
            nameLower.includes("create") ||
            nameLower.includes("craft")
          ) {
            return true;
          }
        }
      }
    }

    return false;
  }
}
