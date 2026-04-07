/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SEC-048: Missing Capability Negotiation Validation
 *
 * Block: C (Operational Security & Enterprise Compliance)
 * Severity: Medium
 * Type: Fuzzer (requires handshake testing)
 *
 * Detects servers declaring capabilities they don't implement, or implementing
 * capabilities not declared. Inconsistency creates vulnerabilities when agents
 * make decisions based on capability manifest.
 *
 * Detection:
 * - Requires fuzzer to compare declared capabilities vs actual behavior
 * - This is a PLACEHOLDER for static analysis
 *
 * References:
 * - MCP Protocol Specification - Capabilities
 */

import type { ISecurityRule } from "../rule.interface";
import type {
  DiscoveryResult,
  SecurityFinding,
} from "../../mcp-server/entities/validation.types";

export class MissingCapabilityNegotiationRule implements ISecurityRule {
  code = "SEC-048";
  name = "Missing Capability Negotiation Validation";
  severity: "medium" = "medium";

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (!discovery.tools || discovery.tools.length === 0) {
      return findings;
    }

    // Keywords indicating dangerous features without capability checks
    const DANGEROUS_FEATURE_KEYWORDS = [
      "dangerous",
      "unsafe",
      "feature",
      "capability",
      "negotiate",
      "client capabilities",
    ];
    const CAPABILITY_CHECK_KEYWORDS = [
      "capability",
      "negotiate",
      "check capability",
      "validate capability",
      "supports",
    ];

    for (const tool of discovery.tools) {
      const toolText = `${tool.name} ${tool.description || ""}`.toLowerCase();

      // Check if tool mentions dangerous features
      const hasDangerousFeature = DANGEROUS_FEATURE_KEYWORDS.some((kw) =>
        toolText.includes(kw),
      );

      if (!hasDangerousFeature) continue;

      // Check if tool mentions capability checks
      const hasCapabilityCheck = CAPABILITY_CHECK_KEYWORDS.some((kw) =>
        toolText.includes(kw),
      );

      // Special case: mentions "without negotiating" or similar
      const explicitlyMissingNegotiation =
        toolText.includes("without negotiat") ||
        toolText.includes("sin negociar");

      if (
        explicitlyMissingNegotiation ||
        (hasDangerousFeature && !hasCapabilityCheck)
      ) {
        findings.push({
          ruleCode: this.code,
          severity: "medium",
          message: `Tool "${tool.name}" provides features without capability negotiation`,
          component: `tool:${tool.name}`,
          location: { type: "tool", name: tool.name },
          evidence: {
            risk: "Inconsistency between declared and actual capabilities creates vulnerabilities",
            detectedIssue:
              "Feature provided without checking client capabilities",
          },
          remediation:
            "Implement capability negotiation to verify client supports the feature before execution",
        });
      }
    }

    return findings;
  }
}
