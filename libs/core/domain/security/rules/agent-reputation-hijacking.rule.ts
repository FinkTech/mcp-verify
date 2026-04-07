/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SEC-038: Agent Reputation Hijacking
 *
 * Block: B (Multi-Agent & Agentic Chain Attacks)
 * Severity: Medium
 * Type: Static + Semantic
 *
 * Detects scenarios where malicious agents can impersonate trusted agents
 * by copying reputation scores, badges, or trust metrics.
 *
 * Detection:
 * Static:
 * - Tools that modify agent reputation/trust scores
 * - Missing cryptographic signatures on reputation data
 * - No verification of reputation source
 *
 * Semantic:
 * - LLM analyzes reputation system design
 *
 * References:
 * - Multi-Agent Security Framework (MASF) 2024 - Trust Model
 * - CWE-290: Authentication Bypass by Spoofing
 */

import type { ISecurityRule } from "../rule.interface";
import type {
  DiscoveryResult,
  SecurityFinding,
} from "../../mcp-server/entities/validation.types";
import type { McpTool } from "../../shared/common.types";
import { t } from "@mcp-verify/shared";

export class AgentReputationHijackingRule implements ISecurityRule {
  code = "SEC-038";
  name = "Agent Reputation Hijacking";
  severity: "medium" = "medium";

  private readonly REPUTATION_KEYWORDS = [
    "reputation",
    "trust",
    "score",
    "rating",
    "rank",
    "badge",
    "credential",
    "certification",
    "level",
    "karma",
    "points",
    "credibility",
    "trustworthiness",
  ];

  private readonly REPUTATION_MODIFICATION_PATTERNS = [
    /set.*reputation/i,
    /update.*trust/i,
    /modify.*score/i,
    /assign.*badge/i,
    /grant.*credential/i,
    /increase.*rating/i,
    /boost.*score/i,
    /elevate.*rank/i,
  ];

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (!discovery.tools || discovery.tools.length === 0) {
      return findings;
    }

    for (const tool of discovery.tools) {
      const modifiesReputation = this.modifiesReputationSystem(tool);

      if (modifiesReputation) {
        const hasVerification = this.hasReputationVerification(tool);

        if (!hasVerification) {
          findings.push({
            severity: this.severity,
            message: t("sec_038_reputation_hijacking", {
              toolName: tool.name,
            }),
            component: `tool:${tool.name}`,
            ruleCode: this.code,
            remediation: t("sec_038_recommendation"),
            references: [
              "Multi-Agent Security Framework (MASF) 2024 - Trust Model",
              "CWE-290: Authentication Bypass by Spoofing",
              "Sybil Attack Prevention in Distributed Systems",
            ],
          });
        }
      }
    }

    return findings;
  }

  private modifiesReputationSystem(tool: McpTool): boolean {
    // Check name pattern
    const nameMatches = this.REPUTATION_MODIFICATION_PATTERNS.some((pattern) =>
      pattern.test(tool.name),
    );
    if (nameMatches) return true;

    // Check description
    if (tool.description) {
      const descLower = tool.description.toLowerCase();
      const descMatches = this.REPUTATION_MODIFICATION_PATTERNS.some(
        (pattern) => pattern.test(descLower),
      );
      if (descMatches) return true;

      // Check for reputation keywords
      const hasReputationKeyword = this.REPUTATION_KEYWORDS.some((keyword) =>
        descLower.includes(keyword),
      );
      const mentionsModification =
        descLower.includes("set") ||
        descLower.includes("update") ||
        descLower.includes("modify");
      if (hasReputationKeyword && mentionsModification) return true;
    }

    // Check for reputation parameters
    if (tool.inputSchema?.properties) {
      for (const propName of Object.keys(tool.inputSchema.properties)) {
        const propLower = propName.toLowerCase();
        const isReputationParam = this.REPUTATION_KEYWORDS.some((keyword) =>
          propLower.includes(keyword),
        );
        if (isReputationParam) return true;
      }
    }

    return false;
  }

  private hasReputationVerification(tool: McpTool): boolean {
    // Check description for verification keywords
    if (tool.description) {
      const descLower = tool.description.toLowerCase();
      const verificationKeywords = [
        "verified",
        "authenticated",
        "signed",
        "cryptographic",
        "signature",
        "proof",
        "attestation",
        "certificate",
        "validate",
        "verify",
        "check signature",
      ];

      const hasVerification = verificationKeywords.some((keyword) =>
        descLower.includes(keyword),
      );
      if (hasVerification) return true;
    }

    // Check for signature/proof parameters
    if (tool.inputSchema?.properties) {
      for (const propName of Object.keys(tool.inputSchema.properties)) {
        const propLower = propName.toLowerCase();
        if (
          propLower.includes("signature") ||
          propLower.includes("proof") ||
          propLower.includes("certificate")
        ) {
          return true;
        }
      }
    }

    return false;
  }
}
