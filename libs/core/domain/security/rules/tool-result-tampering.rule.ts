/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SEC-032: Tool Result Tampering (Agent-in-the-Middle)
 *
 * Block: B (Multi-Agent & Agentic Chain Attacks)
 * Severity: Critical
 * Type: Static + Fuzzer
 *
 * Detects tools vulnerable to result tampering where intermediate agents
 * can modify tool responses before they reach the requesting agent.
 *
 * Detection:
 * Static:
 * - Tools missing integrity verification (signatures, hashes)
 * - No result validation schema
 * - Tools accepting results from other tools without verification
 *
 * Fuzzer:
 * - Test result modification and replay attacks
 *
 * References:
 * - Multi-Agent Security Framework (MASF) 2024 - Result Integrity
 * - CWE-345: Insufficient Verification of Data Authenticity
 */

import type { ISecurityRule } from "../rule.interface";
import type {
  DiscoveryResult,
  SecurityFinding,
} from "../../mcp-server/entities/validation.types";
import type { McpTool } from "../../shared/common.types";
import { t } from "@mcp-verify/shared";

export class ToolResultTamperingRule implements ISecurityRule {
  code = "SEC-032";
  name = "Tool Result Tampering (Agent-in-the-Middle)";
  severity: "critical" = "critical";

  private readonly RESULT_CONSUMER_PATTERNS = [
    /process.*result/i,
    /handle.*response/i,
    /consume.*output/i,
    /validate.*result/i,
    /parse.*response/i,
    /aggregate.*results/i,
  ];

  private readonly INTEGRITY_KEYWORDS = [
    "signature",
    "hash",
    "checksum",
    "hmac",
    "digest",
    "verify",
    "integrity",
    "authenticated",
    "signed",
  ];

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (!discovery.tools || discovery.tools.length === 0) {
      return findings;
    }

    for (const tool of discovery.tools) {
      const consumesResults = this.consumesToolResults(tool);

      if (consumesResults) {
        const hasIntegrityCheck = this.hasIntegrityVerification(tool);

        if (!hasIntegrityCheck) {
          findings.push({
            severity: this.severity,
            message: t("sec_032_result_tampering", {
              toolName: tool.name,
            }),
            component: `tool:${tool.name}`,
            ruleCode: this.code,
            remediation: t("sec_032_recommendation"),
            references: [
              "Multi-Agent Security Framework (MASF) 2024 - Result Integrity",
              "CWE-345: Insufficient Verification of Data Authenticity",
              "NIST SP 800-57 - Key Management",
            ],
          });
        }
      }
    }

    return findings;
  }

  private consumesToolResults(tool: McpTool): boolean {
    // Check tool name
    const nameMatches = this.RESULT_CONSUMER_PATTERNS.some((pattern) =>
      pattern.test(tool.name),
    );
    if (nameMatches) return true;

    // Check description
    if (tool.description) {
      const descLower = tool.description.toLowerCase();
      const descMatches = this.RESULT_CONSUMER_PATTERNS.some((pattern) =>
        pattern.test(descLower),
      );
      if (descMatches) return true;

      // Check for references to other tools
      const mentionsTools =
        descLower.includes("tool") ||
        descLower.includes("result") ||
        descLower.includes("response");
      if (mentionsTools) return true;
    }

    // Check for parameters that look like tool results
    if (tool.inputSchema?.properties) {
      for (const propName of Object.keys(tool.inputSchema.properties)) {
        const propLower = propName.toLowerCase();
        if (
          propLower.includes("result") ||
          propLower.includes("response") ||
          propLower.includes("output")
        ) {
          return true;
        }
      }
    }

    return false;
  }

  private hasIntegrityVerification(tool: McpTool): boolean {
    // Check description for integrity keywords
    if (tool.description) {
      const descLower = tool.description.toLowerCase();
      const hasKeyword = this.INTEGRITY_KEYWORDS.some((keyword) =>
        descLower.includes(keyword),
      );
      if (hasKeyword) return true;
    }

    // Check for integrity-related parameters
    if (tool.inputSchema?.properties) {
      for (const propName of Object.keys(tool.inputSchema.properties)) {
        const propLower = propName.toLowerCase();
        const hasIntegrityParam = this.INTEGRITY_KEYWORDS.some((keyword) =>
          propLower.includes(keyword),
        );
        if (hasIntegrityParam) return true;
      }
    }

    return false;
  }
}
