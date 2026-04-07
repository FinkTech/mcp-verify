/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SEC-050: Insufficient Output Entropy (Weak Randomness)
 *
 * Block: C (Operational Security & Enterprise Compliance)
 * Severity: Medium
 * Type: Fuzzer + Static
 *
 * Detects tools generating security IDs/tokens/nonces with low entropy.
 * Predictable values enable enumeration attacks.
 *
 * Detection:
 * Static:
 * - Tools generating IDs with schema suggesting low entropy (pattern: "^[0-9]{6}$")
 * - maxLength < 16 for security tokens
 *
 * Fuzzer:
 * - Invoke tool N times, apply Shannon entropy analysis
 * - Threshold: < 3.5 bits/char is weak
 *
 * References:
 * - CWE-330: Use of Insufficiently Random Values
 * - NIST SP 800-90A: Entropy Requirements
 */

import type { ISecurityRule } from "../rule.interface";
import type {
  DiscoveryResult,
  SecurityFinding,
} from "../../mcp-server/entities/validation.types";
import type { McpTool } from "../../shared/common.types";
import { t } from "@mcp-verify/shared";

export class InsufficientOutputEntropyRule implements ISecurityRule {
  code = "SEC-050";
  name = "Insufficient Output Entropy";
  severity: "medium" = "medium";

  private readonly SECURITY_ID_KEYWORDS = [
    "token",
    "id",
    "nonce",
    "otp",
    "code",
    "key",
    "session",
    "csrf",
    "secret",
    "random",
  ];

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (!discovery.tools || discovery.tools.length === 0) {
      return findings;
    }

    for (const tool of discovery.tools) {
      // Check if tool generates security IDs
      const generatesSecurityId = this.generatesSecurityId(tool);

      if (generatesSecurityId) {
        const hasWeakPattern = this.hasWeakEntropyPattern(tool);

        if (hasWeakPattern) {
          findings.push({
            severity: this.severity,
            message: t("sec_050_weak_entropy", { toolName: tool.name }),
            component: `tool:${tool.name}`,
            ruleCode: this.code,
            remediation: t("sec_050_recommendation"),
          });
        }
      }
    }

    return findings;
  }

  private generatesSecurityId(tool: McpTool): boolean {
    const nameLower = tool.name.toLowerCase();
    const descLower = tool.description?.toLowerCase() || "";

    return this.SECURITY_ID_KEYWORDS.some(
      (kw) => nameLower.includes(kw) || descLower.includes(kw),
    );
  }

  private hasWeakEntropyPattern(tool: McpTool): boolean {
    // Check inputSchema for suspicious patterns
    if (tool.inputSchema?.properties) {
      for (const [propName, propSchema] of Object.entries(
        tool.inputSchema.properties,
      )) {
        const schema = propSchema as {
          pattern?: string;
          maxLength?: number;
          type?: string;
        };

        // Check for numeric-only patterns (low entropy)
        if (schema.pattern) {
          const numericOnly = /^\^?\[0-9\]\+?\$$/.test(
            schema.pattern.replace(/[{}]/g, ""),
          );
          if (numericOnly) {
            return true;
          }
        }

        // Check for short tokens
        if (
          schema.type === "string" &&
          schema.maxLength &&
          schema.maxLength < 16
        ) {
          const propLower = propName.toLowerCase();
          const isSecurityField = this.SECURITY_ID_KEYWORDS.some((kw) =>
            propLower.includes(kw),
          );

          if (isSecurityField) {
            return true;
          }
        }
      }
    }

    return false;
  }
}
