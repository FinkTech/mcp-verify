/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SEC-049: Timing Side-Channel in Authentication
 *
 * Block: C (Operational Security & Enterprise Compliance)
 * Severity: Medium
 * Type: Fuzzer (requires timing analysis)
 *
 * Detects authentication operations with timing variance that reveals validity.
 * Allows user/token enumeration via timing attacks.
 *
 * Detection:
 * - Requires fuzzer to send valid/invalid credentials and measure response times
 * - Statistical significance test (t-test on n≥30 samples)
 * - This is a PLACEHOLDER for static analysis
 *
 * References:
 * - CWE-208: Observable Timing Discrepancy
 * - OWASP Authentication Cheat Sheet
 */

import type { ISecurityRule } from "../rule.interface";
import type {
  DiscoveryResult,
  SecurityFinding,
} from "../../mcp-server/entities/validation.types";

export class TimingSideChannelAuthRule implements ISecurityRule {
  code = "SEC-049";
  name = "Timing Side-Channel in Authentication";
  severity: "medium" = "medium";

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (!discovery.tools || discovery.tools.length === 0) {
      return findings;
    }

    // Keywords indicating authentication operations
    const AUTH_KEYWORDS = [
      "login",
      "authenticate",
      "auth",
      "signin",
      "verify",
      "check_password",
      "check_credentials",
      "secret",
      "password_check",
    ];

    // Red flags for timing vulnerabilities
    const UNSAFE_COMPARISON = ["===", "==", "equals", "strcmp", "compare"];
    const TIMING_SAFE_INDICATORS = [
      "constant time",
      "timing-safe",
      "constant_time",
      "timing_safe",
      "secure_compare",
      "crypto.timingSafeEqual",
    ];

    for (const tool of discovery.tools) {
      const toolText = `${tool.name} ${tool.description || ""}`.toLowerCase();

      // Check if this is an authentication tool
      const isAuthTool = AUTH_KEYWORDS.some((kw) => toolText.includes(kw));

      if (!isAuthTool) continue;

      // Check for timing-safe indicators
      const hasTimingSafe = TIMING_SAFE_INDICATORS.some((ind) =>
        toolText.includes(ind),
      );

      // Check for unsafe comparison indicators
      const hasUnsafeComparison = UNSAFE_COMPARISON.some((cmp) =>
        toolText.includes(cmp),
      );

      // If auth tool lacks timing-safe comparison, flag it
      if (!hasTimingSafe) {
        findings.push({
          ruleCode: this.code,
          severity: "medium",
          message: `Tool "${tool.name}" performs authentication without documented timing-safe comparison`,
          component: `tool:${tool.name}`,
          location: { type: "tool", name: tool.name },
          evidence: {
            risk: "Timing attacks can reveal valid usernames/passwords through response time analysis",
            detectedOperation:
              "Authentication operation without timing-safe guarantees",
          },
          remediation:
            "Use constant-time comparison functions (crypto.timingSafeEqual in Node.js, hmac.compare_digest in Python) for credential verification",
        });
      }

      // Higher severity if explicitly mentions unsafe comparison
      if (hasUnsafeComparison && !hasTimingSafe) {
        findings.push({
          ruleCode: this.code,
          severity: "high",
          message: `Tool "${tool.name}" uses unsafe comparison method for authentication`,
          component: `tool:${tool.name}`,
          location: { type: "tool", name: tool.name },
          evidence: {
            risk: "Direct string comparison leaks timing information",
            detectedMethod: "Non-constant-time comparison detected",
          },
          remediation:
            "Replace direct comparison with timing-safe alternatives",
        });
      }
    }

    return findings;
  }
}
