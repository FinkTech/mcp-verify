/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SEC-051: Weaponized MCP Fuzzer
 *
 * Block: D (AI Weaponization & Supply Chain MCP)
 * Severity: Critical
 * Type: Static (Pre-Execution)
 *
 * Detects MCP servers that implement fuzzing/testing capabilities which
 * could be weaponized for offensive security without authorization.
 *
 * Detection:
 * Static:
 * - Tools with names like "fuzz_", "exploit_", "attack_", "penetrate_"
 * - Payload generation tools for security testing
 * - Tools accepting target URLs/endpoints without authorization checks
 *
 * References:
 * - Offensive AI Toolkit Detection
 * - CWE-506: Embedded Malicious Code
 * - Responsible Disclosure Practices
 */

import type { ISecurityRule } from "../rule.interface";
import type {
  DiscoveryResult,
  SecurityFinding,
} from "../../mcp-server/entities/validation.types";
import type { McpTool } from "../../shared/common.types";
import { t } from "@mcp-verify/shared";

export class WeaponizedMcpFuzzerRule implements ISecurityRule {
  code = "SEC-051";
  name = "Weaponized MCP Fuzzer";
  severity: "critical" = "critical";

  private readonly OFFENSIVE_TOOL_PATTERNS = [
    /fuzz/i,
    /exploit/i,
    /attack/i,
    /penetrate/i,
    /pentest/i,
    /hack/i,
    /crack/i,
    /break/i,
    /breach/i,
    /pwn/i,
    /payload/i,
    /shellcode/i,
    /backdoor/i,
    /rootkit/i,
  ];

  private readonly PAYLOAD_KEYWORDS = [
    "payload",
    "injection",
    "xss",
    "sqli",
    "rce",
    "command_injection",
    "path_traversal",
    "xxe",
    "ssrf",
    "deserialization",
    "idor",
  ];

  private readonly AUTHORIZATION_KEYWORDS = [
    "authorized",
    "authorization",
    "consent",
    "permission",
    "approved",
    "whitelisted",
    "allowed",
    "verified",
  ];

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (!discovery.tools || discovery.tools.length === 0) {
      return findings;
    }

    for (const tool of discovery.tools) {
      const isOffensiveTool = this.isOffensiveSecurityTool(tool);

      if (isOffensiveTool) {
        const hasAuthorizationCheck = this.hasAuthorizationCheck(tool);

        if (!hasAuthorizationCheck) {
          findings.push({
            severity: this.severity,
            message: t("sec_051_weaponized_fuzzer", {
              toolName: tool.name,
            }),
            component: `tool:${tool.name}`,
            ruleCode: this.code,
            remediation: t("sec_051_recommendation"),
            references: [
              "Offensive AI Toolkit Detection",
              "CWE-506: Embedded Malicious Code",
              "Responsible Vulnerability Disclosure (ISO 29147)",
            ],
          });
        }
      }
    }

    return findings;
  }

  private isOffensiveSecurityTool(tool: McpTool): boolean {
    // Check name pattern
    const nameMatches = this.OFFENSIVE_TOOL_PATTERNS.some((pattern) =>
      pattern.test(tool.name),
    );
    if (nameMatches) return true;

    // Check description
    if (tool.description) {
      const descLower = tool.description.toLowerCase();
      const descMatches = this.OFFENSIVE_TOOL_PATTERNS.some((pattern) =>
        pattern.test(descLower),
      );
      if (descMatches) return true;

      // Check for payload keywords
      const hasPayloadKeyword = this.PAYLOAD_KEYWORDS.some((keyword) =>
        descLower.includes(keyword),
      );
      if (hasPayloadKeyword) return true;
    }

    // Check for target/endpoint parameters (suggests external testing)
    if (tool.inputSchema?.properties) {
      for (const propName of Object.keys(tool.inputSchema.properties)) {
        const propLower = propName.toLowerCase();
        if (
          propLower.includes("target") ||
          propLower.includes("endpoint") ||
          propLower.includes("victim")
        ) {
          return true;
        }
      }
    }

    return false;
  }

  private hasAuthorizationCheck(tool: McpTool): boolean {
    // Check description for authorization keywords
    if (tool.description) {
      const descLower = tool.description.toLowerCase();
      const hasAuth = this.AUTHORIZATION_KEYWORDS.some((keyword) =>
        descLower.includes(keyword),
      );
      if (hasAuth) return true;
    }

    // Check for authorization parameters
    if (tool.inputSchema?.properties) {
      for (const propName of Object.keys(tool.inputSchema.properties)) {
        const propLower = propName.toLowerCase();
        if (
          propLower.includes("authorization") ||
          propLower.includes("consent") ||
          propLower.includes("approved")
        ) {
          return true;
        }
      }
    }

    return false;
  }
}
