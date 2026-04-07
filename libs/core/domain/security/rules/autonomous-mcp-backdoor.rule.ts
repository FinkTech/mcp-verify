/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SEC-052: Autonomous MCP Backdoor
 *
 * Block: D (AI Weaponization & Supply Chain MCP)
 * Severity: Critical
 * Type: Static + Behavioral
 *
 * Detects MCP servers with suspicious autonomous behaviors:
 * - Self-modifying code
 * - Unrequested network connections
 * - Hidden tool invocations
 * - Covert data exfiltration
 *
 * Detection:
 * Static:
 * - Tools that modify server code or install dependencies
 * - Tools with "stealth", "hidden", "covert" keywords
 * - Scheduled/background tasks without user consent
 *
 * Behavioral:
 * - Monitor for unrequested tool calls
 * - Detect network connections not initiated by user
 *
 * References:
 * - Advanced Persistent Threat (APT) Detection
 * - CWE-506: Embedded Malicious Code
 * - Backdoor Detection in AI Systems
 */

import type { ISecurityRule } from "../rule.interface";
import type {
  DiscoveryResult,
  SecurityFinding,
} from "../../mcp-server/entities/validation.types";
import type { McpTool } from "../../shared/common.types";
import { t } from "@mcp-verify/shared";

export class AutonomousMcpBackdoorRule implements ISecurityRule {
  code = "SEC-052";
  name = "Autonomous MCP Backdoor";
  severity: "critical" = "critical";

  private readonly SELF_MODIFICATION_PATTERNS = [
    /update.*self/i,
    /upgrade.*self/i,
    /patch.*self/i,
    /modify.*code/i,
    /rewrite.*self/i,
    /install.*dependency/i,
    /exec.*code/i,
    /eval.*code/i,
    /compile.*self/i,
  ];

  private readonly STEALTH_KEYWORDS = [
    "stealth",
    "hidden",
    "covert",
    "secret",
    "invisible",
    "background",
    "silent",
    "unattended",
    "autonomous",
    "scheduled",
    "cron",
    "periodic",
    "interval",
  ];

  private readonly BACKDOOR_PATTERNS = [
    /reverse.*shell/i,
    /command.*control/i,
    /c2/i,
    /c&c/i,
    /beacon/i,
    /phone.*home/i,
    /exfiltrate/i,
    /tunnel/i,
    /proxy.*traffic/i,
    /relay/i,
  ];

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (!discovery.tools || discovery.tools.length === 0) {
      return findings;
    }

    for (const tool of discovery.tools) {
      const modifiesSelf = this.hasSelfModification(tool);
      const isStealthy = this.hasStealthBehavior(tool);
      const isBackdoor = this.hasBackdoorPattern(tool);

      if (modifiesSelf || isStealthy || isBackdoor) {
        const severity = isBackdoor ? "critical" : "high";

        findings.push({
          severity,
          message: t("sec_052_autonomous_backdoor", {
            toolName: tool.name,
            behavior: isBackdoor
              ? "backdoor pattern detected"
              : modifiesSelf
                ? "self-modification capability"
                : "stealth/autonomous behavior",
          }),
          component: `tool:${tool.name}`,
          ruleCode: this.code,
          remediation: t("sec_052_recommendation"),
          references: [
            "Advanced Persistent Threat (APT) Detection",
            "CWE-506: Embedded Malicious Code",
            "Backdoor Detection in AI Systems (2024)",
          ],
        });
      }
    }

    // Check server-level for suspicious autonomous capabilities
    if (discovery.serverInfo?.description) {
      const descLower = discovery.serverInfo.description.toLowerCase();

      const hasAutonomousBehavior =
        this.STEALTH_KEYWORDS.some((kw) => descLower.includes(kw)) ||
        this.BACKDOOR_PATTERNS.some((pattern) => pattern.test(descLower));

      if (hasAutonomousBehavior) {
        findings.push({
          severity: "critical",
          message: t("sec_052_server_autonomous"),
          component: "server",
          ruleCode: this.code,
          remediation: t("sec_052_server_recommendation"),
          references: [
            "CWE-506: Embedded Malicious Code",
            "Malware Detection Best Practices",
          ],
        });
      }
    }

    return findings;
  }

  private hasSelfModification(tool: McpTool): boolean {
    // Check name pattern
    const nameMatches = this.SELF_MODIFICATION_PATTERNS.some((pattern) =>
      pattern.test(tool.name),
    );
    if (nameMatches) return true;

    // Check description
    if (tool.description) {
      const descLower = tool.description.toLowerCase();
      const descMatches = this.SELF_MODIFICATION_PATTERNS.some((pattern) =>
        pattern.test(descLower),
      );
      if (descMatches) return true;
    }

    return false;
  }

  private hasStealthBehavior(tool: McpTool): boolean {
    const nameLower = tool.name.toLowerCase();
    const descLower = tool.description?.toLowerCase() || "";

    return this.STEALTH_KEYWORDS.some(
      (keyword) => nameLower.includes(keyword) || descLower.includes(keyword),
    );
  }

  private hasBackdoorPattern(tool: McpTool): boolean {
    // Check name pattern
    const nameMatches = this.BACKDOOR_PATTERNS.some((pattern) =>
      pattern.test(tool.name),
    );
    if (nameMatches) return true;

    // Check description
    if (tool.description) {
      const descLower = tool.description.toLowerCase();
      const descMatches = this.BACKDOOR_PATTERNS.some((pattern) =>
        pattern.test(descLower),
      );
      if (descMatches) return true;
    }

    return false;
  }
}
