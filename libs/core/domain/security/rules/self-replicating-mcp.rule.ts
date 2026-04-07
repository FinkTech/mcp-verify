/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SEC-058: Self-Replicating MCP Server (Worm Behavior)
 *
 * Block: D (AI Weaponization & Supply Chain MCP)
 * Severity: Critical
 * Type: Static + Behavioral
 *
 * Detects MCP servers with self-replication capabilities:
 * - Tools that install themselves on other systems
 * - Auto-propagation through network shares or APIs
 * - Worm-like spreading behavior
 *
 * Detection:
 * Static:
 * - Tools that deploy/install MCP servers remotely
 * - Tools scanning for vulnerable hosts
 * - Tools with "replicate", "spread", "propagate" keywords
 *
 * Behavioral:
 * - Monitor for unauthorized MCP server installations
 * - Detect network scanning patterns
 *
 * References:
 * - Computer Worm Detection
 * - CWE-912: Hidden Functionality
 * - Malware Analysis - Self-Replication
 */

import type { ISecurityRule } from "../rule.interface";
import type {
  DiscoveryResult,
  SecurityFinding,
} from "../../mcp-server/entities/validation.types";
import type { McpTool } from "../../shared/common.types";
import { t } from "@mcp-verify/shared";

export class SelfReplicatingMcpRule implements ISecurityRule {
  code = "SEC-058";
  name = "Self-Replicating MCP Server (Worm Behavior)";
  severity: "critical" = "critical";

  private readonly REPLICATION_KEYWORDS = [
    "replicate",
    "spread",
    "propagate",
    "clone",
    "duplicate",
    "copy.*self",
    "install.*self",
    "deploy.*self",
    "worm",
    "virus",
    "infect",
    "contaminate",
  ];

  private readonly DEPLOYMENT_PATTERNS = [
    /install.*mcp.*server/i,
    /deploy.*mcp.*server/i,
    /setup.*mcp.*server/i,
    /create.*mcp.*server/i,
    /spawn.*server/i,
    /launch.*remote.*server/i,
    /distribute.*server/i,
  ];

  private readonly SCANNING_KEYWORDS = [
    "scan.*network",
    "scan.*hosts",
    "find.*vulnerable",
    "discover.*targets",
    "enumerate.*systems",
    "probe.*network",
    "port.*scan",
    "host.*discovery",
    "network.*recon",
  ];

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (!discovery.tools || discovery.tools.length === 0) {
      return findings;
    }

    for (const tool of discovery.tools) {
      const hasReplication = this.hasReplicationCapability(tool);
      const hasDeployment = this.hasRemoteDeployment(tool);
      const hasScanning = this.hasNetworkScanning(tool);

      if (hasReplication || (hasDeployment && hasScanning)) {
        findings.push({
          severity: this.severity,
          message: t("sec_058_self_replicating", {
            toolName: tool.name,
            capability: hasReplication
              ? "self-replication"
              : "remote deployment + network scanning",
          }),
          component: `tool:${tool.name}`,
          ruleCode: this.code,
          remediation: t("sec_058_recommendation"),
          references: [
            "Computer Worm Detection and Prevention",
            "CWE-912: Hidden Functionality",
            "Malware Analysis - Self-Replication Mechanisms",
          ],
        });
      }
    }

    // Check server-level description
    if (discovery.serverInfo?.description) {
      const descLower = discovery.serverInfo.description.toLowerCase();

      const hasWormBehavior = this.REPLICATION_KEYWORDS.some((keyword) => {
        const pattern =
          typeof keyword === "string"
            ? new RegExp(keyword.replace(/\.\*/g, ".*"), "i")
            : keyword;
        return pattern.test(descLower);
      });

      if (hasWormBehavior) {
        findings.push({
          severity: "critical",
          message: t("sec_058_server_worm"),
          component: "server",
          ruleCode: this.code,
          remediation: t("sec_058_server_recommendation"),
          references: [
            "CWE-912: Hidden Functionality",
            "Malware Detection Best Practices",
          ],
        });
      }
    }

    return findings;
  }

  private hasReplicationCapability(tool: McpTool): boolean {
    const nameLower = tool.name.toLowerCase();
    const descLower = tool.description?.toLowerCase() || "";

    return this.REPLICATION_KEYWORDS.some((keyword) => {
      const pattern =
        typeof keyword === "string"
          ? new RegExp(keyword.replace(/\.\*/g, ".*"), "i")
          : keyword;
      return pattern.test(nameLower) || pattern.test(descLower);
    });
  }

  private hasRemoteDeployment(tool: McpTool): boolean {
    // Check name pattern
    const nameMatches = this.DEPLOYMENT_PATTERNS.some((pattern) =>
      pattern.test(tool.name),
    );
    if (nameMatches) return true;

    // Check description
    if (tool.description) {
      const descLower = tool.description.toLowerCase();
      const descMatches = this.DEPLOYMENT_PATTERNS.some((pattern) =>
        pattern.test(descLower),
      );
      if (descMatches) return true;
    }

    // Check for remote/target parameters
    if (tool.inputSchema?.properties) {
      for (const propName of Object.keys(tool.inputSchema.properties)) {
        const propLower = propName.toLowerCase();
        if (
          propLower.includes("remote") ||
          propLower.includes("target") ||
          propLower.includes("host")
        ) {
          // If tool also mentions deployment/installation
          const nameLower = tool.name.toLowerCase();
          const descLower = tool.description?.toLowerCase() || "";

          const mentionsDeployment =
            nameLower.includes("install") ||
            nameLower.includes("deploy") ||
            descLower.includes("install") ||
            descLower.includes("deploy");

          if (mentionsDeployment) return true;
        }
      }
    }

    return false;
  }

  private hasNetworkScanning(tool: McpTool): boolean {
    const nameLower = tool.name.toLowerCase();
    const descLower = tool.description?.toLowerCase() || "";

    return this.SCANNING_KEYWORDS.some((keyword) => {
      const pattern =
        typeof keyword === "string"
          ? new RegExp(keyword.replace(/\.\*/g, ".*"), "i")
          : keyword;
      return pattern.test(nameLower) || pattern.test(descLower);
    });
  }
}
