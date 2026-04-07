/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SEC-036: Distributed Agent Denial of Service
 *
 * Block: B (Multi-Agent & Agentic Chain Attacks)
 * Severity: High
 * Type: Static + Fuzzer
 *
 * Detects tools vulnerable to coordinated DoS attacks from multiple agents,
 * or tools that can be weaponized for DDoS attacks.
 *
 * Detection:
 * Static:
 * - Tools without per-agent rate limiting
 * - Tools that can trigger external requests (SSRF amplification)
 * - Missing global rate limits across all agents
 *
 * Fuzzer:
 * - Test concurrent agent requests
 * - Measure resource exhaustion
 *
 * References:
 * - Multi-Agent Security Framework (MASF) 2024 - Resource Quotas
 * - CWE-400: Uncontrolled Resource Consumption
 */

import type { ISecurityRule } from "../rule.interface";
import type {
  DiscoveryResult,
  SecurityFinding,
} from "../../mcp-server/entities/validation.types";
import type { McpTool } from "../../shared/common.types";
import { t } from "@mcp-verify/shared";

export class DistributedAgentDdosRule implements ISecurityRule {
  code = "SEC-036";
  name = "Distributed Agent Denial of Service";
  severity: "high" = "high";

  private readonly AMPLIFICATION_PATTERNS = [
    /broadcast/i,
    /notify.*all/i,
    /send.*all/i,
    /trigger.*webhook/i,
    /call.*api/i,
    /fetch.*url/i,
    /request.*external/i,
    /invoke.*remote/i,
  ];

  private readonly RESOURCE_INTENSIVE_KEYWORDS = [
    "process",
    "compute",
    "calculate",
    "analyze",
    "generate",
    "render",
    "compile",
    "transform",
    "encode",
    "decode",
    "compress",
    "encrypt",
  ];

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (!discovery.tools || discovery.tools.length === 0) {
      return findings;
    }

    // Check server-level rate limiting
    const hasGlobalRateLimit = this.hasGlobalRateLimiting(discovery);

    for (const tool of discovery.tools) {
      const isAmplifiable = this.isAmplificationVector(tool);
      const isResourceIntensive = this.isResourceIntensive(tool);

      if (isAmplifiable || isResourceIntensive) {
        const hasPerAgentLimit = this.hasPerAgentRateLimit(tool);

        if (!hasPerAgentLimit && !hasGlobalRateLimit) {
          const severity = isAmplifiable ? "high" : "medium";

          findings.push({
            severity,
            message: t("sec_036_agent_ddos", {
              toolName: tool.name,
              reason: isAmplifiable
                ? "amplification vector"
                : "resource intensive",
            }),
            component: `tool:${tool.name}`,
            ruleCode: this.code,
            remediation: t("sec_036_recommendation"),
            references: [
              "Multi-Agent Security Framework (MASF) 2024 - Resource Quotas",
              "CWE-400: Uncontrolled Resource Consumption",
              "OWASP API Security - Rate Limiting",
            ],
          });
        }
      }
    }

    return findings;
  }

  private hasGlobalRateLimiting(discovery: DiscoveryResult): boolean {
    if (!discovery.serverInfo) return false;

    const serverDesc = discovery.serverInfo.description?.toLowerCase() || "";
    const rateLimitKeywords = [
      "rate limit",
      "throttle",
      "quota",
      "rate-limit",
      "requests per",
      "rps limit",
      "qps limit",
    ];

    return rateLimitKeywords.some((keyword) => serverDesc.includes(keyword));
  }

  private isAmplificationVector(tool: McpTool): boolean {
    // Check name pattern
    const nameMatches = this.AMPLIFICATION_PATTERNS.some((pattern) =>
      pattern.test(tool.name),
    );
    if (nameMatches) return true;

    // Check description
    if (tool.description) {
      const descLower = tool.description.toLowerCase();
      const descMatches = this.AMPLIFICATION_PATTERNS.some((pattern) =>
        pattern.test(descLower),
      );
      if (descMatches) return true;
    }

    // Check for URL/webhook parameters (potential SSRF/amplification)
    if (tool.inputSchema?.properties) {
      for (const propName of Object.keys(tool.inputSchema.properties)) {
        const propLower = propName.toLowerCase();
        if (
          propLower.includes("url") ||
          propLower.includes("webhook") ||
          propLower.includes("endpoint")
        ) {
          return true;
        }
      }
    }

    return false;
  }

  private isResourceIntensive(tool: McpTool): boolean {
    const nameLower = tool.name.toLowerCase();
    const descLower = tool.description?.toLowerCase() || "";

    return this.RESOURCE_INTENSIVE_KEYWORDS.some(
      (keyword) => nameLower.includes(keyword) || descLower.includes(keyword),
    );
  }

  private hasPerAgentRateLimit(tool: McpTool): boolean {
    // Check description for rate limiting mentions
    if (tool.description) {
      const descLower = tool.description.toLowerCase();
      const rateLimitKeywords = [
        "rate limit",
        "throttle",
        "per agent",
        "per user",
        "quota",
        "limit per",
        "max requests",
      ];

      const hasRateLimit = rateLimitKeywords.some((keyword) =>
        descLower.includes(keyword),
      );
      if (hasRateLimit) return true;
    }

    // Check for agent_id parameter (suggests per-agent tracking)
    if (tool.inputSchema?.properties) {
      const paramNames = Object.keys(tool.inputSchema.properties).map((p) =>
        p.toLowerCase(),
      );
      const hasAgentId =
        paramNames.includes("agent_id") || paramNames.includes("user_id");
      if (hasAgentId) return true;
    }

    return false;
  }
}
