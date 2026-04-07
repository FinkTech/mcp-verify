/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Exposed Network Endpoint Detection Rule (SEC-014)
 *
 * Detects MCP servers exposed on public network interfaces that could be
 * accessed by unauthorized clients, enabling direct protocol-level attacks,
 * prompt injection, and data exfiltration.
 *
 * Validates:
 * - Server binding to 0.0.0.0 or :: (all interfaces) instead of localhost
 * - Exposed HTTP/HTTPS endpoints without network restrictions
 * - Missing firewall or network-level protection indicators
 * - Development servers running in production-like configurations
 *
 * Attack vectors:
 * - Direct JSON-RPC calls from unauthorized clients
 * - Prompt injection via network-accessible tool endpoints
 * - Resource exhaustion through unrestricted access
 * - Information disclosure via tool discovery
 *
 * @module libs/core/domain/security/rules/exposed-endpoint.rule
 */

import { t } from "@mcp-verify/shared";
import { ISecurityRule } from "../rule.interface";
import type {
  DiscoveryResult,
  SecurityFinding,
} from "../../mcp-server/entities/validation.types";
import type { McpTool, JsonValue } from "../../shared/common.types";

export class ExposedEndpointRule implements ISecurityRule {
  readonly code = "SEC-014";
  get name() {
    return t("sec_exposed_endpoint_name");
  }
  get description() {
    return t("sec_exposed_endpoint_desc");
  }
  readonly helpUri =
    "https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration";
  readonly tags = ["CWE-16", "CWE-749", "OWASP-A06:2021", "Network Exposure"];

  /**
   * Keywords indicating network binding or HTTP server configuration.
   */
  private readonly NETWORK_BINDING_KEYWORDS = [
    "listen",
    "bind",
    "host",
    "address",
    "interface",
    "port",
    "server",
    "http",
    "https",
    "socket",
    "tcp",
    "network",
  ];

  /**
   * Dangerous host configurations that expose servers publicly.
   */
  private readonly DANGEROUS_HOSTS = [
    "0.0.0.0", // IPv4 all interfaces
    "::", // IPv6 all interfaces
    "*", // Wildcard (some frameworks)
    "any", // Generic "any interface"
  ];

  /**
   * Indicators that network protection is configured.
   */
  private readonly PROTECTION_INDICATORS = [
    "firewall",
    "iptables",
    "security group",
    "network policy",
    "allowlist",
    "whitelist",
    "allowed ips",
    "ip filter",
    "localhost only",
    "127.0.0.1",
    "local only",
    "vpn",
    "private network",
    "internal only",
  ];

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    // Analyze tools for network-related configuration
    if (discovery.tools) {
      for (const tool of discovery.tools) {
        findings.push(...this.analyzeTool(tool));
      }
    }

    return findings;
  }

  private analyzeTool(tool: McpTool): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    const toolText = `${tool.name} ${tool.description || ""}`.toLowerCase();

    // Check if tool mentions network binding
    const hasNetworkBinding = this.NETWORK_BINDING_KEYWORDS.some((kw) =>
      toolText.includes(kw),
    );

    if (!hasNetworkBinding) {
      return findings; // Tool doesn't deal with network configuration
    }

    // Check for dangerous host configurations in description or schema
    const hasDangerousHost = this.hasDangerousHostConfiguration(tool);
    const hasProtection = this.hasNetworkProtection(tool);

    if (hasDangerousHost && !hasProtection) {
      findings.push({
        severity: "critical",
        message: t("finding_exposed_endpoint_public_binding", {
          tool: tool.name,
        }),
        component: `tool:${tool.name}`,
        ruleCode: this.code,
        evidence: {
          risk: t("risk_exposed_endpoint_unauthorized_access"),
          attackVectors: [
            t("attack_vector_direct_jsonrpc"),
            t("attack_vector_prompt_injection"),
            t("attack_vector_tool_abuse"),
          ],
        },
        remediation: t("remediation_exposed_endpoint_localhost"),
      });
    }

    // Check for missing network protection
    if (hasNetworkBinding && !hasProtection && !hasDangerousHost) {
      findings.push({
        severity: "high",
        message: t("finding_exposed_endpoint_no_protection", {
          tool: tool.name,
        }),
        component: `tool:${tool.name}`,
        ruleCode: this.code,
        evidence: {
          risk: t("risk_exposed_endpoint_unprotected"),
        },
        remediation: t("remediation_exposed_endpoint_add_protection"),
      });
    }

    // Check for parameters that configure network binding
    if (tool.inputSchema?.properties) {
      findings.push(...this.analyzeNetworkParameters(tool));
    }

    return findings;
  }

  private hasDangerousHostConfiguration(tool: McpTool): boolean {
    const description = tool.description?.toLowerCase() || "";
    const schemaStr = tool.inputSchema
      ? JSON.stringify(tool.inputSchema).toLowerCase()
      : "";

    const fullText = `${description} ${schemaStr}`;

    return this.DANGEROUS_HOSTS.some((host) => fullText.includes(host));
  }

  private hasNetworkProtection(tool: McpTool): boolean {
    const description = tool.description?.toLowerCase() || "";
    const schemaStr = tool.inputSchema
      ? JSON.stringify(tool.inputSchema).toLowerCase()
      : "";

    const fullText = `${description} ${schemaStr}`;

    return this.PROTECTION_INDICATORS.some((indicator) =>
      fullText.includes(indicator),
    );
  }

  private analyzeNetworkParameters(tool: McpTool): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (!tool.inputSchema?.properties) {
      return findings;
    }

    for (const [paramName, paramConfig] of Object.entries(
      tool.inputSchema.properties,
    )) {
      const config = paramConfig as Record<string, JsonValue>;
      const paramNameLower = paramName.toLowerCase();

      // Check for host/address parameters
      if (
        paramNameLower === "host" ||
        paramNameLower === "address" ||
        paramNameLower === "bind" ||
        paramNameLower === "interface"
      ) {
        const hasEnum = config.enum && Array.isArray(config.enum);
        const defaultValue = config.default as string | undefined;

        // Check if default is dangerous
        if (
          defaultValue &&
          this.DANGEROUS_HOSTS.includes(defaultValue.toLowerCase())
        ) {
          findings.push({
            severity: "critical",
            message: t("finding_exposed_endpoint_param_default", {
              param: paramName,
              value: defaultValue,
            }),
            component: `tool:${tool.name}`,
            ruleCode: this.code,
            location: { type: "tool", name: tool.name, parameter: paramName },
            evidence: {
              defaultValue,
              risk: t("risk_exposed_endpoint_default_public"),
            },
            remediation: t("remediation_exposed_endpoint_safe_default"),
          });
        }

        // Check if enum allows dangerous values
        if (hasEnum && config.enum) {
          const dangerousValues = (config.enum as string[]).filter((val) =>
            this.DANGEROUS_HOSTS.includes(String(val).toLowerCase()),
          );

          if (dangerousValues.length > 0) {
            findings.push({
              severity: "high",
              message: t("finding_exposed_endpoint_param_allows", {
                param: paramName,
                values: dangerousValues.join(", "),
              }),
              component: `tool:${tool.name}`,
              ruleCode: this.code,
              location: { type: "tool", name: tool.name, parameter: paramName },
              evidence: {
                dangerousValues,
                risk: t("risk_exposed_endpoint_configurable"),
              },
              remediation: t("remediation_exposed_endpoint_restrict_enum"),
            });
          }
        }

        // Check for missing validation pattern
        if (!config.pattern && !hasEnum) {
          findings.push({
            severity: "medium",
            message: t("finding_exposed_endpoint_param_no_validation", {
              param: paramName,
            }),
            component: `tool:${tool.name}`,
            ruleCode: this.code,
            location: { type: "tool", name: tool.name, parameter: paramName },
            remediation: t("remediation_exposed_endpoint_add_validation"),
          });
        }
      }
    }

    return findings;
  }
}
