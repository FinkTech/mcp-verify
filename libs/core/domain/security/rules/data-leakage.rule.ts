/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Data Leakage Detection Rule (SEC-008)
 *
 * Detects potential exposure of sensitive information (PII, Secrets).
 *
 * Validates:
 * - Tool parameters asking for clear-text secrets (passwords, tokens).
 * - Resources that appear to expose configuration or credentials.
 *
 * @module libs/core/domain/security/rules/data-leakage.rule
 */

import { t } from "@mcp-verify/shared";
import { ISecurityRule } from "../rule.interface";
import type {
  DiscoveryResult,
  SecurityFinding,
} from "../../mcp-server/entities/validation.types";
import type {
  McpTool,
  McpResource,
  JsonValue,
} from "../../shared/common.types";

export class DataLeakageRule implements ISecurityRule {
  readonly code = "SEC-008";
  get name() {
    return t("sec_data_leakage_name");
  }
  get description() {
    return t("sec_data_leakage_desc");
  }
  readonly helpUri =
    "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure";
  readonly tags = ["CWE-200", "OWASP-A01:2021", "Information Disclosure"];

  private readonly SENSITIVE_KEYWORDS = [
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "auth_code",
    "credential",
    "ssn",
    "credit_card",
  ];

  private readonly RISKY_RESOURCE_EXTENSIONS = [
    ".env",
    ".key",
    ".pem",
    ".p12",
    ".pfx",
    ".kdbx",
    "id_rsa",
    "config.json",
    "settings.xml",
  ];

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    // Analyze Tools for input leakage
    if (discovery.tools) {
      for (const tool of discovery.tools) {
        findings.push(...this.analyzeTool(tool));
      }
    }

    // Analyze Resources for output leakage
    if (discovery.resources) {
      for (const resource of discovery.resources) {
        findings.push(...this.analyzeResource(resource));
      }
    }

    return findings;
  }

  private analyzeTool(tool: McpTool): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    if (!tool.inputSchema?.properties) return findings;

    for (const [paramName, paramConfig] of Object.entries(
      tool.inputSchema.properties,
    )) {
      const config = paramConfig as Record<string, JsonValue>;

      if (
        this.isSensitive(
          paramName,
          typeof config.description === "string"
            ? config.description
            : undefined,
        )
      ) {
        // Warning: Tool accepts secrets.
        // We can't know for sure if they handle it safely, but we warn about using it in plain arguments.
        // Ideally, secrets should be environment variables or managed by the host, not passed as arguments by the LLM.
        findings.push({
          severity: "medium",
          message: t("finding_data_leakage_sensitive", {
            tool: tool.name,
            param: paramName,
          }),
          component: `tool:${tool.name}`,
          ruleCode: this.code,
          location: { type: "tool", name: tool.name, parameter: paramName },
          evidence: { parameter: paramName },
          remediation: t("avoid_passing_secrets_as_tool_arguments_use_enviro"),
        });
      }
    }
    return findings;
  }

  private analyzeResource(resource: McpResource): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const uri = (resource.uri || "").toLowerCase();
    const name = (resource.name || "").toLowerCase();

    // Check against risky extensions/filenames
    const isRiskyFile = this.RISKY_RESOURCE_EXTENSIONS.some(
      (ext) => uri.endsWith(ext) || name.includes(ext),
    );

    if (isRiskyFile) {
      findings.push({
        severity: "critical",
        message: t("finding_data_leakage_resource", {
          resource: resource.name || t("unknown"),
        }),
        component: `resource:${resource.name || t("unknown")}`,
        ruleCode: this.code,
        location: { type: "resource", uri: resource.uri },
        evidence: {
          uri: resource.uri,
          match: t("risk_data_leakage_risky_file"),
        },
        remediation: t("do_not_expose_configuration_files_keys_or_credenti"),
      });
    }

    return findings;
  }

  private isSensitive(name: string, description?: string): boolean {
    const text = `${name} ${description || ""}`.toLowerCase();
    return this.SENSITIVE_KEYWORDS.some((k) => text.includes(k));
  }
}
