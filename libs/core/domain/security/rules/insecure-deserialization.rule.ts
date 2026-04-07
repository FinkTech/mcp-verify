/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Insecure Deserialization Detection Rule (SEC-006)
 *
 * Detects potential insecure deserialization vulnerabilities in MCP server tools.
 * Insecure deserialization can lead to remote code execution, injection attacks,
 * and privilege escalation.
 *
 * Validates:
 * - Tools that deserialize data from untrusted sources
 * - Use of dangerous formats (pickle, YAML unsafe_load, Java serialization)
 * - Lack of type validation or schema enforcement
 * - Missing integrity checks (signatures, HMACs)
 *
 * @module libs/core/domain/security/rules/insecure-deserialization.rule
 */

import { t } from "@mcp-verify/shared";
import { ISecurityRule } from "../rule.interface";
import type {
  DiscoveryResult,
  SecurityFinding,
} from "../../mcp-server/entities/validation.types";
import type { McpTool, JsonValue } from "../../shared/common.types";

export class InsecureDeserializationRule implements ISecurityRule {
  readonly code = "SEC-006";
  get name() {
    return t("sec_insecure_deserialization_name");
  }
  get description() {
    return t("sec_insecure_deserialization_desc");
  }
  readonly helpUri =
    "https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization";
  readonly tags = ["CWE-502", "OWASP-A08:2021", "Insecure Deserialization"];

  /**
   * Keywords indicating deserialization operations.
   */
  private readonly DESERIALIZATION_KEYWORDS = [
    "deserialize",
    "unserialize",
    "unpickle",
    "unmarshal",
    "decode",
    "parse",
    "load",
    "restore",
    "reconstruct",
  ];

  /**
   * Dangerous serialization formats that can execute code during deserialization.
   */
  private readonly DANGEROUS_FORMATS = [
    "pickle",
    "cpickle",
    "yaml",
    "java",
    "php",
    "ruby marshal",
    "native",
    "binary",
    ".net",
    "objectinputstream",
  ];

  /**
   * Safe serialization formats (still require validation).
   */
  private readonly SAFE_FORMATS = [
    "json",
    "xml",
    "protobuf",
    "msgpack",
    "avro",
    "thrift",
  ];

  /**
   * Indicators of safe deserialization practices.
   */
  private readonly SAFE_INDICATORS = [
    "schema validation",
    "type checking",
    "whitelist",
    "signature",
    "hmac",
    "signed",
    "verified",
    "safe_load",
    "limited deserialization",
  ];

  /**
   * Dangerous YAML methods.
   */
  private readonly UNSAFE_YAML = [
    "yaml.load",
    "yaml.unsafe_load",
    "yaml.fullload",
  ];

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (discovery.tools) {
      for (const tool of discovery.tools) {
        findings.push(...this.analyzeTool(tool));
      }
    }

    return findings;
  }

  private analyzeTool(tool: McpTool): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const isDeserializationTool = this.isDeserializationTool(
      tool.name,
      tool.description,
    );

    if (!isDeserializationTool) {
      return findings;
    }

    const hasSafeIndicators = this.hasSafePractices(tool.description);
    const dangerousFormat = this.detectDangerousFormat(
      tool.name,
      tool.description,
    );

    // CRITICAL: Tool uses dangerous serialization format
    if (dangerousFormat) {
      findings.push({
        severity: "critical",
        message: t("finding_deserialization_dangerous", {
          tool: tool.name,
          format: dangerousFormat,
        }),
        component: `tool:${tool.name}`,
        ruleCode: this.code,
        evidence: {
          dangerousFormat,
          risk: t("risk_deserialization_rce"),
        },
        remediation: t("remediation_deserialization_safe", {
          format: dangerousFormat,
        }),
      });
    }

    // Check for unsafe YAML usage
    if (this.detectUnsafeYAML(tool.description)) {
      findings.push({
        severity: "critical",
        message: t("finding_deserialization_unsafe_yaml", { tool: tool.name }),
        component: `tool:${tool.name}`,
        ruleCode: this.code,
        evidence: {
          risk: t("risk_deserialization_yaml"),
          detectedMethod: "yaml.load or yaml.unsafe_load",
        },
        remediation: t("remediation_deserialization_yaml"),
      });
    }

    if (!tool.inputSchema?.properties) {
      if (!hasSafeIndicators) {
        findings.push({
          severity: "high",
          message: t("finding_deserialization_no_schema", { tool: tool.name }),
          component: `tool:${tool.name}`,
          ruleCode: this.code,
          evidence: {
            risk: t("risk_deserialization_no_type"),
          },
          remediation: t("remediation_deserialization_strict"),
        });
      }
      return findings;
    }

    // Analyze parameters
    for (const [paramName, paramConfig] of Object.entries(
      tool.inputSchema.properties,
    )) {
      const config = paramConfig as Record<string, JsonValue>;

      // Check for parameters accepting serialized data
      if (this.isSerializedDataParam(paramName, config)) {
        // Missing type definition (accepts 'any')
        if (!config.type) {
          findings.push({
            severity: "critical",
            message: t("finding_deserialization_no_type", { param: paramName }),
            component: `tool:${tool.name}`,
            ruleCode: this.code,
            location: { type: "tool", name: tool.name, parameter: paramName },
            evidence: {
              risk: t("risk_deserialization_injection"),
              currentType: "any (unspecified)",
            },
            remediation: t("remediation_deserialization_explicit"),
          });
        }

        // Type is 'object' but no properties defined
        if (
          config.type === "object" &&
          !config.properties &&
          !config.additionalProperties
        ) {
          findings.push({
            severity: "high",
            message: t("finding_deserialization_arbitrary", {
              param: paramName,
            }),
            component: `tool:${tool.name}`,
            ruleCode: this.code,
            location: { type: "tool", name: tool.name, parameter: paramName },
            evidence: {
              risk: t("risk_deserialization_properties"),
            },
            remediation: t("remediation_deserialization_properties"),
          });
        }

        // NEW: Check for generic string parameters without any format validation, which is risky for deserialization
        if (
          config.type === "string" &&
          !config.format &&
          !this.hasSafePractices(tool.description)
        ) {
          findings.push({
            severity: "high",
            message: `Parameter '${paramName}' accepts a generic string for deserialization without format validation or safe indicators.`,
            component: `tool:${tool.name}`,
            ruleCode: this.code,
            location: { type: "tool", name: tool.name, parameter: paramName },
            evidence: {
              risk: "A generic string can be used to pass malicious payloads (e.g., encoded objects, RCE gadgets) that are processed by unsafe deserializers.",
              currentType: "string",
            },
            remediation:
              'Specify a strict `format` (e.g., `date-time`) or `pattern` for the string parameter, or document the safe handling practices (e.g., "uses safe_load") in the tool description.',
          });
        }

        // Check for base64/encoded data that might be serialized
        if (
          config.format === "base64" ||
          paramName.toLowerCase().includes("encoded")
        ) {
          findings.push({
            severity: "medium",
            message: t("finding_deserialization_encoded", { param: paramName }),
            component: `tool:${tool.name}`,
            ruleCode: this.code,
            location: { type: "tool", name: tool.name, parameter: paramName },
            evidence: {
              format: config.format || "encoded",
              risk: t("risk_deserialization_encoded"),
            },
            remediation: t("remediation_deserialization_encoded"),
          });
        }
      }
    }

    // Warn if no safe practices mentioned
    if (
      !hasSafeIndicators &&
      findings.some((f) => f.severity === "critical" || f.severity === "high")
    ) {
      findings.push({
        severity: "high",
        message: t("finding_deserialization_no_security", { tool: tool.name }),
        component: `tool:${tool.name}`,
        ruleCode: this.code,
        evidence: {
          missingIndicators: this.SAFE_INDICATORS.join(", "),
        },
        remediation: t("remediation_deserialization_all"),
      });
    }

    return findings;
  }

  private isDeserializationTool(name: string, description?: string): boolean {
    const text = `${name} ${description || ""}`.toLowerCase();
    return this.DESERIALIZATION_KEYWORDS.some((kw) => text.includes(kw));
  }

  private hasSafePractices(description?: string): boolean {
    if (!description) return false;
    const text = description.toLowerCase();
    return this.SAFE_INDICATORS.some((indicator) => text.includes(indicator));
  }

  private detectDangerousFormat(
    name: string,
    description?: string,
  ): string | null {
    const text = `${name} ${description || ""}`.toLowerCase();

    for (const format of this.DANGEROUS_FORMATS) {
      if (text.includes(format.toLowerCase())) {
        return format;
      }
    }

    return null;
  }

  private detectUnsafeYAML(description?: string): boolean {
    if (!description) return false;
    const text = description.toLowerCase();

    return this.UNSAFE_YAML.some((method) =>
      text.includes(method.toLowerCase()),
    );
  }

  private isSerializedDataParam(
    name: string,
    config: Record<string, JsonValue>,
  ): boolean {
    const serializedParamNames = [
      "data",
      "object",
      "payload",
      "serialized",
      "encoded",
      "pickled",
      "marshaled",
      "blob",
      "binary",
    ];

    const nameLower = name.toLowerCase();
    const descLower = (
      typeof config.description === "string" ? config.description : ""
    ).toLowerCase();

    return (
      serializedParamNames.some(
        (sp) => nameLower.includes(sp) || descLower.includes(sp),
      ) || this.DESERIALIZATION_KEYWORDS.some((kw) => descLower.includes(kw))
    );
  }
}
