/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Missing Input Constraints Detection Rule (SEC-019)
 *
 * Detects parameters lacking basic input validation constraints such as
 * maxLength, minLength, pattern, minimum, maximum. While not always a
 * security vulnerability, missing constraints can lead to DoS attacks,
 * buffer issues, and poor data quality.
 *
 * Validates:
 * - String parameters without maxLength (potential DoS)
 * - Numeric parameters without bounds (integer overflow)
 * - Parameters without format validation (pattern)
 * - Arrays without size limits
 *
 * Attack vectors:
 * - Denial of Service via extremely large inputs
 * - LLM token exhaustion with massive strings
 * - Memory exhaustion with unbounded arrays
 * - Integer overflow vulnerabilities
 *
 * Note: This rule is informational (Low severity) and disabled by default.
 * Enable via config: security.rules['SEC-019'].enabled = true
 *
 * @module libs/core/domain/security/rules/missing-input-constraints.rule
 */

import { t } from "@mcp-verify/shared";
import { ISecurityRule } from "../rule.interface";
import type {
  DiscoveryResult,
  SecurityFinding,
} from "../../mcp-server/entities/validation.types";
import type { McpTool, JsonValue } from "../../shared/common.types";

export class MissingInputConstraintsRule implements ISecurityRule {
  readonly code = "SEC-019";
  get name() {
    return t("sec_missing_constraints_name");
  }
  get description() {
    return t("sec_missing_constraints_desc");
  }
  readonly helpUri =
    "https://owasp.org/www-project-top-ten/2017/A4_2017-XML_External_Entities_(XXE)";
  readonly tags = ["CWE-1284", "CWE-20", "OWASP-A04:2021", "Input Validation"];

  /**
   * Recommended maximum string length (10MB)
   */
  private readonly RECOMMENDED_MAX_STRING_LENGTH = 10 * 1024 * 1024;

  /**
   * Recommended maximum array items
   */
  private readonly RECOMMENDED_MAX_ARRAY_ITEMS = 10000;

  /**
   * Parameter names that should always have constraints
   */
  private readonly CRITICAL_PARAMS = [
    "query",
    "sql",
    "command",
    "script",
    "code",
    "path",
    "url",
    "uri",
    "filename",
    "email",
    "username",
    "password",
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

    if (!tool.inputSchema?.properties) {
      return findings;
    }

    for (const [paramName, paramConfig] of Object.entries(
      tool.inputSchema.properties,
    )) {
      const config = paramConfig as Record<string, JsonValue>;
      const paramType = config.type as string;

      // Check string parameters
      if (paramType === "string") {
        findings.push(
          ...this.checkStringConstraints(paramName, config, tool.name),
        );
      }

      // Check numeric parameters
      if (paramType === "number" || paramType === "integer") {
        findings.push(
          ...this.checkNumericConstraints(paramName, config, tool.name),
        );
      }

      // Check array parameters
      if (paramType === "array") {
        findings.push(
          ...this.checkArrayConstraints(paramName, config, tool.name),
        );
      }

      // Check object parameters
      if (paramType === "object") {
        findings.push(
          ...this.checkObjectConstraints(paramName, config, tool.name),
        );
      }
    }

    return findings;
  }

  private checkStringConstraints(
    paramName: string,
    config: Record<string, JsonValue>,
    toolName: string,
  ): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const isCritical = this.CRITICAL_PARAMS.some((kw) =>
      paramName.toLowerCase().includes(kw),
    );

    // Missing maxLength
    if (!config.maxLength && !config.pattern && !config.enum) {
      findings.push({
        severity: isCritical ? "medium" : "low",
        message: t("finding_missing_constraints_maxlength", {
          param: paramName,
          tool: toolName,
        }),
        component: `tool:${toolName}`,
        ruleCode: this.code,
        location: { type: "tool", name: toolName, parameter: paramName },
        evidence: {
          parameterType: "string",
          missingConstraint: "maxLength",
          risk: t("risk_missing_constraints_dos"),
        },
        remediation: t("remediation_missing_constraints_add_maxlength", {
          recommended: this.RECOMMENDED_MAX_STRING_LENGTH,
        }),
      });
    }

    // Missing pattern for critical params
    if (isCritical && !config.pattern && !config.enum) {
      findings.push({
        severity: "low",
        message: t("finding_missing_constraints_pattern", {
          param: paramName,
          tool: toolName,
        }),
        component: `tool:${toolName}`,
        ruleCode: this.code,
        location: { type: "tool", name: toolName, parameter: paramName },
        evidence: {
          parameterType: "string",
          missingConstraint: "pattern",
          isCriticalParam: true,
        },
        remediation: t("remediation_missing_constraints_add_pattern"),
      });
    }

    return findings;
  }

  private checkNumericConstraints(
    paramName: string,
    config: Record<string, JsonValue>,
    toolName: string,
  ): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    // Missing minimum
    if (config.minimum === undefined && config.exclusiveMinimum === undefined) {
      findings.push({
        severity: "low",
        message: t("finding_missing_constraints_minimum", {
          param: paramName,
          tool: toolName,
        }),
        component: `tool:${toolName}`,
        ruleCode: this.code,
        location: { type: "tool", name: toolName, parameter: paramName },
        evidence: {
          parameterType: config.type as string,
          missingConstraint: "minimum",
        },
        remediation: t("remediation_missing_constraints_add_bounds"),
      });
    }

    // Missing maximum
    if (config.maximum === undefined && config.exclusiveMaximum === undefined) {
      findings.push({
        severity: "low",
        message: t("finding_missing_constraints_maximum", {
          param: paramName,
          tool: toolName,
        }),
        component: `tool:${toolName}`,
        ruleCode: this.code,
        location: { type: "tool", name: toolName, parameter: paramName },
        evidence: {
          parameterType: config.type as string,
          missingConstraint: "maximum",
          risk: t("risk_missing_constraints_overflow"),
        },
        remediation: t("remediation_missing_constraints_add_bounds"),
      });
    }

    return findings;
  }

  private checkArrayConstraints(
    paramName: string,
    config: Record<string, JsonValue>,
    toolName: string,
  ): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    // Missing maxItems
    if (!config.maxItems) {
      findings.push({
        severity: "low",
        message: t("finding_missing_constraints_maxitems", {
          param: paramName,
          tool: toolName,
        }),
        component: `tool:${toolName}`,
        ruleCode: this.code,
        location: { type: "tool", name: toolName, parameter: paramName },
        evidence: {
          parameterType: "array",
          missingConstraint: "maxItems",
          risk: t("risk_missing_constraints_memory"),
        },
        remediation: t("remediation_missing_constraints_add_maxitems", {
          recommended: this.RECOMMENDED_MAX_ARRAY_ITEMS,
        }),
      });
    }

    return findings;
  }

  private checkObjectConstraints(
    paramName: string,
    config: Record<string, JsonValue>,
    toolName: string,
  ): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    // Missing maxProperties
    if (!config.maxProperties && !config.properties) {
      findings.push({
        severity: "low",
        message: t("finding_missing_constraints_maxprops", {
          param: paramName,
          tool: toolName,
        }),
        component: `tool:${toolName}`,
        ruleCode: this.code,
        location: { type: "tool", name: toolName, parameter: paramName },
        evidence: {
          parameterType: "object",
          missingConstraint: "maxProperties or properties definition",
        },
        remediation: t("remediation_missing_constraints_define_schema"),
      });
    }

    return findings;
  }
}
