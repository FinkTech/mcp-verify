/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SQL Injection Detection Rule (SEC-003)
 *
 * Detects potential SQL injection vulnerabilities in MCP server tools.
 * SQL injection allows attackers to manipulate database queries, potentially
 * leading to data theft, modification, or deletion.
 *
 * Validates:
 * - Tools that appear to execute SQL queries based on naming conventions
 * - Input parameters that lack strict validation for SQL metacharacters
 * - Absence of prepared statements or parameterized queries in descriptions
 *
 * @module libs/core/domain/security/rules/sql-injection.rule
 */

import { t, compileRegexSafe, isSafePattern } from "@mcp-verify/shared";
import { ISecurityRule } from "../rule.interface";
import type {
  DiscoveryResult,
  SecurityFinding,
} from "../../mcp-server/entities/validation.types";
import type { McpTool, JsonValue } from "../../shared/common.types";

export class SQLInjectionRule implements ISecurityRule {
  readonly code = "SEC-003";
  get name() {
    return t("sec_sql_injection_name");
  }
  get description() {
    return t("sec_sql_injection_desc");
  }
  readonly helpUri = "https://owasp.org/www-community/attacks/SQL_Injection";

  /**
   * SQL metacharacters commonly used in injection attacks.
   */
  private readonly SQL_METACHARACTERS = [
    "'",
    '"',
    ";",
    "--",
    "/*",
    "*/",
    "xp_",
    "sp_",
    "UNION",
    "SELECT",
    "DROP",
    "INSERT",
    "UPDATE",
    "DELETE",
  ];

  /**
   * Keywords that strongly suggest a tool executes SQL queries.
   */
  private readonly SQL_KEYWORDS = [
    "sql",
    "query",
    "database",
    "db",
    "mysql",
    "postgres",
    "postgresql",
    "sqlite",
    "mssql",
    "oracle",
    "select",
    "insert",
    "update",
    "delete",
    "execute",
    "exec",
    "stored_procedure",
    "sp_",
    "table",
    "column",
  ];

  /**
   * Positive indicators that suggest the tool uses safe practices.
   */
  private readonly SAFE_INDICATORS = [
    "prepared statement",
    "parameterized",
    "placeholder",
    "bind parameter",
    "orm",
    "sequelize",
    "typeorm",
    "prisma",
    "knex",
    "drizzle",
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
    const isSQLTool = this.isSQLTool(tool.name, tool.description);

    if (!isSQLTool) {
      return findings;
    }

    // Check if tool mentions safe practices
    const hasSafeIndicators = this.hasSafePractices(tool.description);

    if (!tool.inputSchema?.properties) {
      // SQL tool with no input schema is unusual but might be safe (predefined queries)
      if (isSQLTool && !hasSafeIndicators) {
        findings.push({
          severity: "medium",
          message: t("finding_sql_no_schema", { tool: tool.name }),
          component: `tool:${tool.name}`,
          ruleCode: this.code,
          evidence: {
            toolName: tool.name,
            description: tool.description || null,
            reason: t("no_input_parameters_defined"),
          },
          remediation: t("if_the_tool_accepts_any_input_define_a_strict_inpu"),
        });
      }
      return findings;
    }

    // Analyze each parameter
    for (const [paramName, paramConfig] of Object.entries(
      tool.inputSchema.properties,
    )) {
      const config = paramConfig as Record<string, JsonValue>;

      // Parameters that might be used in SQL queries
      const isQueryParam = this.isQueryParameter(paramName, config);

      if (isQueryParam && config.type === "string") {
        // CRITICAL: No validation pattern
        if (!config.pattern) {
          findings.push({
            severity: hasSafeIndicators ? "medium" : "critical",
            message: t("finding_sql_potential", {
              param: paramName,
              tool: tool.name,
            }),
            component: `tool:${tool.name}`,
            ruleCode: this.code,
            location: { type: "tool", name: tool.name, parameter: paramName },
            evidence: {
              risk: t("unsanitized_input_in_sql_query_context"),
              parameter: paramName,
              hasSafePractices: hasSafeIndicators,
            },
            remediation: hasSafeIndicators
              ? t("even_with_prepared_statements_implement_input_vali")
              : t("use_prepared_statements_with_placeholders_and_impl"),
          });
        } else {
          // Check if pattern allows SQL metacharacters
          const weakResult =
            typeof config.pattern === "string"
              ? this.isWeakPattern(config.pattern)
              : null;
          if (weakResult && weakResult.isWeak) {
            findings.push({
              severity: "critical",
              message: t("finding_sql_potential", {
                param: paramName,
                tool: tool.name,
              }), // Use consistent localized key
              component: `tool:${tool.name}`,
              ruleCode: this.code,
              location: { type: "tool", name: tool.name, parameter: paramName },
              evidence: {
                pattern: config.pattern,
                allowedSQLChars: weakResult.allowedChars,
                hasSafePractices: hasSafeIndicators,
              },
              remediation: t(
                "strengthen_the_regex_to_strictly_exclude_sql_metac",
              ),
            });
          }
        }
      }

      // Check for numeric parameters without type enforcement
      if (
        isQueryParam &&
        (!config.type || config.type === "string") &&
        !config.pattern
      ) {
        if (
          paramName.toLowerCase().includes("id") ||
          paramName.toLowerCase().includes("limit") ||
          paramName.toLowerCase().includes("offset")
        ) {
          findings.push({
            severity: "medium",
            message: t("finding_sql_type_mismatch", { param: paramName }),
            component: `tool:${tool.name}`,
            ruleCode: this.code,
            location: { type: "tool", name: tool.name, parameter: paramName },
            evidence: {
              currentType: config.type || "any",
              expectedType: "integer or number",
            },
            remediation: t(
              "define_a_strict_input_schema_with_expected_types_i",
            ),
          });
        }
      }
    }

    // Warn if SQL tool doesn't mention safe practices
    if (!hasSafeIndicators && findings.some((f) => f.severity === "critical")) {
      findings.push({
        severity: "high",
        message: t("finding_sql_no_prepared", { tool: tool.name }),
        component: `tool:${tool.name}`,
        ruleCode: this.code,
        evidence: {
          missingIndicators: this.SAFE_INDICATORS.join(", "),
        },
        remediation: t("update_tool_description_to_explicitly_state_use_of"),
      });
    }

    return findings;
  }

  private isSQLTool(name: string, description?: string): boolean {
    const text = `${name} ${description || ""}`.toLowerCase();
    return this.SQL_KEYWORDS.some((kw) => text.includes(kw));
  }

  private hasSafePractices(description?: string): boolean {
    if (!description) return false;
    const text = description.toLowerCase();
    return this.SAFE_INDICATORS.some((indicator) => text.includes(indicator));
  }

  private isQueryParameter(
    name: string,
    config: Record<string, JsonValue>,
  ): boolean {
    const queryParamNames = [
      "query",
      "sql",
      "where",
      "condition",
      "filter",
      "search",
      "table",
      "column",
      "field",
      "order",
      "sort",
      "limit",
      "offset",
      "id",
      "username",
      "email",
    ];

    const nameLower = name.toLowerCase();
    const descLower = (
      typeof config.description === "string" ? config.description : ""
    ).toLowerCase();

    return queryParamNames.some(
      (qp) => nameLower.includes(qp) || descLower.includes(qp),
    );
  }

  private isWeakPattern(pattern: string): {
    isWeak: boolean;
    allowedChars: string[];
  } {
    // ReDoS Protection: Reject extremely long patterns
    if (pattern.length > 1000) {
      return { isWeak: true, allowedChars: [t("evidence_redos_too_long")] };
    }

    // ReDoS Protection: Detect dangerous regex patterns
    const redosPatterns = [/(\w+\*)+/, /(\w+)+\1/, /(\w\|)+/];
    for (const redosPattern of redosPatterns) {
      if (redosPattern.test(pattern)) {
        return { isWeak: true, allowedChars: [t("evidence_redos_pattern")] };
      }
    }

    try {
      // ReDoS Protection: Check pattern safety before compilation
      if (!isSafePattern(pattern)) {
        // Pattern contains dangerous constructs (nested quantifiers, etc.)
        return { isWeak: true, allowedChars: [t("evidence_redos_vulnerable")] };
      }

      // Compile regex with timeout protection
      const { regex, timedOut, error } = compileRegexSafe(pattern, undefined, {
        timeout: 100,
      });

      if (timedOut || !regex) {
        // Regex compilation or test took too long - mark as weak
        return { isWeak: true, allowedChars: [t("evidence_redos_timeout")] };
      }

      const allowedChars: string[] = [];

      // Test dangerous SQL characters
      const dangerousChars = ["'", '"', ";", "--", "/*"];

      for (const char of dangerousChars) {
        if (regex.test(`test${char}test`) || regex.test(char)) {
          allowedChars.push(char);
        }
      }

      // Test SQL keywords (simplified check)
      const sqlKeywords = ["SELECT", "UNION", "DROP", "INSERT"];
      for (const keyword of sqlKeywords) {
        if (regex.test(keyword)) {
          allowedChars.push(`keyword:${keyword}`);
        }
      }

      return {
        isWeak: allowedChars.length > 0,
        allowedChars,
      };
    } catch (e) {
      return { isWeak: false, allowedChars: [] };
    }
  }
}
