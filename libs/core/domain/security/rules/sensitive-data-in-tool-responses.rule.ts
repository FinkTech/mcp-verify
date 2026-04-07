/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SEC-026: Sensitive Data Exposure in Tool Responses (LLM06)
 *
 * Block: A (OWASP LLM Top 10 in MCP Context)
 * Severity: High
 * Type: Static + Fuzzer
 *
 * Detects tools that may leak PII, credentials, or sensitive data in responses
 * without proper redaction or access control.
 *
 * Detection:
 * Static:
 * - Tools with "get_user", "fetch_profile", "list_credentials" patterns
 * - Missing output schema constraints (no contentEncoding, no enum)
 * - Description mentions PII keywords without "redacted" or "filtered"
 *
 * Fuzzer:
 * - Invoke tools and scan responses for PII patterns
 *
 * References:
 * - OWASP LLM Top 10 2025 - LLM06: Sensitive Information Disclosure
 * - GDPR Art. 5 - Data minimization
 * - CWE-359: Exposure of Private Information
 */

import type { ISecurityRule } from "../rule.interface";
import type {
  DiscoveryResult,
  SecurityFinding,
} from "../../mcp-server/entities/validation.types";
import type { McpTool } from "../../shared/common.types";
import { t } from "@mcp-verify/shared";

export class SensitiveDataInToolResponsesRule implements ISecurityRule {
  code = "SEC-026";
  name = "Sensitive Data Exposure in Tool Responses";
  severity: "high" = "high";

  private readonly PII_KEYWORDS = [
    "email",
    "phone",
    "ssn",
    "social_security",
    "passport",
    "credit_card",
    "card_number",
    "cvv",
    "account_number",
    "password",
    "secret",
    "token",
    "api_key",
    "private_key",
    "address",
    "birthday",
    "birth_date",
    "dob",
    "gender",
    "race",
    "ethnicity",
    "religion",
    "medical",
    "health",
  ];

  private readonly REDACTION_KEYWORDS = [
    "redacted",
    "filtered",
    "sanitized",
    "masked",
    "anonymized",
    "encrypted",
    "hashed",
    "obfuscated",
    "protected",
    "secure",
  ];

  private readonly SENSITIVE_TOOL_PATTERNS = [
    /get.*user/i,
    /fetch.*profile/i,
    /retrieve.*account/i,
    /list.*credentials?/i,
    /show.*secrets?/i,
    /get.*password/i,
    /fetch.*token/i,
    /retrieve.*keys?/i,
    /list.*api.*key/i,
  ];

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (!discovery.tools || discovery.tools.length === 0) {
      return findings;
    }

    for (const tool of discovery.tools) {
      const isSensitiveTool = this.isSensitiveTool(tool);

      if (isSensitiveTool) {
        const hasRedactionMention = this.mentionsRedaction(tool);
        const hasOutputConstraints = this.hasOutputConstraints(tool);

        if (!hasRedactionMention && !hasOutputConstraints) {
          findings.push({
            severity: this.severity,
            message: t("sec_026_sensitive_exposure", {
              toolName: tool.name,
            }),
            component: `tool:${tool.name}`,
            ruleCode: this.code,
            remediation: t("sec_026_recommendation"),
            references: [
              "OWASP LLM Top 10 2025 - LLM06: Sensitive Information Disclosure",
              "GDPR Art. 5 - Data minimization",
              "CWE-359: Exposure of Private Information",
            ],
          });
        }
      }
    }

    return findings;
  }

  private isSensitiveTool(tool: McpTool): boolean {
    // Check name pattern
    const nameMatches = this.SENSITIVE_TOOL_PATTERNS.some((pattern) =>
      pattern.test(tool.name),
    );
    if (nameMatches) return true;

    // Check description for PII keywords
    if (tool.description) {
      const descLower = tool.description.toLowerCase();
      const hasPII = this.PII_KEYWORDS.some((keyword) =>
        descLower.includes(keyword),
      );
      if (hasPII) return true;
    }

    // Check inputSchema for PII-related params
    if (tool.inputSchema?.properties) {
      for (const propName of Object.keys(tool.inputSchema.properties)) {
        const propLower = propName.toLowerCase();
        const hasPII = this.PII_KEYWORDS.some((keyword) =>
          propLower.includes(keyword),
        );
        if (hasPII) return true;
      }
    }

    return false;
  }

  private mentionsRedaction(tool: McpTool): boolean {
    if (!tool.description) return false;

    const descLower = tool.description.toLowerCase();
    return this.REDACTION_KEYWORDS.some((keyword) =>
      descLower.includes(keyword),
    );
  }

  private hasOutputConstraints(tool: McpTool): boolean {
    // Check if tool declares output schema constraints
    // This is not standard in MCP 2024-11-05, but some servers may extend it
    const toolExt = tool as { outputSchema?: { properties?: unknown } };
    if (toolExt.outputSchema?.properties) {
      return true;
    }

    // Check if description mentions output filtering
    if (tool.description) {
      const descLower = tool.description.toLowerCase();
      return (
        descLower.includes("output") &&
        this.REDACTION_KEYWORDS.some((kw) => descLower.includes(kw))
      );
    }

    return false;
  }
}
