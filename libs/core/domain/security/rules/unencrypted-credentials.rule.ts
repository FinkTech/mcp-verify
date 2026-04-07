/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Unencrypted Credential Storage Detection Rule (SEC-021)
 *
 * Detects tools that store, save, or persist credentials, passwords, or
 * sensitive authentication data without explicit mention of encryption,
 * hashing, or secure storage mechanisms.
 *
 * Validates:
 * - Tools that store credentials without encryption indicators
 * - Password persistence without hashing mentions
 * - Token storage without secure storage mechanisms
 * - Configuration saving with sensitive data
 *
 * Attack vectors:
 * - Plaintext credential storage on disk
 * - Database compromise exposing unencrypted passwords
 * - Configuration file leaks with cleartext secrets
 * - Memory dumps revealing stored credentials
 *
 * @module libs/core/domain/security/rules/unencrypted-credentials.rule
 */

import { t } from "@mcp-verify/shared";
import { ISecurityRule } from "../rule.interface";
import type {
  DiscoveryResult,
  SecurityFinding,
} from "../../mcp-server/entities/validation.types";
import type { McpTool } from "../../shared/common.types";

export class UnencryptedCredentialsRule implements ISecurityRule {
  readonly code = "SEC-021";
  get name() {
    return t("sec_unencrypted_creds_name");
  }
  get description() {
    return t("sec_unencrypted_creds_desc");
  }
  readonly helpUri =
    "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure";
  readonly tags = ["CWE-256", "CWE-312", "OWASP-A02:2021", "Cleartext Storage"];

  /**
   * Keywords indicating storage/persistence operations
   */
  private readonly STORAGE_KEYWORDS = [
    "store",
    "save",
    "persist",
    "write",
    "cache",
    "log",
    "record",
    "archive",
    "backup",
    "export",
    "dump",
  ];

  /**
   * Keywords indicating sensitive credential data
   */
  private readonly CREDENTIAL_KEYWORDS = [
    "password",
    "passwd",
    "pwd",
    "credential",
    "credentials",
    "secret",
    "api key",
    "api_key",
    "apikey",
    "token",
    "access_token",
    "auth_token",
    "private key",
    "private_key",
    "auth",
    "authentication",
  ];

  /**
   * Keywords indicating secure storage (mitigating factors)
   */
  private readonly SECURITY_KEYWORDS = [
    "encrypt",
    "encrypted",
    "encryption",
    "hash",
    "hashed",
    "hashing",
    "bcrypt",
    "scrypt",
    "argon2",
    "secure",
    "secured",
    "securely",
    "keychain",
    "vault",
    "keystore",
    "aes",
    "rsa",
    "cipher",
    "protected",
    "safeguard",
  ];

  /**
   * Insecure storage methods
   */
  private readonly INSECURE_STORAGE_METHODS = [
    "plaintext",
    "plain text",
    "cleartext",
    "clear text",
    "unencrypted",
    "raw",
    "base64", // base64 is encoding, not encryption
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

    const text = `${tool.name} ${tool.description || ""}`.toLowerCase();

    // Check if tool involves storage
    const hasStorageKeyword = this.STORAGE_KEYWORDS.some((kw) =>
      text.includes(kw),
    );

    if (!hasStorageKeyword) {
      return findings; // Tool doesn't deal with storage
    }

    // Check if tool deals with credentials
    const credentialKeywords = this.CREDENTIAL_KEYWORDS.filter((kw) =>
      text.includes(kw),
    );

    if (credentialKeywords.length === 0) {
      return findings; // Tool doesn't deal with credentials
    }

    // Check if security measures are mentioned
    const hasSecurityKeyword = this.SECURITY_KEYWORDS.some((kw) =>
      text.includes(kw),
    );

    // Check for explicit insecure storage mentions
    const insecureStorageMethods = this.INSECURE_STORAGE_METHODS.filter((kw) =>
      text.includes(kw),
    );

    // Critical: Explicit mention of insecure storage
    if (insecureStorageMethods.length > 0) {
      findings.push({
        severity: "critical",
        message: t("finding_unencrypted_creds_explicit", {
          tool: tool.name,
          methods: insecureStorageMethods.join(", "),
        }),
        component: `tool:${tool.name}`,
        ruleCode: this.code,
        location: { type: "tool", name: tool.name },
        evidence: {
          insecureMethods: insecureStorageMethods,
          credentialTypes: credentialKeywords,
          risk: t("risk_unencrypted_creds_plaintext"),
        },
        remediation: t("remediation_unencrypted_creds_encrypt"),
      });
      return findings; // No need to check further
    }

    // High: Storage of credentials without security mentions
    if (!hasSecurityKeyword) {
      findings.push({
        severity: "high",
        message: t("finding_unencrypted_creds_no_security", {
          tool: tool.name,
          credTypes: credentialKeywords.slice(0, 2).join(", "),
        }),
        component: `tool:${tool.name}`,
        ruleCode: this.code,
        location: { type: "tool", name: tool.name },
        evidence: {
          credentialTypes: credentialKeywords,
          storageDetected: true,
          securityMentioned: false,
          risk: t("risk_unencrypted_creds_exposure"),
        },
        remediation: t("remediation_unencrypted_creds_implement"),
      });
    }

    // Medium: Uses base64 (which is not encryption)
    if (text.includes("base64") && credentialKeywords.length > 0) {
      findings.push({
        severity: "medium",
        message: t("finding_unencrypted_creds_base64", { tool: tool.name }),
        component: `tool:${tool.name}`,
        ruleCode: this.code,
        location: { type: "tool", name: tool.name },
        evidence: {
          encoding: "base64",
          credentialTypes: credentialKeywords,
          risk: t("risk_unencrypted_creds_encoding_not_encryption"),
        },
        remediation: t("remediation_unencrypted_creds_real_encryption"),
      });
    }

    // Check parameter names for credential storage
    if (tool.inputSchema?.properties) {
      for (const [paramName, paramConfig] of Object.entries(
        tool.inputSchema.properties,
      )) {
        const paramLower = paramName.toLowerCase();
        const config = paramConfig as Record<string, string | undefined>;

        // Parameter suggests credential storage
        const isCredentialParam = this.CREDENTIAL_KEYWORDS.some((kw) =>
          paramLower.includes(kw),
        );
        const isStorageParam = this.STORAGE_KEYWORDS.some((kw) =>
          paramLower.includes(kw),
        );

        if (isCredentialParam && isStorageParam) {
          // Check parameter description for security mentions
          const paramDesc = (config.description || "").toLowerCase();
          const hasParamSecurity = this.SECURITY_KEYWORDS.some((kw) =>
            paramDesc.includes(kw),
          );

          if (!hasParamSecurity) {
            findings.push({
              severity: "high",
              message: t("finding_unencrypted_creds_param", {
                param: paramName,
                tool: tool.name,
              }),
              component: `tool:${tool.name}`,
              ruleCode: this.code,
              location: { type: "tool", name: tool.name, parameter: paramName },
              evidence: {
                parameter: paramName,
                risk: t("risk_unencrypted_creds_param_storage"),
              },
              remediation: t("remediation_unencrypted_creds_param_secure"),
            });
          }
        }
      }
    }

    return findings;
  }
}
