/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Insecure URI Scheme Detection Rule (SEC-016)
 *
 * Detects use of dangerous or unencrypted URI schemes in MCP resources that
 * could expose data to Man-in-the-Middle attacks or insecure protocols.
 *
 * Validates:
 * - Resources using insecure schemes (http://, ftp://, gopher://)
 * - Deprecated or dangerous protocols (telnet://, ldap://)
 * - Missing encryption in data transport
 * - Localhost resources with insecure schemes
 *
 * Attack vectors:
 * - Man-in-the-Middle interception of resource data
 * - Credential theft over unencrypted connections
 * - Data tampering during resource fetching
 * - Protocol downgrade attacks
 *
 * @module libs/core/domain/security/rules/insecure-uri-scheme.rule
 */

import { t } from "@mcp-verify/shared";
import { ISecurityRule } from "../rule.interface";
import type {
  DiscoveryResult,
  SecurityFinding,
} from "../../mcp-server/entities/validation.types";
import type { McpResource } from "../../shared/common.types";

export class InsecureURISchemeRule implements ISecurityRule {
  readonly code = "SEC-016";
  get name() {
    return t("sec_insecure_uri_name");
  }
  get description() {
    return t("sec_insecure_uri_desc");
  }
  readonly helpUri =
    "https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration";
  readonly tags = [
    "CWE-319",
    "CWE-757",
    "OWASP-A02:2021",
    "Cleartext Transmission",
  ];

  /**
   * Secure URI schemes that are acceptable
   */
  private readonly SECURE_SCHEMES = [
    "https:", // Encrypted HTTP
    "mcp:", // MCP protocol
    "file:", // Local file system (with caution)
    "data:", // Data URIs (embedded content)
  ];

  /**
   * Insecure schemes with severity levels
   */
  private readonly INSECURE_SCHEMES = {
    "http:": {
      severity: "high" as const,
      risk: "Man-in-the-Middle attack, unencrypted data transmission",
    },
    "ftp:": {
      severity: "critical" as const,
      risk: "Credentials and data sent in plaintext",
    },
    "telnet:": {
      severity: "critical" as const,
      risk: "Completely unencrypted, legacy protocol",
    },
    "gopher:": {
      severity: "high" as const,
      risk: "Deprecated protocol with security vulnerabilities",
    },
    "ldap:": {
      severity: "high" as const,
      risk: "Unencrypted LDAP, use ldaps:// instead",
    },
    "ws:": {
      severity: "high" as const,
      risk: "Unencrypted WebSocket, use wss:// instead",
    },
  };

  /**
   * Localhost patterns that may reduce severity
   */
  private readonly LOCALHOST_PATTERNS = [
    /^https?:\/\/localhost(:\d+)?/i,
    /^https?:\/\/127\.0\.0\.1(:\d+)?/,
    /^https?:\/\/\[::1\](:\d+)?/,
  ];

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (discovery.resources) {
      for (const resource of discovery.resources) {
        findings.push(...this.analyzeResource(resource));
      }
    }

    return findings;
  }

  private analyzeResource(resource: McpResource): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    // Parse URI to extract scheme
    let scheme: string;
    let isLocalhost = false;

    try {
      const url = new URL(resource.uri);
      scheme = url.protocol;

      // Check if localhost
      isLocalhost = this.LOCALHOST_PATTERNS.some((pattern) =>
        pattern.test(resource.uri),
      );
    } catch (error) {
      // Invalid URI format
      findings.push({
        severity: "medium",
        message: t("finding_insecure_uri_malformed", {
          resource: resource.name,
        }),
        component: `resource:${resource.name}`,
        ruleCode: this.code,
        evidence: {
          uri: resource.uri,
          error: "Invalid URI format",
        },
        remediation: t("remediation_insecure_uri_fix_format"),
      });
      return findings;
    }

    // Check if scheme is insecure
    if (scheme in this.INSECURE_SCHEMES) {
      const { severity, risk } =
        this.INSECURE_SCHEMES[scheme as keyof typeof this.INSECURE_SCHEMES];

      // Reduce severity if localhost (development environment)
      const finalSeverity =
        isLocalhost && severity === "high" ? "medium" : severity;

      findings.push({
        severity: finalSeverity,
        message: t("finding_insecure_uri_scheme", {
          resource: resource.name,
          scheme: scheme.replace(":", ""),
        }),
        component: `resource:${resource.name}`,
        ruleCode: this.code,
        location: { type: "resource", name: resource.name },
        evidence: {
          uri: resource.uri,
          scheme,
          risk,
          isLocalhost,
        },
        remediation: t("remediation_insecure_uri_use_secure", {
          scheme: this.getSecureAlternative(scheme),
        }),
      });
    }

    // Warn about file:// scheme (potential path traversal)
    if (scheme === "file:") {
      findings.push({
        severity: "medium",
        message: t("finding_insecure_uri_file_scheme", {
          resource: resource.name,
        }),
        component: `resource:${resource.name}`,
        ruleCode: this.code,
        location: { type: "resource", name: resource.name },
        evidence: {
          uri: resource.uri,
          risk: t("risk_insecure_uri_file_traversal"),
        },
        remediation: t("remediation_insecure_uri_file_validate"),
      });
    }

    // Check for credentials in URI
    if (this.hasCredentialsInURI(resource.uri)) {
      findings.push({
        severity: "critical",
        message: t("finding_insecure_uri_credentials", {
          resource: resource.name,
        }),
        component: `resource:${resource.name}`,
        ruleCode: this.code,
        location: { type: "resource", name: resource.name },
        evidence: {
          uri: this.redactCredentials(resource.uri),
          risk: t("risk_insecure_uri_exposed_creds"),
        },
        remediation: t("remediation_insecure_uri_remove_creds"),
      });
    }

    return findings;
  }

  private getSecureAlternative(insecureScheme: string): string {
    const alternatives: Record<string, string> = {
      "http:": "https://",
      "ftp:": "sftp:// or https://",
      "telnet:": "ssh://",
      "ldap:": "ldaps://",
      "ws:": "wss://",
    };

    return alternatives[insecureScheme] || "https://";
  }

  private hasCredentialsInURI(uri: string): boolean {
    // Check for user:pass@ pattern
    return /@/.test(uri) && /\/\/[^@]+:[^@]+@/.test(uri);
  }

  private redactCredentials(uri: string): string {
    // Redact credentials from URI for evidence
    return uri.replace(/\/\/([^:]+):([^@]+)@/, "//***:***@");
  }
}
