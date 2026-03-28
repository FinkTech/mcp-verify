/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Sensitive Data in Tool Descriptions Rule (SEC-018)
 *
 * Detects sensitive information (API keys, credentials, internal paths, emails)
 * hardcoded or leaked in tool descriptions, parameter descriptions, or examples.
 *
 * Validates:
 * - API keys, access tokens, and secrets in descriptions
 * - Hardcoded credentials or passwords in examples
 * - Internal server paths and configuration details
 * - Email addresses and phone numbers
 * - Database connection strings
 *
 * Attack vectors:
 * - Information disclosure to LLM and end users
 * - Credential theft from example values
 * - Internal architecture exposure
 * - Social engineering with leaked contact information
 *
 * @module libs/core/domain/security/rules/secrets-in-descriptions.rule
 */

import { t } from '@mcp-verify/shared';
import { ISecurityRule } from '../rule.interface';
import type { DiscoveryResult, SecurityFinding } from '../../mcp-server/entities/validation.types';
import type { McpTool, JsonValue } from '../../shared/common.types';

export class SecretsInDescriptionsRule implements ISecurityRule {
  readonly code = 'SEC-018';
  get name() { return t('sec_secrets_desc_name'); }
  get description() { return t('sec_secrets_desc_desc'); }
  readonly helpUri = 'https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure';
  readonly tags = ['CWE-200', 'CWE-522', 'OWASP-A01:2021', 'Information Disclosure'];

  /**
   * Patterns for detecting sensitive data in text
   */
  private readonly SENSITIVE_PATTERNS = {
    // API Keys and Tokens
    apiKey: {
      pattern: /(?:api[_-]?key|apikey|api[_-]?token)[:\s=]+['"]?([a-zA-Z0-9_\-]{20,})/gi,
      severity: 'critical' as const,
      type: 'API Key'
    },
    jwt: {
      pattern: /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g,
      severity: 'critical' as const,
      type: 'JWT Token'
    },
    awsKey: {
      pattern: /AKIA[0-9A-Z]{16}/g,
      severity: 'critical' as const,
      type: 'AWS Access Key'
    },
    genericSecret: {
      pattern: /(?:secret|password|passwd|pwd)[:\s=]+['"]?([^\s'"]{8,})/gi,
      severity: 'critical' as const,
      type: 'Secret/Password'
    },

    // Database Connections
    connectionString: {
      pattern: /(?:mongodb|postgres|mysql):\/\/[^:\s]+:[^@\s]+@[^\s]+/gi,
      severity: 'critical' as const,
      type: 'Database Connection String'
    },

    // OAuth and Bearer Tokens
    bearerToken: {
      pattern: /bearer\s+[a-zA-Z0-9_\-\.]{20,}/gi,
      severity: 'critical' as const,
      type: 'Bearer Token'
    },

    // Email Addresses
    email: {
      pattern: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g,
      severity: 'medium' as const,
      type: 'Email Address'
    },

    // Internal Paths
    internalPath: {
      pattern: /(?:\/home\/|\/var\/|\/etc\/|C:\\Users\\|C:\\Program Files\\)[^\s'"]{10,}/gi,
      severity: 'medium' as const,
      type: 'Internal File Path'
    },

    // IP Addresses (private ranges)
    privateIP: {
      pattern: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g,
      severity: 'low' as const,
      type: 'Private IP Address'
    },

    // Phone Numbers
    phoneNumber: {
      pattern: /\b\+?[\d\s\-()]{10,}\b/g,
      severity: 'low' as const,
      type: 'Phone Number'
    }
  };

  /**
   * Keywords that indicate sensitive information might be present
   */
  private readonly SENSITIVE_KEYWORDS = [
    'api key', 'api_key', 'apikey',
    'secret', 'password', 'passwd', 'pwd',
    'token', 'access_token', 'auth_token',
    'credentials', 'credential',
    'private key', 'private_key',
    'connection string', 'database url'
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

    // Check tool description
    if (tool.description) {
      findings.push(...this.scanText(
        tool.description,
        `tool:${tool.name}`,
        'tool description',
        tool.name
      ));
    }

    // Check parameter descriptions
    if (tool.inputSchema?.properties) {
      for (const [paramName, paramConfig] of Object.entries(tool.inputSchema.properties)) {
        const config = paramConfig as Record<string, JsonValue>;

        // Check parameter description
        if (config.description && typeof config.description === 'string') {
          findings.push(...this.scanText(
            config.description,
            `tool:${tool.name}`,
            `parameter '${paramName}' description`,
            tool.name,
            paramName
          ));
        }

        // Check enum values (might contain example secrets)
        if (config.enum && Array.isArray(config.enum)) {
          const enumText = config.enum.join(' ');
          findings.push(...this.scanText(
            enumText,
            `tool:${tool.name}`,
            `parameter '${paramName}' enum values`,
            tool.name,
            paramName
          ));
        }

        // Check default values
        if (config.default && typeof config.default === 'string') {
          findings.push(...this.scanText(
            config.default,
            `tool:${tool.name}`,
            `parameter '${paramName}' default value`,
            tool.name,
            paramName
          ));
        }

        // Check examples
        if (config.examples && Array.isArray(config.examples)) {
          const examplesText = config.examples.join(' ');
          findings.push(...this.scanText(
            examplesText,
            `tool:${tool.name}`,
            `parameter '${paramName}' examples`,
            tool.name,
            paramName
          ));
        }
      }
    }

    return findings;
  }

  private scanText(
    text: string,
    component: string,
    location: string,
    toolName: string,
    paramName?: string
  ): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    // Check each sensitive pattern
    for (const [patternName, { pattern, severity, type }] of Object.entries(this.SENSITIVE_PATTERNS)) {
      const matches = text.match(pattern);

      if (matches && matches.length > 0) {
        // Redact the actual sensitive data in the finding
        const redactedMatches = matches.map(match => this.redactSensitiveData(match, type));

        findings.push({
          severity,
          message: t('finding_secrets_desc_detected', {
            type,
            location,
            tool: toolName
          }),
          component,
          ruleCode: this.code,
          location: {
            type: 'tool',
            name: toolName,
            parameter: paramName
          },
          evidence: {
            sensitiveType: type,
            location,
            matchCount: matches.length,
            redactedExamples: redactedMatches.slice(0, 2), // Show max 2 examples
            risk: t('risk_secrets_desc_disclosure')
          },
          remediation: t('remediation_secrets_desc_remove', { type })
        });
      }
    }

    // Check for sensitive keywords (informational)
    const textLower = text.toLowerCase();
    const foundKeywords = this.SENSITIVE_KEYWORDS.filter(kw => textLower.includes(kw));

    if (foundKeywords.length > 0 && findings.length === 0) {
      // Keywords present but no pattern match - still worth warning
      findings.push({
        severity: 'low',
        message: t('finding_secrets_desc_keywords', {
          location,
          tool: toolName
        }),
        component,
        ruleCode: this.code,
        location: {
          type: 'tool',
          name: toolName,
          parameter: paramName
        },
        evidence: {
          keywords: foundKeywords,
          location
        },
        remediation: t('remediation_secrets_desc_review')
      });
    }

    return findings;
  }

  private redactSensitiveData(match: string, type: string): string {
    // Show first and last few characters, redact middle
    if (match.length <= 8) {
      return '***';
    }

    const visibleChars = 3;
    const prefix = match.substring(0, visibleChars);
    const suffix = match.substring(match.length - visibleChars);

    return `${prefix}***${suffix} (${type})`;
  }
}
