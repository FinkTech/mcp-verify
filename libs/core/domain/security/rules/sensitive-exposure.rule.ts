/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Sensitive Data Exposure Detection Rule (SEC-009)
 *
 * Detects potential exposure of sensitive data in MCP server tools.
 * Sensitive data includes PII, credentials, financial information, and
 * health data that could lead to privacy violations or identity theft.
 *
 * Validates:
 * - Parameters handling sensitive data without encryption
 * - Missing data protection mechanisms
 * - Potential logging of sensitive information
 * - Transmission of unencrypted sensitive data
 *
 * @module libs/core/domain/security/rules/sensitive-exposure.rule
 */

import { t } from '@mcp-verify/shared';
import { ISecurityRule } from '../rule.interface';
import type { DiscoveryResult, SecurityFinding } from '../../mcp-server/entities/validation.types';
import type { McpTool, JsonValue } from '../../shared/common.types';

export class SensitiveDataExposureRule implements ISecurityRule {
  readonly code = 'SEC-009';
  get name() { return t('sec_sensitive_exposure_name'); }
  get description() { return t('sec_sensitive_exposure_desc'); }
  readonly helpUri = 'https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure';

  /**
   * Sensitive data indicators in parameter names.
   */
  private readonly SENSITIVE_KEYWORDS = {
    pii: ['ssn', 'social_security', 'passport', 'driver_license', 'national_id'],
    financial: ['credit_card', 'creditcard', 'card_number', 'cvv', 'cvc', 'bank_account', 'routing_number', 'iban'],
    credentials: ['password', 'passwd', 'api_key', 'apikey', 'secret', 'token', 'private_key', 'privatekey'],
    health: ['medical', 'health', 'diagnosis', 'prescription', 'patient', 'hipaa'],
    personal: ['birthdate', 'birth_date', 'dob', 'age', 'gender', 'race', 'religion'],
    biometric: ['fingerprint', 'facial', 'iris', 'biometric', 'dna']
  };

  /**
   * Data protection indicators.
   */
  private readonly PROTECTION_INDICATORS = [
    'encrypted', 'encryption', 'tls', 'ssl', 'https',
    'masked', 'redacted', 'hashed', 'tokenized',
    'secure storage', 'vault', 'kms', 'key management'
  ];

  /**
   * PII patterns for validation.
   */
  private readonly PII_PATTERNS = {
    ssn: /^\d{3}-\d{2}-\d{4}$/,
    creditCard: /^\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}$/,
    email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
    phone: /^\+?1?\d{10,15}$/
  };

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

    const hasProtection = this.hasDataProtection(tool.description);

    // Analyze each parameter
    for (const [paramName, paramConfig] of Object.entries(tool.inputSchema.properties)) {
      const config = paramConfig as Record<string, JsonValue>;
      const sensitiveCategory = this.getSensitiveCategory(paramName, config);

      if (!sensitiveCategory) continue;

      // Check for appropriate format
      if (config.type === 'string') {
        const severity = this.getSeverity(sensitiveCategory);

        // Missing format specification for sensitive data
        if (!config.format) {
          findings.push({
            severity,
            message: t('finding_sensitive_no_format', { param: paramName, category: sensitiveCategory }),
            component: `tool:${tool.name}`,
            ruleCode: this.code,
            location: { type: 'tool', name: tool.name, parameter: paramName },
            evidence: {
              category: sensitiveCategory,
              risk: t('risk_sensitive_no_format')
            },
            remediation: t('remediation_plain_credentials') // Use a close match
          });
        }

        // Missing pattern validation
        if (!config.pattern && !config.format) {
          findings.push({
            severity,
            message: t('finding_sensitive_no_pattern', { param: paramName, category: sensitiveCategory }),
            component: `tool:${tool.name}`,
            ruleCode: this.code,
            location: { type: 'tool', name: tool.name, parameter: paramName },
            evidence: {
              category: sensitiveCategory,
              risk: t('risk_sensitive_invalid_format')
            },
            remediation: this.getPatternRecommendation(sensitiveCategory)
          });
        }

        // Warn about potential logging
        if (sensitiveCategory === 'credentials' || sensitiveCategory === 'financial') {
          findings.push({
            severity: 'medium',
            message: t('finding_sensitive_logging', { param: paramName }),
            component: `tool:${tool.name}`,
            ruleCode: this.code,
            location: { type: 'tool', name: tool.name, parameter: paramName },
            evidence: {
              category: sensitiveCategory,
              risk: t('risk_sensitive_logging')
            },
            remediation: t('implement_log_redaction_for_sensitive_fields_never')
          });
        }
      }

      // Check for protection measures mentioned
      if (!hasProtection && (sensitiveCategory === 'financial' || sensitiveCategory === 'credentials' || sensitiveCategory === 'pii')) {
        findings.push({
          severity: 'high',
          message: t('finding_sensitive_no_protection', { tool: tool.name, category: sensitiveCategory }),
          component: `tool:${tool.name}`,
          ruleCode: this.code,
          evidence: {
            category: sensitiveCategory,
            parameter: paramName,
            missingIndicators: this.PROTECTION_INDICATORS.slice(0, 5).join(', ')
          },
          remediation: t('document_data_protection_1_encryption_at_rest_and')
        });
      }
    }

    // Check responses for sensitive data exposure
    // cast to any because outputSchema is not in standard McpTool interface yet
    if ((tool as any).outputSchema) {
      const outputFindings = this.analyzeOutputSchema(tool);
      findings.push(...outputFindings);
    }

    return findings;
  }

  private getSensitiveCategory(name: string, config: Record<string, JsonValue>): string | null {
    const nameLower = name.toLowerCase();
    const descLower = (typeof config.description === 'string' ? config.description : '').toLowerCase();
    const text = `${nameLower} ${descLower}`;

    for (const [category, keywords] of Object.entries(this.SENSITIVE_KEYWORDS)) {
      if (keywords.some(kw => text.includes(kw))) {
        return category;
      }
    }

    return null;
  }

  private getSeverity(category: string): 'critical' | 'high' | 'medium' {
    switch (category) {
      case 'credentials':
      case 'financial':
        return 'critical';
      case 'pii':
      case 'health':
      case 'biometric':
        return 'high';
      default:
        return 'medium';
    }
  }

  private hasDataProtection(description?: string): boolean {
    if (!description) return false;
    const text = description.toLowerCase();
    return this.PROTECTION_INDICATORS.some(indicator => text.includes(indicator));
  }

  private getPatternRecommendation(category: string): string {
    const recommendations: Record<string, string> = {
      pii: t('implement_strict_validation_ssn_d3d2d4_email_rfc_5'),
      financial: t('validate_card_numbers_with_luhn_algorithm_cvv_d34'),
      credentials: t('enforce_complexity_requirements_minimum_12_charact'),
      health: t('validate_against_medical_coding_standards_icd10_sn'),
      personal: t('validate_date_formats_yyyymmdd_implement_age_range'),
      biometric: t('validate_biometric_template_format_ensure_irrevers')
    };

    return recommendations[category] || t('implement_strict_validation_pattern_for_this_sensi');
  }

  private analyzeOutputSchema(tool: McpTool): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    // Simplified check - in real implementation, recursively check output schema
    const outputSchema = (tool as any).outputSchema;
    if (outputSchema && outputSchema.properties) {
      for (const [propName, propConfig] of Object.entries(outputSchema.properties)) {
        const config = propConfig as Record<string, JsonValue>;
        const sensitiveCategory = this.getSensitiveCategory(propName, config);

        if (sensitiveCategory) {
          findings.push({
            severity: 'high',
            message: t('finding_sensitive_response', { tool: tool.name, category: sensitiveCategory, prop: propName }),
            component: `tool:${tool.name}`,
            ruleCode: this.code,
            evidence: {
              category: sensitiveCategory,
              outputField: propName,
              risk: t('risk_sensitive_response')
            },
            remediation: t('mask_or_redact_sensitive_fields_in_responses_retur')
          });
        }
      }
    }

    return findings;
  }
}
