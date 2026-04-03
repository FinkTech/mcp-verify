/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Authentication Bypass Detection Rule (SEC-001)
 *
 * Detects potential authentication bypass vulnerabilities in MCP server tools.
 * Weak authentication can allow unauthorized access, privilege escalation,
 * and account takeover.
 *
 * Validates:
 * - Password/credential handling without strong hashing
 * - Missing complexity requirements for passwords
 * - Insecure authentication mechanisms
 * - Lack of multi-factor authentication
 * - Timing attack vulnerabilities in credential verification
 *
 * @module libs/core/domain/security/rules/auth-bypass.rule
 */

import { t } from '@mcp-verify/shared';
import { ISecurityRule } from '../rule.interface';
import type { DiscoveryResult, SecurityFinding } from '../../mcp-server/entities/validation.types';
import type { McpTool, JsonValue } from '../../shared/common.types';

export class AuthenticationBypassRule implements ISecurityRule {
  readonly code = 'SEC-001';
  get name() { return t('sec_auth_bypass_name'); }
  get description() { return t('sec_auth_bypass_desc'); }
  readonly helpUri = 'https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication';

  /**
   * Keywords indicating authentication operations.
   */
  private readonly AUTH_KEYWORDS = [
    'login', 'authenticate', 'auth', 'signin', 'sign_in', 'verify',
    'check_password', 'verify_password', 'check_credentials', 'validate_user',
    'session', 'token', 'jwt', 'oauth', 'sso',
    'register', 'signup', 'sign_up', 'create_user', 'user_creation',
    'password', 'credential', 'update_password', 'change_password', 'reset_password',
    'admin_access', 'admin', 'access'
  ];

  /**
   * Strong password hashing algorithms.
   */
  private readonly STRONG_HASHING = [
    'bcrypt', 'argon2', 'scrypt', 'pbkdf2'
  ];

  /**
   * Weak/deprecated hashing algorithms.
   */
  private readonly WEAK_HASHING = [
    'md5', 'sha1', 'sha-1', 'plain', 'plaintext', 'clear text',
    'base64', 'reversible'
  ];

  /**
   * Indicators of secure authentication practices.
   */
  private readonly SECURE_INDICATORS = [
    'rate limiting', 'brute force protection', 'account lockout',
    'mfa', 'multi-factor', '2fa', 'two-factor', 'totp', 'otp',
    'constant time comparison', 'timing-safe', 'secure comparison'
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
    const isAuthTool = this.isAuthenticationTool(tool.name, tool.description);

    if (!isAuthTool) {
      return findings;
    }

    const hasStrongHashing = this.hasStrongHashing(tool.description);
    const hasWeakHashing = this.hasWeakHashing(tool.description);
    const hasSecureIndicators = this.hasSecurePractices(tool.description);

    // CRITICAL: Tool uses weak hashing
    if (hasWeakHashing) {
      findings.push({
        severity: 'critical',
        message: t('finding_auth_weak_hashing', { tool: tool.name }),
        component: `tool:${tool.name}`,
        ruleCode: this.code,
        evidence: {
          risk: t('passwords_can_be_cracked_easily_with_rainbow_table'),
          detectedAlgorithm: this.getWeakHashingMethod(tool.description)
        },
        remediation: t('replace_weak_hashing_with_bcrypt_argon2_or_scrypt')
      });
    }

    if (!tool.inputSchema?.properties) {
      if (!hasStrongHashing && !hasWeakHashing) {
        findings.push({
          severity: 'high',
          message: t('finding_auth_no_hashing_method', { tool: tool.name }),
          component: `tool:${tool.name}`,
          ruleCode: this.code,
          evidence: {
            risk: t('unclear_if_passwords_are_stored_securely')
          },
          remediation: t('document_the_password_hashing_algorithm_used_shoul')
        });
      }
      return findings;
    }

    // Analyze parameters
    for (const [paramName, paramConfig] of Object.entries(tool.inputSchema.properties)) {
      const config = paramConfig as Record<string, JsonValue>;

      // Check password parameters
      if (this.isPasswordParameter(paramName, config)) {
        // Missing minimum length
        if (!config.minLength || (typeof config.minLength === 'number' && config.minLength < 8)) {
          findings.push({
            severity: 'high',
            message: t('finding_auth_min_length', { param: paramName }),
            component: `tool:${tool.name}`,
            ruleCode: this.code,
            location: { type: 'tool', name: tool.name, parameter: paramName },
            evidence: {
              currentMinLength: config.minLength || 0,
              recommendedMinLength: 12
            },
            remediation: t('set_minlength_to_at_least_8_characters_preferably')
          });
        }

        // Missing pattern (complexity requirements)
        if (!config.pattern) {
          findings.push({
            severity: 'medium',
            message: t('finding_auth_complexity', { param: paramName }),
            component: `tool:${tool.name}`,
            ruleCode: this.code,
            location: { type: 'tool', name: tool.name, parameter: paramName },
            evidence: {
              risk: t('risk_weak_passwords')
            },
            remediation: t('implement_complexity_requirements_uppercase_lowerc')
          });
        }
      }

      // Check username/email parameters for enumeration
      if (this.isUsernameParameter(paramName, config)) {
        // Could allow user enumeration if error messages differ
        if (!hasSecureIndicators) {
          findings.push({
            severity: 'medium',
            message: t('finding_auth_user_enumeration', { param: paramName }),
            component: `tool:${tool.name}`,
            ruleCode: this.code,
            location: { type: 'tool', name: tool.name, parameter: paramName },
            evidence: {
              risk: t('risk_user_enumeration')
            },
            remediation: t('remediation_user_enumeration')
          });
        }
      }

      // Check for API keys/tokens being passed as plain strings
      if (this.isCredentialParameter(paramName, config)) {
        if (config.type === 'string' && !config.format) {
          findings.push({
            severity: 'medium',
            message: t('finding_auth_credentials_plain', { param: paramName }),
            component: `tool:${tool.name}`,
            ruleCode: this.code,
            location: { type: 'tool', name: tool.name, parameter: paramName },
            evidence: {
              risk: t('risk_plain_credentials')
            },
            remediation: t('remediation_plain_credentials')
          });
        }
      }
    }

    // General warnings
    if (!hasStrongHashing && !hasWeakHashing) {
      findings.push({
        severity: 'high',
        message: t('finding_auth_no_hashing', { tool: tool.name }),
        component: `tool:${tool.name}`,
        ruleCode: this.code,
        evidence: {
          missingIndicators: this.STRONG_HASHING.join(', ')
        },
        remediation: t('document_password_hashing_method_use_bcrypt_argon2')
      });
    }

    if (!hasSecureIndicators) {
      findings.push({
        severity: 'medium',
        message: t('finding_auth_no_brute_force', { tool: tool.name }),
        component: `tool:${tool.name}`,
        ruleCode: this.code,
        evidence: {
          missingIndicators: 'Rate limiting, account lockout, MFA'
        },
        remediation: t('implement_1_rate_limiting_on_login_attempts_2_acco')
      });
    }

    return findings;
  }

  private isAuthenticationTool(name: string, description?: string): boolean {
    const text = `${name} ${description || ''}`.toLowerCase();
    return this.AUTH_KEYWORDS.some(kw => text.includes(kw));
  }

  private hasStrongHashing(description?: string): boolean {
    if (!description) return false;
    const text = description.toLowerCase();
    return this.STRONG_HASHING.some(algo => text.includes(algo));
  }

  private hasWeakHashing(description?: string): boolean {
    if (!description) return false;
    const text = description.toLowerCase();
    return this.WEAK_HASHING.some(algo => text.includes(algo));
  }

  private getWeakHashingMethod(description?: string): string {
    if (!description) return 'unknown';
    const text = description.toLowerCase();
    const found = this.WEAK_HASHING.find(algo => text.includes(algo));
    return found || 'unknown';
  }

  private hasSecurePractices(description?: string): boolean {
    if (!description) return false;
    const text = description.toLowerCase();
    return this.SECURE_INDICATORS.some(indicator => text.includes(indicator));
  }

  private isPasswordParameter(name: string, config: Record<string, JsonValue>): boolean {
    const passwordNames = ['password', 'passwd', 'pwd', 'pass', 'secret'];
    const nameLower = name.toLowerCase();
    const descLower = (typeof config.description === 'string' ? config.description : '').toLowerCase();

    return passwordNames.some(p => nameLower.includes(p) || descLower.includes('password')) ||
      config.format === 'password';
  }

  private isUsernameParameter(name: string, config: Record<string, JsonValue>): boolean {
    const usernameNames = ['username', 'user', 'email', 'login', 'account'];
    const nameLower = name.toLowerCase();

    return usernameNames.some(u => nameLower.includes(u)) ||
      config.format === 'email';
  }

  private isCredentialParameter(name: string, config: Record<string, JsonValue>): boolean {
    const credentialNames = ['token', 'apikey', 'api_key', 'secret', 'key', 'credential'];
    const nameLower = name.toLowerCase();

    return credentialNames.some(c => nameLower.includes(c));
  }
}
