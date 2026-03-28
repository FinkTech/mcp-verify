/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Missing Rate Limiting Detection Rule (SEC-010)
 *
 * Detects tools that perform expensive or sensitive operations without
 * rate limiting, which can lead to resource exhaustion, abuse, and DoS.
 *
 * Validates:
 * - Expensive operations (DB queries, API calls, file I/O) without rate limits
 * - Authentication/authorization tools without rate limiting
 * - Resource-intensive computations
 * - Missing throttling configuration
 *
 * @module libs/core/domain/security/rules/rate-limiting.rule
 */

import { t } from '@mcp-verify/shared';
import { ISecurityRule } from '../rule.interface';
import type { DiscoveryResult, SecurityFinding } from '../../mcp-server/entities/validation.types';
import type { McpTool, JsonValue } from '../../shared/common.types';

export class RateLimitingRule implements ISecurityRule {
  readonly code = 'SEC-010';
  get name() { return t('sec_rate_limiting_name'); }
  get description() { return t('sec_rate_limiting_desc'); }
  readonly helpUri = 'https://owasp.org/www-community/controls/Rate_Limiting';
  readonly tags = ['CWE-770', 'OWASP-A04:2021', 'Resource Exhaustion'];

  /**
   * Keywords indicating expensive operations that need rate limiting.
   */
  private readonly EXPENSIVE_OPERATIONS = {
    database: ['query', 'sql', 'database', 'db', 'select', 'insert', 'update', 'delete', 'transaction'],
    network: ['api', 'http', 'fetch', 'request', 'curl', 'webhook', 'external', 'remote'],
    file: ['file', 'read', 'write', 'upload', 'download', 'storage', 'disk', 'filesystem'],
    compute: ['compute', 'calculate', 'process', 'analyze', 'generate', 'render', 'encode', 'decode', 'hash'],
    auth: ['login', 'authenticate', 'signin', 'verify', 'password', 'credential']
  };

  /**
   * Indicators that rate limiting is implemented.
   */
  private readonly RATE_LIMIT_INDICATORS = [
    'rate limit', 'rate-limit', 'rate limiting', 'throttle', 'throttling',
    'requests per', 'rpm', 'rps', 'per minute', 'per second', 'per hour',
    'quota', 'limit', 'max requests', 'backoff', 'retry-after',
    'x-rate-limit', 'ratelimit'
  ];

  /**
   * Extensions/properties indicating rate limit configuration.
   */
  private readonly RATE_LIMIT_EXTENSIONS = [
    'x-rate-limit', 'x-ratelimit', 'x-throttle', 'x-quota'
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

    // Determine if tool performs expensive operations
    const expensiveCategories = this.getExpensiveCategories(tool.name, tool.description);

    if (expensiveCategories.length === 0) {
      return findings; // Not an expensive tool
    }

    const hasRateLimiting = this.hasRateLimiting(tool);

    // If expensive operations detected but no rate limiting
    if (!hasRateLimiting) {
      const severity = this.getSeverity(expensiveCategories);

      findings.push({
        severity,
        message: t('finding_rate_limit_missing', { tool: tool.name, ops: expensiveCategories.join(', ') }),
        component: `tool:${tool.name}`,
        ruleCode: this.code,
        evidence: {
          operationTypes: expensiveCategories,
          risk: t('risk_rate_limit_exhaustion')
        },
        remediation: this.getRemediation(expensiveCategories)
      });
    }

    // Check for specific high-risk scenarios
    if (expensiveCategories.includes('auth') && !hasRateLimiting) {
      findings.push({
        severity: 'high',
        message: t('finding_rate_limit_auth_must', { tool: tool.name }),
        component: `tool:${tool.name}`,
        ruleCode: this.code,
        evidence: {
          risk: t('risk_rate_limit_brute_force')
        },
        remediation: t('remediation_rate_limit_aggressive')
      });
    }

    // Check for file upload without size/rate limits
    if (expensiveCategories.includes('file') && tool.inputSchema?.properties) {
      const fileParams = this.getFileParameters(tool.inputSchema.properties);

      for (const param of fileParams) {
        if (!param.config.maxLength && !param.config.maxSize) {
          findings.push({
            severity: 'medium',
            message: t('finding_rate_limit_no_size', { param: param.name }),
            component: `tool:${tool.name}`,
            ruleCode: this.code,
            location: { type: 'tool', name: tool.name, parameter: param.name },
            evidence: {
              risk: t('risk_rate_limit_disk_space')
            },
            remediation: t('remediation_rate_limit_file')
          });
        }
      }
    }

    return findings;
  }

  private getExpensiveCategories(name: string, description?: string): string[] {
    const text = `${name} ${description || ''}`.toLowerCase();
    const categories: string[] = [];

    for (const [category, keywords] of Object.entries(this.EXPENSIVE_OPERATIONS)) {
      if (keywords.some(kw => text.includes(kw))) {
        categories.push(category);
      }
    }

    return categories;
  }

  private hasRateLimiting(tool: McpTool): boolean {
    // Check description for rate limiting mentions
    if (tool.description) {
      const descLower = tool.description.toLowerCase();
      if (this.RATE_LIMIT_INDICATORS.some(indicator => descLower.includes(indicator))) {
        return true;
      }
    }

    // Check for x-rate-limit extensions in schema
    if (tool.inputSchema) {
      const schema = JSON.stringify(tool.inputSchema).toLowerCase();

      if (this.RATE_LIMIT_EXTENSIONS.some(ext => schema.includes(ext))) {
        return true;
      }
    }

    // Check for rate limit properties in parameters
    if (tool.inputSchema?.properties) {
      for (const [paramName, paramConfig] of Object.entries(tool.inputSchema.properties)) {
        const config = paramConfig as Record<string, JsonValue>;
        const nameLower = paramName.toLowerCase();

        if (nameLower.includes('ratelimit') || nameLower.includes('throttle') || nameLower.includes('quota')) {
          return true;
        }

        if (typeof config.description === 'string') {
          const descLower = config.description.toLowerCase();
          if (this.RATE_LIMIT_INDICATORS.some(indicator => descLower.includes(indicator))) {
            return true;
          }
        }
      }
    }

    return false;
  }

  private getSeverity(categories: string[]): 'critical' | 'high' | 'medium' {
    if (categories.includes('auth')) {
      return 'high';
    }

    if (categories.includes('database') || categories.includes('file')) {
      return 'medium';
    }

    return 'medium';
  }

  private getRemediation(categories: string[]): string {
    const recommendations = [];

    recommendations.push(t('remediation_rate_limit_generic'));

    if (categories.includes('auth')) {
      recommendations.push(t('rate_limit_guideline_auth'));
    }

    if (categories.includes('database')) {
      recommendations.push(t('rate_limit_guideline_db'));
    }

    if (categories.includes('network')) {
      recommendations.push(t('rate_limit_guideline_net'));
    }

    if (categories.includes('file')) {
      recommendations.push(t('rate_limit_guideline_file'));
    }

    if (categories.includes('compute')) {
      recommendations.push(t('rate_limit_guideline_compute'));
    }

    recommendations.push(t('rate_limit_config_options'));
    recommendations.push(t('rate_limit_option_extension'));
    recommendations.push(t('rate_limit_option_docs'));
    recommendations.push(t('rate_limit_option_header'));

    return recommendations.join('\n');
  }

  private getFileParameters(properties: Record<string, JsonValue>): Array<{ name: string; config: Record<string, JsonValue> }> {
    const fileParams: Array<{ name: string; config: Record<string, JsonValue> }> = [];

    for (const [paramName, paramConfig] of Object.entries(properties)) {
      const config = paramConfig as Record<string, JsonValue>;
      const nameLower = paramName.toLowerCase();

      if (nameLower.includes('file') ||
        nameLower.includes('upload') ||
        nameLower.includes('attachment') ||
        config.format === 'binary' ||
        config.contentMediaType) {
        fileParams.push({ name: paramName, config });
      }
    }

    return fileParams;
  }
}
