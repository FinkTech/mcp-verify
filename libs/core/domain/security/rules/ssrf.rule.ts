/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Server-Side Request Forgery (SSRF) Detection Rule (SEC-004)
 *
 * Detects potential SSRF vulnerabilities in MCP server tools.
 * SSRF allows an attacker to induce the server to make HTTP requests to
 * arbitrary domains, including internal networks (e.g., metadata services, localhost).
 *
 * Validates:
 * - Tool parameters that accept URLs/URIs.
 * - Absence of strict allowlists (regex) for domains.
 * - Permissive patterns that allow 'http' (unencrypted) or internal IP ranges.
 *
 * @module libs/core/domain/security/rules/ssrf.rule
 */

import { t } from '@mcp-verify/shared';
import { ISecurityRule } from '../rule.interface';
import { translations } from '../../reporting/i18n';
import type { DiscoveryResult, SecurityFinding } from '../../mcp-server/entities/validation.types';
import type { McpTool, JsonValue } from '../../shared/common.types';

type TranslationKey = keyof typeof translations.en;

export class SSRFDetectionRule implements ISecurityRule {
  readonly code = 'SEC-004';
  get name() { return t('sec_ssrf_name'); }
  get description() { return t('sec_ssrf_desc'); }
  readonly helpUri = 'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery';
  readonly tags = ['CWE-918', 'OWASP-A10:2021', 'SSRF'];

  /**
   * Keywords indicating a parameter expects a URL.
   */
  private readonly URL_INDICATORS = [
    'url', 'uri', 'link', 'endpoint', 'webhook', 'callback', 'host', 'domain', 'address'
  ];

  /**
   * Dangerous IP ranges or localhost references that should never be default-allowed.
   */
  private readonly INTERNAL_NETWORK_PATTERNS = [
    'localhost',
    '127.0.0.1',
    '0.0.0.0',
    '169.254.', // Cloud metadata
    '192.168.', // Local network
    '10.',      // Local network
    '::1'
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

    if (!tool.inputSchema?.properties) return findings;

    for (const [paramName, paramConfig] of Object.entries(tool.inputSchema.properties)) {
      const config = paramConfig as Record<string, JsonValue>;

      // Check if parameter is a URL input
      if (!this.isUrlParameter(paramName, config)) continue;

      // 1. Check for absence of validation
      if (!config.pattern && !config.format) {
        findings.push({
          severity: 'high',
          message: t('finding_ssrf_potential', { param: paramName }),
          component: `tool:${tool.name}`,
          ruleCode: this.code,
          location: { type: 'tool', name: tool.name, parameter: paramName },
          evidence: { parameter: paramName, risk: t('risk_ssrf_arbitrary') },
          remediation: t('remediation_ssrf_restrict')
        });
        continue;
      }

      // 2. Check for weak validation (if pattern exists)
      // Type guard: pattern must be a string to be validated
      if (config.pattern && typeof config.pattern === 'string') {
        const weakness = this.isWeakUrlPattern(config.pattern);
        if (weakness.isWeak) {
          findings.push({
            severity: 'medium',
            message: t('finding_ssrf_weak_val', { param: paramName }),
            component: `tool:${tool.name}`,
            ruleCode: this.code,
            location: { type: 'tool', name: tool.name, parameter: paramName },
            evidence: { pattern: config.pattern, issue: weakness.reason ? t(weakness.reason) : null },
            remediation: t('remediation_ssrf_tighten')
          });
        }
      }
    }

    return findings;
  }

  private isUrlParameter(name: string, config: Record<string, JsonValue>): boolean {
    if (config.type !== 'string') return false;

    // Explicit format check (if using JSON schema formats)
    if (config.format === 'uri' || config.format === 'url') return true;

    // Keyword heuristic
    const nameLower = name.toLowerCase();
    const descLower = (typeof config.description === 'string' ? config.description : '').toLowerCase();

    return this.URL_INDICATORS.some(i => nameLower.includes(i) || descLower.includes(i));
  }

  private isWeakUrlPattern(pattern: string): { isWeak: boolean; reason?: TranslationKey } {
    // Check if it allows HTTP (insecure)
    if (!pattern.toLowerCase().includes('https') && pattern.includes('http')) {
      return { isWeak: true, reason: 'ssrf_insecure_http' };
    }

    // Check if it's too permissive (e.g., starts with .* or similar)
    if (pattern.startsWith('.*') || pattern === '.*' || pattern.startsWith('^.*')) {
      return { isWeak: true, reason: 'ssrf_wildcard_start' };
    }

    // Check if it doesn't anchor the start/end (partial matches are dangerous for validation)
    if (!pattern.startsWith('^') || !pattern.endsWith('$')) {
      return { isWeak: true, reason: 'ssrf_not_anchored' };
    }

    return { isWeak: false };
  }
}
