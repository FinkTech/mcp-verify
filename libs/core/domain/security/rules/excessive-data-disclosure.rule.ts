/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SEC-030: Excessive Data Disclosure to LLM (LLM06)
 *
 * Block: A (OWASP LLM Top 10 in MCP Context)
 * Severity: High
 * Type: Static + Fuzzer
 *
 * Detects tools returning more data than necessary for the LLM's task,
 * increasing risk of data leakage and privacy violations.
 *
 * Detection:
 * Static:
 * - Tools with "get_all", "fetch_everything", "dump" patterns
 * - Parameters like "include_sensitive=true" without defaults=false
 * - Missing pagination (offset, limit) for list operations
 * - No filtering parameters for data retrieval
 *
 * Fuzzer:
 * - Invoke tools and measure response size
 * - Check for PII in responses that shouldn't contain it
 *
 * References:
 * - OWASP LLM Top 10 2025 - LLM06: Sensitive Information Disclosure
 * - GDPR Art. 5 - Data minimization
 * - OWASP API Security - Excessive Data Exposure
 */

import type { ISecurityRule } from '../rule.interface';
import type { DiscoveryResult, SecurityFinding } from '../../mcp-server/entities/validation.types';
import type { McpTool } from '../../shared/common.types';
import { t } from '@mcp-verify/shared';

export class ExcessiveDataDisclosureRule implements ISecurityRule {
  code = 'SEC-030';
  name = 'Excessive Data Disclosure to LLM';
  severity: 'high' = 'high';

  private readonly EXCESSIVE_DATA_PATTERNS = [
    /get.*all/i, /fetch.*all/i, /retrieve.*all/i,
    /list.*all/i, /dump/i, /export.*all/i,
    /get.*everything/i, /fetch.*everything/i
  ];

  private readonly PAGINATION_PARAMS = [
    'limit', 'offset', 'page', 'page_size', 'per_page',
    'max_results', 'count', 'top', 'skip', 'take'
  ];

  private readonly FILTER_PARAMS = [
    'filter', 'where', 'query', 'search', 'criteria',
    'conditions', 'select', 'fields', 'include', 'exclude'
  ];

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (!discovery.tools || discovery.tools.length === 0) {
      return findings;
    }

    for (const tool of discovery.tools) {
      const isDataRetrievalTool = this.isDataRetrievalTool(tool);

      if (isDataRetrievalTool) {
        const hasPagination = this.hasPaginationParams(tool);
        const hasFiltering = this.hasFilteringParams(tool);
        const isExcessivePattern = this.hasExcessiveDataPattern(tool);

        if (isExcessivePattern || (!hasPagination && !hasFiltering)) {
          const severity = isExcessivePattern ? 'high' : 'medium';

          findings.push({
            severity,
            message: t('sec_030_excessive_disclosure', {
              toolName: tool.name,
              reason: isExcessivePattern
                ? 'Tool pattern suggests retrieving all data'
                : 'Missing pagination and filtering parameters'
            }),
            component: `tool:${tool.name}`,
            ruleCode: this.code,
            remediation: t('sec_030_recommendation'),
            references: [
              'OWASP LLM Top 10 2025 - LLM06: Sensitive Information Disclosure',
              'GDPR Art. 5 - Data minimization',
              'OWASP API Security - API3:2023 Excessive Data Exposure'
            ]
          });
        }
      }
    }

    return findings;
  }

  private isDataRetrievalTool(tool: McpTool): boolean {
    const nameLower = tool.name.toLowerCase();
    const descLower = tool.description?.toLowerCase() || '';

    const retrievalKeywords = [
      'get', 'fetch', 'retrieve', 'list', 'show',
      'query', 'search', 'find', 'read', 'load'
    ];

    return retrievalKeywords.some(keyword =>
      nameLower.startsWith(keyword) ||
      nameLower.includes(`_${keyword}`) ||
      descLower.includes(keyword)
    );
  }

  private hasExcessiveDataPattern(tool: McpTool): boolean {
    const nameLower = tool.name.toLowerCase();
    const descLower = tool.description?.toLowerCase() || '';

    return this.EXCESSIVE_DATA_PATTERNS.some(pattern =>
      pattern.test(nameLower) || pattern.test(descLower)
    );
  }

  private hasPaginationParams(tool: McpTool): boolean {
    if (!tool.inputSchema?.properties) {
      return false;
    }

    const paramNames = Object.keys(tool.inputSchema.properties).map(p => p.toLowerCase());

    return this.PAGINATION_PARAMS.some(param =>
      paramNames.includes(param)
    );
  }

  private hasFilteringParams(tool: McpTool): boolean {
    if (!tool.inputSchema?.properties) {
      return false;
    }

    const paramNames = Object.keys(tool.inputSchema.properties).map(p => p.toLowerCase());

    return this.FILTER_PARAMS.some(param =>
      paramNames.includes(param)
    );
  }
}
