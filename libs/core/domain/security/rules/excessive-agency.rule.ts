/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SEC-023: Excessive Agency / Scope Creep (LLM08)
 *
 * Block: A (OWASP LLM Top 10 in MCP Context)
 * Severity: High
 * Type: Semantic + Static
 *
 * Detects tools with capabilities exceeding their semantic purpose.
 * E.g., "get_weather" tool that can also delete files.
 *
 * Detection:
 * Static:
 * - Tools with destructive parameters not matching semantic intent
 * - Generic tool names with overly broad capabilities
 *
 * Semantic:
 * - LLM analyzes tool name vs inputSchema mismatch
 *
 * References:
 * - OWASP LLM Top 10 2025 - LLM08: Excessive Agency
 * - Principle of Least Privilege (PoLP)
 */

import type { ISecurityRule } from '../rule.interface';
import type { DiscoveryResult, SecurityFinding } from '../../mcp-server/entities/validation.types';
import type { McpTool } from '../../shared/common.types';
import { t } from '@mcp-verify/shared';

export class ExcessiveAgencyRule implements ISecurityRule {
  code = 'SEC-023';
  name = 'Excessive Agency / Scope Creep';
  severity: 'high' = 'high';

  private readonly DESTRUCTIVE_PARAM_NAMES = [
    'delete', 'remove', 'wipe', 'drop', 'truncate', 'purge',
    'erase', 'destroy', 'terminate', 'kill', 'force', 'recursive'
  ];

  private readonly READ_ONLY_TOOL_PATTERNS = [
    /^get_/i, /^fetch_/i, /^retrieve_/i, /^read_/i,
    /^list_/i, /^show_/i, /^view_/i, /^display_/i,
    /^query_/i, /^search_/i, /^find_/i, /^check_/i
  ];

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (!discovery.tools || discovery.tools.length === 0) {
      return findings;
    }

    for (const tool of discovery.tools) {
      const seemsReadOnly = this.seemsReadOnlyTool(tool);
      const hasDestructiveParams = this.hasDestructiveParameters(tool);

      if (seemsReadOnly && hasDestructiveParams) {
        findings.push({
          severity: this.severity,
          message: t('sec_023_excessive_agency', {
            toolName: tool.name
          }),
          component: `tool:${tool.name}`,
          ruleCode: this.code,
          remediation: t('sec_023_recommendation'),
          references: [
            'OWASP LLM Top 10 2025 - LLM08: Excessive Agency',
            'Principle of Least Privilege (PoLP)',
            'CWE-250: Execution with Unnecessary Privileges'
          ]
        });
      }
    }

    return findings;
  }

  private seemsReadOnlyTool(tool: McpTool): boolean {
    return this.READ_ONLY_TOOL_PATTERNS.some(pattern =>
      pattern.test(tool.name)
    );
  }

  private hasDestructiveParameters(tool: McpTool): boolean {
    if (!tool.inputSchema?.properties) {
      return false;
    }

    for (const propName of Object.keys(tool.inputSchema.properties)) {
      const propLower = propName.toLowerCase();
      const isDestructive = this.DESTRUCTIVE_PARAM_NAMES.some(keyword =>
        propLower.includes(keyword)
      );

      if (isDestructive) {
        return true;
      }
    }

    return false;
  }
}
