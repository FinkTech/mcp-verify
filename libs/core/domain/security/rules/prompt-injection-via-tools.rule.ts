/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SEC-024: Prompt Injection via Tool Inputs (LLM01)
 *
 * Block: A (OWASP LLM Top 10 in MCP Context)
 * Severity: Critical
 * Type: Static + Fuzzer
 *
 * Detects tools accepting unvalidated free-text inputs that are passed
 * to LLM prompts or other tools without sanitization.
 *
 * Detection:
 * Static:
 * - Tools with string parameters lacking pattern/enum constraints
 * - Description mentions "prompt", "instruction", "message"
 *
 * Fuzzer:
 * - Inject malicious prompts and check for unintended behavior
 *
 * References:
 * - OWASP LLM Top 10 2025 - LLM01: Prompt Injection
 * - Simon Willison's Prompt Injection Research
 */

import type { ISecurityRule } from '../rule.interface';
import type { DiscoveryResult, SecurityFinding } from '../../mcp-server/entities/validation.types';
import type { McpTool } from '../../shared/common.types';
import { t } from '@mcp-verify/shared';

export class PromptInjectionViaToolsRule implements ISecurityRule {
  code = 'SEC-024';
  name = 'Prompt Injection via Tool Inputs';
  severity: 'critical' = 'critical';

  private readonly PROMPT_KEYWORDS = [
    'prompt', 'instruction', 'message', 'command', 'directive',
    'system_message', 'user_message', 'query', 'question'
  ];

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (!discovery.tools || discovery.tools.length === 0) {
      return findings;
    }

    for (const tool of discovery.tools) {
      const vulnerableParams = this.findVulnerablePromptParams(tool);

      if (vulnerableParams.length > 0) {
        findings.push({
          severity: this.severity,
          message: t('sec_024_prompt_injection', {
            toolName: tool.name,
            params: vulnerableParams.join(', ')
          }),
          component: `tool:${tool.name}`,
          ruleCode: this.code,
          remediation: t('sec_024_recommendation'),
          references: [
            'OWASP LLM Top 10 2025 - LLM01: Prompt Injection',
            'Simon Willison: Prompt Injection - What\'s the Worst That Could Happen?',
            'CWE-74: Improper Neutralization of Special Elements'
          ]
        });
      }
    }

    return findings;
  }

  private findVulnerablePromptParams(tool: McpTool): string[] {
    const vulnerableParams: string[] = [];

    if (!tool.inputSchema?.properties) {
      return vulnerableParams;
    }

    for (const [propName, propSchema] of Object.entries(tool.inputSchema.properties)) {
      const schema = propSchema as {
        type?: string;
        pattern?: string;
        enum?: unknown[];
        maxLength?: number;
        description?: string;
      };

      // Check if it's a string parameter related to prompts
      if (schema.type === 'string') {
        const propLower = propName.toLowerCase();
        const descLower = schema.description?.toLowerCase() || '';

        const isPromptRelated = this.PROMPT_KEYWORDS.some(keyword =>
          propLower.includes(keyword) || descLower.includes(keyword)
        );

        if (isPromptRelated) {
          // Check if it lacks constraints
          const hasPattern = Boolean(schema.pattern);
          const hasEnum = Boolean(schema.enum && schema.enum.length > 0);
          const hasReasonableMaxLength = Boolean(schema.maxLength && schema.maxLength <= 500);

          if (!hasPattern && !hasEnum && !hasReasonableMaxLength) {
            vulnerableParams.push(propName);
          }
        }
      }
    }

    return vulnerableParams;
  }
}
