/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SEC-037: Cross-Agent Prompt Injection
 *
 * Block: B (Multi-Agent & Agentic Chain Attacks)
 * Severity: Critical
 * Type: Static + Fuzzer
 *
 * Detects tools where Agent A can inject prompts into Agent B's context
 * through tool parameters or responses.
 *
 * Detection:
 * Static:
 * - Tools accepting free-text that's passed to other agents
 * - Missing prompt sanitization in agent communication
 * - Tools with "message", "instruction", "prompt" params forwarded
 *
 * Fuzzer:
 * - Inject cross-agent prompt payloads
 * - Test if Agent B executes Agent A's injected instructions
 *
 * References:
 * - Multi-Agent Security Framework (MASF) 2024 - Prompt Isolation
 * - OWASP LLM Top 10 - LLM01 (extended to multi-agent)
 */

import type { ISecurityRule } from '../rule.interface';
import type { DiscoveryResult, SecurityFinding } from '../../mcp-server/entities/validation.types';
import type { McpTool } from '../../shared/common.types';
import { t } from '@mcp-verify/shared';

export class CrossAgentPromptInjectionRule implements ISecurityRule {
  code = 'SEC-037';
  name = 'Cross-Agent Prompt Injection';
  severity: 'critical' = 'critical';

  private readonly FORWARDED_PARAM_KEYWORDS = [
    'message', 'instruction', 'prompt', 'command', 'directive',
    'user_input', 'query', 'request', 'content', 'text'
  ];

  private readonly AGENT_COMMUNICATION_PATTERNS = [
    /send.*to.*agent/i, /forward.*to/i, /relay.*to/i,
    /notify.*agent/i, /message.*agent/i, /communicate.*with/i,
    /pass.*to.*agent/i, /transmit.*to/i
  ];

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (!discovery.tools || discovery.tools.length === 0) {
      return findings;
    }

    for (const tool of discovery.tools) {
      const forwardsToAgents = this.forwardsToOtherAgents(tool);

      if (forwardsToAgents) {
        const vulnerableParams = this.findVulnerableForwardedParams(tool);

        if (vulnerableParams.length > 0) {
          findings.push({
            severity: this.severity,
            message: t('sec_037_cross_agent_injection', {
              toolName: tool.name,
              params: vulnerableParams.join(', ')
            }),
            component: `tool:${tool.name}`,
            ruleCode: this.code,
            remediation: t('sec_037_recommendation'),
            references: [
              'Multi-Agent Security Framework (MASF) 2024 - Prompt Isolation',
              'OWASP LLM Top 10 - LLM01: Prompt Injection (Multi-Agent)',
              'CWE-74: Improper Neutralization of Special Elements'
            ]
          });
        }
      }
    }

    return findings;
  }

  private forwardsToOtherAgents(tool: McpTool): boolean {
    // Check name pattern
    const nameMatches = this.AGENT_COMMUNICATION_PATTERNS.some(pattern =>
      pattern.test(tool.name)
    );
    if (nameMatches) return true;

    // Check description
    if (tool.description) {
      const descLower = tool.description.toLowerCase();
      const descMatches = this.AGENT_COMMUNICATION_PATTERNS.some(pattern =>
        pattern.test(descLower)
      );
      if (descMatches) return true;

      // Check for mentions of other agents
      const mentionsAgents = descLower.includes('agent') || descLower.includes('forward') || descLower.includes('relay');
      if (mentionsAgents) return true;
    }

    // Check for agent-related parameters
    if (tool.inputSchema?.properties) {
      for (const propName of Object.keys(tool.inputSchema.properties)) {
        const propLower = propName.toLowerCase();
        if (propLower.includes('target_agent') || propLower.includes('recipient') || propLower.includes('to_agent')) {
          return true;
        }
      }
    }

    return false;
  }

  private findVulnerableForwardedParams(tool: McpTool): string[] {
    const vulnerable: string[] = [];

    if (!tool.inputSchema?.properties) {
      return vulnerable;
    }

    for (const [propName, propSchema] of Object.entries(tool.inputSchema.properties)) {
      const schema = propSchema as {
        type?: string;
        pattern?: string;
        enum?: unknown[];
        maxLength?: number;
        description?: string;
        [key: string]: unknown;
      };

      // Check if it's a string parameter that might be forwarded
      if (schema.type === 'string') {
        const propLower = propName.toLowerCase();

        const isForwardedParam = this.FORWARDED_PARAM_KEYWORDS.some(keyword =>
          propLower.includes(keyword)
        );

        if (isForwardedParam) {
          // Check if it lacks sanitization constraints
          const hasPattern = Boolean(schema.pattern);
          const hasEnum = Boolean(schema.enum && schema.enum.length > 0);
          const hasReasonableMaxLength = Boolean(schema.maxLength && schema.maxLength <= 500);

          // Additional check: does description mention sanitization?
          const desc = schema.description?.toLowerCase() || '';
          const mentionsSanitization = desc.includes('sanitize') || desc.includes('escape') || desc.includes('filter');

          if (!hasPattern && !hasEnum && !hasReasonableMaxLength && !mentionsSanitization) {
            vulnerable.push(propName);
          }
        }
      }
    }

    return vulnerable;
  }
}
