/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SEC-035: Agent State Poisoning
 *
 * Block: B (Multi-Agent & Agentic Chain Attacks)
 * Severity: High
 * Type: Static + Fuzzer
 *
 * Detects tools that modify shared agent state or memory without proper
 * validation, allowing malicious agents to corrupt state for other agents.
 *
 * Detection:
 * Static:
 * - Tools with "set_state", "update_memory", "persist" patterns
 * - Missing state validation/sanitization
 * - No state isolation between agents
 *
 * Fuzzer:
 * - Inject malicious state and test propagation
 *
 * References:
 * - Multi-Agent Security Framework (MASF) 2024 - State Isolation
 * - CWE-362: Concurrent Execution using Shared Resource
 */

import type { ISecurityRule } from '../rule.interface';
import type { DiscoveryResult, SecurityFinding } from '../../mcp-server/entities/validation.types';
import type { McpTool } from '../../shared/common.types';
import { t } from '@mcp-verify/shared';

export class AgentStatePoisoningRule implements ISecurityRule {
  code = 'SEC-035';
  name = 'Agent State Poisoning';
  severity: 'high' = 'high';

  private readonly STATE_MODIFICATION_PATTERNS = [
    /set.*state/i, /update.*state/i, /modify.*state/i,
    /persist.*state/i, /save.*state/i, /store.*state/i,
    /set.*memory/i, /update.*memory/i, /write.*memory/i,
    /cache.*set/i, /session.*update/i, /context.*set/i
  ];

  private readonly STATE_KEYWORDS = [
    'state', 'memory', 'context', 'session', 'cache',
    'storage', 'persist', 'save', 'store', 'global'
  ];

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (!discovery.tools || discovery.tools.length === 0) {
      return findings;
    }

    for (const tool of discovery.tools) {
      const modifiesState = this.modifiesSharedState(tool);

      if (modifiesState) {
        const hasValidation = this.hasStateValidation(tool);
        const hasIsolation = this.hasAgentIsolation(tool);

        if (!hasValidation || !hasIsolation) {
          findings.push({
            severity: this.severity,
            message: t('sec_035_state_poisoning', {
              toolName: tool.name,
              issue: !hasValidation ? 'missing validation' : 'missing agent isolation'
            }),
            component: `tool:${tool.name}`,
            ruleCode: this.code,
            remediation: t('sec_035_recommendation'),
            references: [
              'Multi-Agent Security Framework (MASF) 2024 - State Isolation',
              'CWE-362: Concurrent Execution using Shared Resource',
              'OWASP - Session Management'
            ]
          });
        }
      }
    }

    return findings;
  }

  private modifiesSharedState(tool: McpTool): boolean {
    // Check name pattern
    const nameMatches = this.STATE_MODIFICATION_PATTERNS.some(pattern =>
      pattern.test(tool.name)
    );
    if (nameMatches) return true;

    // Check description
    if (tool.description) {
      const descLower = tool.description.toLowerCase();
      const descMatches = this.STATE_MODIFICATION_PATTERNS.some(pattern =>
        pattern.test(descLower)
      );
      if (descMatches) return true;

      // Check for state keywords
      const hasStateKeyword = this.STATE_KEYWORDS.some(keyword =>
        descLower.includes(keyword)
      );
      const mentionsWrite = descLower.includes('write') || descLower.includes('update') || descLower.includes('set');
      if (hasStateKeyword && mentionsWrite) return true;
    }

    // Check parameters
    if (tool.inputSchema?.properties) {
      for (const propName of Object.keys(tool.inputSchema.properties)) {
        const propLower = propName.toLowerCase();
        const isStateParam = this.STATE_KEYWORDS.some(keyword =>
          propLower.includes(keyword)
        );
        if (isStateParam) return true;
      }
    }

    return false;
  }

  private hasStateValidation(tool: McpTool): boolean {
    // Check description for validation keywords
    if (tool.description) {
      const descLower = tool.description.toLowerCase();
      const validationKeywords = [
        'validate', 'sanitize', 'verify', 'check',
        'filter', 'clean', 'escape'
      ];

      const hasValidation = validationKeywords.some(keyword =>
        descLower.includes(keyword)
      );
      if (hasValidation) return true;
    }

    // Check if state parameters have validation constraints
    if (tool.inputSchema?.properties) {
      for (const [propName, propSchema] of Object.entries(tool.inputSchema.properties)) {
        const propLower = propName.toLowerCase();
        const isStateParam = this.STATE_KEYWORDS.some(keyword =>
          propLower.includes(keyword)
        );

        if (isStateParam) {
          const schema = propSchema as {
            pattern?: string;
            format?: string;
            enum?: unknown[];
            maxLength?: number;
            [key: string]: unknown;
          };

          const hasConstraints = schema.pattern || schema.format || schema.enum || schema.maxLength;
          if (hasConstraints) return true;
        }
      }
    }

    return false;
  }

  private hasAgentIsolation(tool: McpTool): boolean {
    // Check if tool requires agent_id or session_id for state isolation
    if (!tool.inputSchema?.properties) {
      return false;
    }

    const paramNames = Object.keys(tool.inputSchema.properties).map(p => p.toLowerCase());

    const isolationParams = [
      'agent_id', 'session_id', 'user_id', 'tenant_id',
      'namespace', 'scope', 'context_id'
    ];

    return isolationParams.some(param =>
      paramNames.includes(param)
    );
  }
}
