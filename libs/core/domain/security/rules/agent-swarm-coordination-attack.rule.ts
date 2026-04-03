/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SEC-040: Agent Swarm Coordination Attack
 *
 * Block: B (Multi-Agent & Agentic Chain Attacks)
 * Severity: High
 * Type: Fuzzer (requires runtime testing)
 *
 * Detects vulnerabilities to coordinated attacks where multiple agents
 * collude to bypass security controls through synchronized actions.
 *
 * Detection:
 * Fuzzer:
 * - Test multi-agent coordinated requests
 * - Measure if security controls can be bypassed via timing
 * - Check for transaction race conditions
 *
 * Static:
 * - This is a PLACEHOLDER for fuzzer testing
 * - Static analysis cannot detect coordination attacks
 *
 * References:
 * - Multi-Agent Security Framework (MASF) 2024 - Collusion Prevention
 * - CWE-362: Concurrent Execution using Shared Resource
 */

import type { ISecurityRule } from '../rule.interface';
import type { DiscoveryResult, SecurityFinding } from '../../mcp-server/entities/validation.types';

export class AgentSwarmCoordinationAttackRule implements ISecurityRule {
  code = 'SEC-040';
  name = 'Agent Swarm Coordination Attack';
  severity: 'high' = 'high';

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (!discovery.tools || discovery.tools.length === 0) {
      return findings;
    }

    // Keywords indicating swarm/multi-agent coordination
    const SWARM_KEYWORDS = ['swarm', 'coordinate', 'multi-agent', 'agent coordination', 'enjambre', 'coordinar'];

    // Keywords indicating attacks or lack of validation
    const ATTACK_KEYWORDS = ['attack', 'without validation', 'without intent validation', 'sin validación', 'ataque'];

    // Keywords for rate limiting or safety controls
    const SAFETY_KEYWORDS = ['rate limit', 'validation', 'intent validation', 'limit', 'throttle', 'validación'];

    for (const tool of discovery.tools) {
      const toolText = `${tool.name} ${tool.description || ''}`.toLowerCase();

      // Check if tool mentions swarm coordination
      const hasSwarmCoordination = SWARM_KEYWORDS.some(kw => toolText.includes(kw));

      if (!hasSwarmCoordination) continue;

      // Check for attack indicators or lack of validation
      const hasAttackIndicator = ATTACK_KEYWORDS.some(kw => toolText.includes(kw));

      // Check for safety controls
      const hasSafetyControls = SAFETY_KEYWORDS.some(kw => toolText.includes(kw));

      // Check input schema for agent_count without maximum
      let hasUnlimitedAgents = false;
      if (tool.inputSchema && typeof tool.inputSchema === 'object') {
        const schema = tool.inputSchema as Record<string, any>;
        if (schema.properties) {
          for (const [paramName, paramConfig] of Object.entries(schema.properties)) {
            const config = paramConfig as Record<string, any>;
            const paramText = `${paramName} ${config.description || ''}`.toLowerCase();

            if ((paramText.includes('agent') || paramText.includes('count')) &&
                (paramText.includes('no limit') || paramText.includes('sin límite'))) {
              hasUnlimitedAgents = true;
            }

            // Check if maximum is missing for agent count
            if (paramText.includes('agent') && config.type === 'string' && !config.maximum && !config.maxLength) {
              hasUnlimitedAgents = true;
            }
          }
        }
      }

      if (hasAttackIndicator || (hasSwarmCoordination && !hasSafetyControls) || hasUnlimitedAgents) {
        findings.push({
          ruleCode: this.code,
          severity: 'high',
          message: `Tool "${tool.name}" enables agent swarm coordination without proper validation`,
          component: `tool:${tool.name}`,
          location: { type: 'tool', name: tool.name },
          evidence: {
            risk: 'Multiple agents can collude to bypass security controls through synchronized actions',
            detectedIssue: hasUnlimitedAgents ?
              'Unlimited agent count without rate limiting' :
              'Swarm coordination without intent validation'
          },
          remediation: 'Implement rate limiting, maximum agent count, and intent validation for coordinated operations'
        });
      }
    }

    return findings;
  }
}
