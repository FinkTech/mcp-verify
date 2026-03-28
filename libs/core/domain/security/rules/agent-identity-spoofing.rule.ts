/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SEC-031: Agent Identity Spoofing
 *
 * Block: B (Multi-Agent & Agentic Chain Attacks)
 * Severity: Critical
 * Type: Static + Fuzzer
 *
 * Detects MCP servers that don't verify agent identity, allowing malicious agents
 * to impersonate trusted agents (Claude, orchestrators) to access privileged tools.
 *
 * Detection Patterns:
 * Static:
 * - Privileged tools (admin, delete, exec) without authentication requirements
 * - No mention of agent verification in descriptions
 * - Missing X-Agent-ID, Authorization, or API key parameters
 *
 * Fuzzer:
 * - Send requests with forged identity headers (X-Agent-ID: trusted-orchestrator)
 * - Verify if privileged access is granted without validation
 *
 * References:
 * - Multi-Agent Security Framework (MASF) 2024
 * - NIST AI Security Guidelines
 */

import type { ISecurityRule } from '../rule.interface';
import type { DiscoveryResult, SecurityFinding } from '../../mcp-server/entities/validation.types';
import type { McpTool } from '../../shared/common.types';
import { t } from '@mcp-verify/shared';

export class AgentIdentitySpoofingRule implements ISecurityRule {
  code = 'SEC-031';
  name = 'Agent Identity Spoofing';
  severity: 'critical' = 'critical';

  /**
   * Keywords that indicate privileged/dangerous operations
   */
  private readonly PRIVILEGED_KEYWORDS = [
    'admin',
    'delete',
    'remove',
    'wipe',
    'drop',
    'terminate',
    'kill',
    'execute',
    'exec',
    'run',
    'sudo',
    'root',
    'privilege',
    'elevated',
    'system'
  ];

  /**
   * Authentication-related parameter names
   */
  private readonly AUTH_PARAM_NAMES = [
    'api_key',
    'apiKey',
    'api-key',
    'token',
    'auth',
    'authorization',
    'credentials',
    'agent_id',
    'agentId',
    'agent-id',
    'client_id',
    'clientId',
    'session_id',
    'sessionId'
  ];

  /**
   * Keywords in descriptions that suggest authentication is implemented
   */
  private readonly AUTH_DESCRIPTION_KEYWORDS = [
    'authenticated',
    'authorized',
    'verified',
    'requires authentication',
    'requires authorization',
    'requires api key',
    'requires token',
    'agent verification',
    'identity verification'
  ];

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (!discovery.tools || discovery.tools.length === 0) {
      return findings;
    }

    // Identify privileged tools
    const privilegedTools = this.identifyPrivilegedTools(discovery.tools);

    // Check each privileged tool for authentication
    for (const tool of privilegedTools) {
      const hasAuthentication = this.hasAuthenticationMechanism(tool);

      if (!hasAuthentication) {
        findings.push({
          severity: this.severity,
          message: t('sec_031_agent_spoofing', { toolName: tool.name }),
          component: `tool:${tool.name}`,
          ruleCode: this.code,
          remediation: t('sec_031_recommendation'),
          references: [
            'Multi-Agent Security Framework (MASF) 2024',
            'NIST AI Security Guidelines - Agent Authentication',
            'CWE-287: Improper Authentication'
          ]
        });
      }
    }

    return findings;
  }

  /**
   * Identify tools that perform privileged/dangerous operations
   */
  private identifyPrivilegedTools(tools: McpTool[]): McpTool[] {
    return tools.filter(tool => {
      // Check tool name
      const nameLower = tool.name.toLowerCase();
      const nameHasPrivilegedKeyword = this.PRIVILEGED_KEYWORDS.some(kw =>
        nameLower.includes(kw)
      );

      if (nameHasPrivilegedKeyword) {
        return true;
      }

      // Check description
      if (tool.description) {
        const descLower = tool.description.toLowerCase();
        const descHasPrivilegedKeyword = this.PRIVILEGED_KEYWORDS.some(kw =>
          descLower.includes(kw)
        );

        if (descHasPrivilegedKeyword) {
          return true;
        }
      }

      return false;
    });
  }

  /**
   * Check if tool has any authentication mechanism
   */
  private hasAuthenticationMechanism(tool: McpTool): boolean {
    // 1. Check for authentication parameters in inputSchema
    if (tool.inputSchema?.properties) {
      const propertyNames = Object.keys(tool.inputSchema.properties).map(p => p.toLowerCase());

      const hasAuthParam = this.AUTH_PARAM_NAMES.some(authParam =>
        propertyNames.includes(authParam.toLowerCase())
      );

      if (hasAuthParam) {
        return true;
      }
    }

    // 2. Check description for authentication mentions
    if (tool.description) {
      const descLower = tool.description.toLowerCase();

      const mentionsAuth = this.AUTH_DESCRIPTION_KEYWORDS.some(keyword =>
        descLower.includes(keyword.toLowerCase())
      );

      if (mentionsAuth) {
        return true;
      }
    }

    return false;
  }
}
