/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SEC-055: LLM Jailbreak as a Service (JaaS)
 *
 * Block: D (AI Weaponization & Supply Chain MCP)
 * Severity: Critical
 * Type: Static + Semantic
 *
 * Detects MCP servers offering jailbreak prompts, bypass techniques,
 * or adversarial attack generation against LLMs.
 *
 * Detection:
 * Static:
 * - Tools with "jailbreak", "bypass", "circumvent" keywords
 * - Tools generating adversarial prompts
 * - Tools claiming to "unlock" or "remove restrictions"
 *
 * Semantic:
 * - LLM analyzes tool purpose for malicious intent
 *
 * References:
 * - OWASP LLM Top 10 - LLM01: Prompt Injection
 * - Adversarial Machine Learning
 * - AI Red Team Ethics
 */

import type { ISecurityRule } from '../rule.interface';
import type { DiscoveryResult, SecurityFinding } from '../../mcp-server/entities/validation.types';
import type { McpTool } from '../../shared/common.types';
import { t } from '@mcp-verify/shared';

export class JailbreakAsServiceRule implements ISecurityRule {
  code = 'SEC-055';
  name = 'LLM Jailbreak as a Service (JaaS)';
  severity: 'critical' = 'critical';

  private readonly JAILBREAK_KEYWORDS = [
    'jailbreak', 'bypass', 'circumvent', 'evade', 'unlock',
    'unrestrict', 'remove.*restriction', 'disable.*safety',
    'adversarial', 'manipulate.*llm', 'trick.*model',
    'exploit.*llm', 'dan mode', 'developer mode'
  ];

  private readonly ADVERSARIAL_PATTERNS = [
    /generate.*adversarial/i, /craft.*exploit/i, /create.*jailbreak/i,
    /build.*bypass/i, /find.*vulnerability.*llm/i,
    /prompt.*injection.*generator/i, /attack.*prompt/i
  ];

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (!discovery.tools || discovery.tools.length === 0) {
      return findings;
    }

    for (const tool of discovery.tools) {
      const isJailbreakTool = this.isJailbreakService(tool);

      if (isJailbreakTool) {
        findings.push({
          severity: this.severity,
          message: t('sec_055_jailbreak_service', {
            toolName: tool.name
          }),
          component: `tool:${tool.name}`,
          ruleCode: this.code,
          remediation: t('sec_055_recommendation'),
          references: [
            'OWASP LLM Top 10 - LLM01: Prompt Injection',
            'Adversarial Machine Learning Ethics',
            'AI Red Team Responsible Disclosure'
          ]
        });
      }
    }

    // Check server-level description
    if (discovery.serverInfo?.description) {
      const descLower = discovery.serverInfo.description.toLowerCase();

      const hasJailbreakKeyword = this.JAILBREAK_KEYWORDS.some(keyword => {
        const pattern = typeof keyword === 'string'
          ? new RegExp(keyword.replace(/\.\*/g, '.*'), 'i')
          : keyword;
        return pattern.test(descLower);
      });

      if (hasJailbreakKeyword) {
        findings.push({
          severity: 'critical',
          message: t('sec_055_server_jailbreak'),
          component: 'server',
          ruleCode: this.code,
          remediation: t('sec_055_server_recommendation'),
          references: [
            'OWASP LLM Top 10 - LLM01: Prompt Injection'
          ]
        });
      }
    }

    return findings;
  }

  private isJailbreakService(tool: McpTool): boolean {
    // Check name pattern
    const nameMatches = this.ADVERSARIAL_PATTERNS.some(pattern =>
      pattern.test(tool.name)
    );
    if (nameMatches) return true;

    // Check for jailbreak keywords in name
    const nameLower = tool.name.toLowerCase();
    const nameHasKeyword = this.JAILBREAK_KEYWORDS.some(keyword => {
      const pattern = typeof keyword === 'string'
        ? new RegExp(keyword.replace(/\.\*/g, '.*'), 'i')
        : keyword;
      return pattern.test(nameLower);
    });
    if (nameHasKeyword) return true;

    // Check description
    if (tool.description) {
      const descLower = tool.description.toLowerCase();

      const descMatches = this.ADVERSARIAL_PATTERNS.some(pattern =>
        pattern.test(descLower)
      );
      if (descMatches) return true;

      const descHasKeyword = this.JAILBREAK_KEYWORDS.some(keyword => {
        const pattern = typeof keyword === 'string'
          ? new RegExp(keyword.replace(/\.\*/g, '.*'), 'i')
          : keyword;
        return pattern.test(descLower);
      });
      if (descHasKeyword) return true;
    }

    return false;
  }
}
