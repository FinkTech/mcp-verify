/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Excessive Tool Permissions Detection Rule (SEC-017)
 *
 * Detects tools that suggest overprivileged access or violation of the
 * principle of least privilege. Tools with administrative, root, or
 * unrestricted access pose significant security risks.
 *
 * Validates:
 * - Tools with administrative or root-level access
 * - Unrestricted or full_access permissions
 * - System-wide modification capabilities
 * - Database-level destructive operations
 * - Bypass or override mechanisms
 *
 * Attack vectors:
 * - Privilege escalation through overprivileged tools
 * - Unauthorized system modifications
 * - Data destruction via administrative tools
 * - Security control bypass
 *
 * @module libs/core/domain/security/rules/excessive-permissions.rule
 */

import { t } from '@mcp-verify/shared';
import { ISecurityRule } from '../rule.interface';
import type { DiscoveryResult, SecurityFinding } from '../../mcp-server/entities/validation.types';
import type { McpTool } from '../../shared/common.types';

export class ExcessivePermissionsRule implements ISecurityRule {
  readonly code = 'SEC-017';
  get name() { return t('sec_excessive_perms_name'); }
  get description() { return t('sec_excessive_perms_desc'); }
  readonly helpUri = 'https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control';
  readonly tags = ['CWE-250', 'CWE-269', 'OWASP-A01:2021', 'Least Privilege Violation'];

  /**
   * Critical keywords indicating dangerous administrative access
   */
  private readonly CRITICAL_KEYWORDS = {
    root: { weight: 10, category: 'administrative' },
    admin: { weight: 8, category: 'administrative' },
    superuser: { weight: 10, category: 'administrative' },
    sudo: { weight: 10, category: 'administrative' },
    elevated: { weight: 7, category: 'administrative' },

    full_access: { weight: 9, category: 'unrestricted' },
    unrestricted: { weight: 9, category: 'unrestricted' },
    bypass: { weight: 8, category: 'unrestricted' },
    override: { weight: 7, category: 'unrestricted' },

    system_wide: { weight: 8, category: 'scope' },
    global: { weight: 6, category: 'scope' },
    all_users: { weight: 7, category: 'scope' },

    database_drop: { weight: 10, category: 'destructive' },
    truncate: { weight: 9, category: 'destructive' },
    delete_all: { weight: 9, category: 'destructive' },
    purge: { weight: 8, category: 'destructive' },

    execute_all: { weight: 9, category: 'execution' },
    exec_any: { weight: 9, category: 'execution' },
    run_any: { weight: 8, category: 'execution' },
  };

  /**
   * High-risk keywords
   */
  private readonly HIGH_RISK_KEYWORDS = {
    privileged: { weight: 6, category: 'administrative' },
    administrator: { weight: 6, category: 'administrative' },

    manage_all: { weight: 6, category: 'scope' },
    modify_all: { weight: 6, category: 'scope' },

    system_config: { weight: 5, category: 'configuration' },
    kernel: { weight: 7, category: 'system' },

    drop_database: { weight: 8, category: 'destructive' },
    format: { weight: 8, category: 'destructive' },
  };

  /**
   * Medium-risk keywords
   */
  private readonly MEDIUM_RISK_KEYWORDS = {
    configure: { weight: 3, category: 'configuration' },
    settings: { weight: 2, category: 'configuration' },
    permissions: { weight: 4, category: 'administrative' },
    access_control: { weight: 4, category: 'administrative' },
  };

  /**
   * Patterns that suggest administrative tools
   */
  private readonly ADMIN_PATTERNS = [
    /admin[_-]?panel/i,
    /admin[_-]?console/i,
    /super[_-]?admin/i,
    /root[_-]?access/i,
    /manage[_-]?all/i,
    /system[_-]?admin/i,
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

    const text = `${tool.name} ${tool.description || ''}`.toLowerCase();
    const detectedKeywords: string[] = [];
    let riskScore = 0;
    const categories = new Set<string>();

    // Check critical keywords
    for (const [keyword, { weight, category }] of Object.entries(this.CRITICAL_KEYWORDS)) {
      if (text.includes(keyword)) {
        detectedKeywords.push(keyword);
        riskScore += weight;
        categories.add(category);
      }
    }

    // Check high-risk keywords
    for (const [keyword, { weight, category }] of Object.entries(this.HIGH_RISK_KEYWORDS)) {
      if (text.includes(keyword)) {
        detectedKeywords.push(keyword);
        riskScore += weight;
        categories.add(category);
      }
    }

    // Check medium-risk keywords
    for (const [keyword, { weight, category }] of Object.entries(this.MEDIUM_RISK_KEYWORDS)) {
      if (text.includes(keyword)) {
        detectedKeywords.push(keyword);
        riskScore += weight;
        categories.add(category);
      }
    }

    // Check admin patterns
    const matchedPatterns = this.ADMIN_PATTERNS.filter(pattern => pattern.test(text));
    if (matchedPatterns.length > 0) {
      riskScore += matchedPatterns.length * 5;
      categories.add('administrative');
    }

    // Determine severity based on score
    let severity: 'critical' | 'high' | 'medium' | 'low' = 'low';
    if (riskScore >= 15) {
      severity = 'critical';
    } else if (riskScore >= 10) {
      severity = 'high';
    } else if (riskScore >= 5) {
      severity = 'medium';
    }

    // Only report if there are findings
    if (detectedKeywords.length > 0 || matchedPatterns.length > 0) {
      findings.push({
        severity,
        message: t('finding_excessive_perms_detected', {
          tool: tool.name,
          score: riskScore
        }),
        component: `tool:${tool.name}`,
        ruleCode: this.code,
        location: { type: 'tool', name: tool.name },
        evidence: {
          riskScore,
          detectedKeywords: detectedKeywords.slice(0, 5), // Top 5
          categories: Array.from(categories),
          adminPatterns: matchedPatterns.length > 0,
          risk: t('risk_excessive_perms_privilege_escalation')
        },
        remediation: t('remediation_excessive_perms_least_privilege')
      });
    }

    // Special check: Tools that combine multiple dangerous categories
    if (categories.has('destructive') && categories.has('unrestricted')) {
      findings.push({
        severity: 'critical',
        message: t('finding_excessive_perms_destructive_unrestricted', { tool: tool.name }),
        component: `tool:${tool.name}`,
        ruleCode: this.code,
        location: { type: 'tool', name: tool.name },
        evidence: {
          categories: Array.from(categories),
          risk: t('risk_excessive_perms_data_loss')
        },
        remediation: t('remediation_excessive_perms_split_permissions')
      });
    }

    // Check for tools with "all" or "any" in parameter names (overly permissive inputs)
    if (tool.inputSchema?.properties) {
      for (const [paramName] of Object.entries(tool.inputSchema.properties)) {
        if (/\b(all|any)\b/i.test(paramName)) {
          findings.push({
            severity: 'medium',
            message: t('finding_excessive_perms_param_all', {
              param: paramName,
              tool: tool.name
            }),
            component: `tool:${tool.name}`,
            ruleCode: this.code,
            location: { type: 'tool', name: tool.name, parameter: paramName },
            remediation: t('remediation_excessive_perms_specific_params')
          });
        }
      }
    }

    return findings;
  }
}
