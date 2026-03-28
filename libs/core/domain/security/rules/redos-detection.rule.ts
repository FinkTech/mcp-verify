/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Regular Expression Denial of Service (ReDoS) Detection Rule (SEC-011)
 *
 * Detects regex patterns vulnerable to catastrophic backtracking that can
 * cause denial of service through exponential time complexity.
 *
 * Validates:
 * - Regex patterns with nested quantifiers
 * - Overlapping alternations
 * - Patterns susceptible to catastrophic backtracking
 * - Missing anchors that allow partial matching abuse
 *
 * @module libs/core/domain/security/rules/redos-detection.rule
 */

import { t } from '@mcp-verify/shared';
import { ISecurityRule } from '../rule.interface';
import type { DiscoveryResult, SecurityFinding } from '../../mcp-server/entities/validation.types';
import type { McpTool, JsonValue } from '../../shared/common.types';

export class ReDoSDetectionRule implements ISecurityRule {
  readonly code = 'SEC-011';
  get name() { return t('sec_redos_name'); }
  get description() { return t('sec_redos_desc'); }
  readonly helpUri = 'https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS';
  readonly tags = ['CWE-1333', 'OWASP-A05:2021', 'ReDoS'];

  /**
   * Dangerous regex patterns that indicate potential ReDoS.
   */
  private readonly DANGEROUS_PATTERNS = [
    // Nested quantifiers: (a+)+, (a*)*, (a+)*
    /\([^)]*[+*]\)[+*]/,

    // Overlapping alternations: (a|a)+, (a|ab)+
    /\([^)]*\|[^)]*\)[+*]/,

    // Multiple consecutive quantifiers: a++, a**
    /[+*]{2,}/,

    // Nested groups with quantifiers: ((a+)+)+
    /\(\([^)]*[+*]\)[+*]\)/
  ];

  /**
   * Safe regex indicators.
   */
  private readonly SAFE_INDICATORS = [
    // Anchored patterns
    /^\^.*\$$/,

    // Character classes without quantifiers
    /^\[[^\]]+\]$/,

    // Simple literal strings
    /^[a-zA-Z0-9_-]+$/
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

    if (!tool.inputSchema?.properties) {
      return findings;
    }

    // Analyze each parameter
    for (const [paramName, paramConfig] of Object.entries(tool.inputSchema.properties)) {
      const config = paramConfig as Record<string, JsonValue>;

      // Check pattern property
      if (typeof config.pattern === 'string') {
        const vulnerabilities = this.analyzeRegexPattern(config.pattern);

        if (vulnerabilities.length > 0) {
          findings.push({
            severity: 'medium',
            message: t('finding_redos_vulnerable', { param: paramName }),
            component: `tool:${tool.name}`,
            ruleCode: this.code,
            location: { type: 'tool', name: tool.name, parameter: paramName },
            evidence: {
              pattern: config.pattern,
              vulnerabilities: vulnerabilities,
              risk: t('risk_redos_evaluation')
            },
            remediation: t('remediation_redos_simplify')
          });
        }

        // Check for missing anchors
        if (!this.hasProperAnchors(config.pattern)) {
          findings.push({
            severity: 'low',
            message: t('finding_redos_no_anchors', { param: paramName }),
            component: `tool:${tool.name}`,
            ruleCode: this.code,
            location: { type: 'tool', name: tool.name, parameter: paramName },
            evidence: {
              pattern: config.pattern,
              risk: t('risk_redos_partial')
            },
            remediation: t('remediation_redos_anchors')
          });
        }
      }
    }

    return findings;
  }

  private analyzeRegexPattern(pattern: string): string[] {
    const vulnerabilities: string[] = [];

    try {
      // Test for dangerous patterns
      for (const dangerousPattern of this.DANGEROUS_PATTERNS) {
        if (dangerousPattern.test(pattern)) {
          vulnerabilities.push(this.getVulnerabilityType(dangerousPattern, pattern));
        }
      }

      // Check for specific anti-patterns
      if (this.hasNestedQuantifiers(pattern)) {
        vulnerabilities.push(t('nested_quantifiers_detected_eg_a'));
      }

      if (this.hasOverlappingAlternation(pattern)) {
        vulnerabilities.push(t('overlapping_alternation_detected_eg_aab'));
      }

      if (this.hasExcessiveBacktracking(pattern)) {
        vulnerabilities.push(t('potential_excessive_backtracking'));
      }

    } catch (e) {
      // Invalid regex itself is a problem
      vulnerabilities.push(t('invalid_regex_pattern'));
    }

    return vulnerabilities;
  }

  private getVulnerabilityType(dangerousPattern: RegExp, _userPattern: string): string {
    const patternStr = dangerousPattern.toString();

    if (patternStr.includes('[+*]{2,}')) {
      return t('multiple_consecutive_quantifiers');
    }
    if (patternStr.includes('\\(\\([^)]*[+*]\\)[+*]\\)')) {
      return t('deeply_nested_quantifiers');
    }
    if (patternStr.includes('\\([^)]*\\|[^)]*\\)[+*]')) {
      return t('potentially_dangerous_pattern'); // Use a generic key or map better
    }
    if (patternStr.includes('\\([^)]*[+*]\\)[+*]')) {
      return t('nested_quantifiers_detected_eg_a');
    }

    return t('potentially_dangerous_pattern');
  }

  private hasNestedQuantifiers(pattern: string): boolean {
    // Simplified check for patterns like (a+)+, (a*)+, etc.
    const nestedQuantifierPatterns = [
      /\([^)]*\+\)\+/,  // (a+)+
      /\([^)]*\*\)\*/,  // (a*)*
      /\([^)]*\+\)\*/,  // (a+)*
      /\([^)]*\*\)\+/   // (a*)+
    ];

    return nestedQuantifierPatterns.some(p => p.test(pattern));
  }

  private hasOverlappingAlternation(pattern: string): boolean {
    // Check for patterns like (a|ab)+, (abc|abcd)+
    // This is a simplified heuristic
    const alternations = pattern.match(/\([^)]*\|[^)]*\)/g);

    if (!alternations) return false;

    for (const alt of alternations) {
      const parts = alt.slice(1, -1).split('|');

      // Check if any part is a prefix of another
      for (let i = 0; i < parts.length; i++) {
        for (let j = i + 1; j < parts.length; j++) {
          if (parts[i].startsWith(parts[j]) || parts[j].startsWith(parts[i])) {
            return true;
          }
        }
      }
    }

    return false;
  }

  private hasExcessiveBacktracking(pattern: string): boolean {
    // Heuristic: count quantifiers and groups
    const quantifiers = (pattern.match(/[+*?]/g) || []).length;
    const groups = (pattern.match(/\(/g) || []).length;

    // If there are multiple quantifiers in nested groups, it's risky
    return quantifiers > 3 && groups > 2;
  }

  private hasProperAnchors(pattern: string): boolean {
    // Check if pattern starts with ^ and ends with $
    return pattern.startsWith('^') && pattern.endsWith('$');
  }

  private getRemediationAdvice(vulnerabilities: string[], pattern: string): string {
    const advice: string[] = [
      'Remediation steps:',
      '1. Simplify regex pattern to avoid nested quantifiers',
      '2. Use atomic groups or possessive quantifiers if supported',
      '3. Consider using simpler validation (character classes, length limits)',
      '4. Add timeout limits for regex evaluation',
      '5. Test regex with ReDoS checker tools (e.g., regex101.com with debugger)'
    ];

    if (vulnerabilities.some(v => v.includes('Nested quantifiers'))) {
      advice.push('\nSpecific fix for nested quantifiers:');
      advice.push('- Replace (a+)+ with a+');
      advice.push('- Replace (a*)* with a*');
      advice.push('- Use character classes instead: [a]+ instead of (a+)+');
    }

    if (vulnerabilities.some(v => v.includes('alternation'))) {
      advice.push('\nSpecific fix for overlapping alternation:');
      advice.push('- Reorder alternatives from longest to shortest');
      advice.push('- Remove redundant alternatives');
      advice.push('- Example: (abc|abcd)+ → (abcd|abc)+ or just abcd*');
    }

    return advice.join('\n');
  }
}
