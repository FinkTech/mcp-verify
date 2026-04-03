/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SEC-045: Insufficient Error Granularity
 *
 * Block: C (Operational Security & Enterprise Compliance)
 * Severity: Medium
 * Type: Fuzzer (requires runtime testing)
 *
 * Detects errors that are either:
 * (a) Too verbose - exposing stack traces, paths, versions
 * (b) Too generic - only error codes without messages
 *
 * Both extremes are problematic for agents making decisions based on errors.
 *
 * Detection:
 * - Requires fuzzer to send malformed inputs and analyze error responses
 * - This is a PLACEHOLDER for static analysis
 *
 * References:
 * - OWASP Error Handling Cheat Sheet
 * - CWE-209: Information Exposure Through Error Messages
 */

import type { ISecurityRule } from '../rule.interface';
import type { DiscoveryResult, SecurityFinding } from '../../mcp-server/entities/validation.types';

export class InsufficientErrorGranularityRule implements ISecurityRule {
  code = 'SEC-045';
  name = 'Insufficient Error Granularity';
  severity: 'medium' = 'medium';

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (!discovery.tools || discovery.tools.length === 0) {
      return findings;
    }

    // Keywords indicating verbose error messages that reveal implementation details
    const VERBOSE_ERROR_KEYWORDS = [
      'database error',
      'stack trace',
      'line',
      'file path',
      'sql error',
      'exception',
      'implementation details',
      'detalles de implementación',
      'error at line',
      'error en línea'
    ];

    // Keywords indicating too generic errors
    const GENERIC_ERROR_KEYWORDS = [
      'generic error',
      'error code only',
      'no message',
      'error genérico',
      'solo código'
    ];

    for (const tool of discovery.tools) {
      const toolText = `${tool.name} ${tool.description || ''}`.toLowerCase();

      // Check for verbose errors
      const hasVerboseErrors = VERBOSE_ERROR_KEYWORDS.some(kw => toolText.includes(kw));

      if (hasVerboseErrors) {
        findings.push({
          ruleCode: this.code,
          severity: 'medium',
          message: `Tool "${tool.name}" may expose implementation details in error messages`,
          component: `tool:${tool.name}`,
          location: { type: 'tool', name: tool.name },
          evidence: {
            risk: 'Verbose errors reveal internal paths, versions, and system architecture to attackers',
            detectedPattern: 'Error messages revealing implementation details'
          },
          remediation: 'Use generic error messages for users, log detailed errors server-side only'
        });
      }

      // Check for too generic errors
      const hasGenericErrors = GENERIC_ERROR_KEYWORDS.some(kw => toolText.includes(kw));

      if (hasGenericErrors) {
        findings.push({
          ruleCode: this.code,
          severity: 'low',
          message: `Tool "${tool.name}" may use overly generic error messages`,
          component: `tool:${tool.name}`,
          location: { type: 'tool', name: tool.name },
          evidence: {
            risk: 'Too generic errors make debugging impossible for legitimate users',
            detectedPattern: 'Error codes without explanatory messages'
          },
          remediation: 'Balance between security and usability - provide meaningful but safe error messages'
        });
      }
    }

    return findings;
  }
}
