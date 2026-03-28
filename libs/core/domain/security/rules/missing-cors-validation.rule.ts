/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SEC-046: Missing CORS / Origin Validation (HTTP Transport)
 *
 * Block: C (Operational Security & Enterprise Compliance)
 * Severity: High
 * Type: Static
 *
 * Detects MCP servers over HTTP/SSE without origin validation.
 * Allows CSRF attacks where malicious web pages make requests to local MCP server.
 *
 * Detection:
 * - HTTP/SSE transport without origin checks mentioned in serverInfo
 * - This is STATIC ONLY - actual CORS testing requires fuzzer
 *
 * References:
 * - OWASP CSRF Cheat Sheet
 * - CWE-352: Cross-Site Request Forgery
 */

import type { ISecurityRule } from '../rule.interface';
import type { DiscoveryResult, SecurityFinding } from '../../mcp-server/entities/validation.types';
import { t } from '@mcp-verify/shared';

export class MissingCorsValidationRule implements ISecurityRule {
  code = 'SEC-046';
  name = 'Missing CORS / Origin Validation';
  severity: 'high' = 'high';

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    // Note: This is a placeholder for HTTP transport detection
    // Actual CORS validation requires fuzzer to send Origin headers
    // For now, we check if server mentions CORS in description

    if (discovery.serverInfo?.description) {
      const descLower = discovery.serverInfo.description.toLowerCase();
      const mentionsCors = descLower.includes('cors') || descLower.includes('origin');

      if (!mentionsCors) {
        // Conservative: only flag if server explicitly uses HTTP/network
        const mentionsHttp = descLower.includes('http') || descLower.includes('sse');

        if (mentionsHttp) {
          findings.push({
            severity: 'medium', // Lowered since this is heuristic
            message: t('sec_046_no_cors_mention'),
            component: 'server',
            ruleCode: this.code,
            remediation: t('sec_046_recommendation')
          });
        }
      }
    }

    return findings;
  }
}
