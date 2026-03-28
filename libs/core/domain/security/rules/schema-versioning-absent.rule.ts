/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SEC-044: Schema Versioning Absent
 *
 * Block: C (Operational Security & Enterprise Compliance)
 * Severity: Medium
 * Type: Static
 *
 * Detects tools without version information in their schemas.
 * In CI/CD with multiple MCP server versions deployed simultaneously,
 * lack of versioning makes breaking change detection impossible.
 *
 * Detection:
 * - Missing version field in tool definitions
 * - Missing $schema field
 * - No version in server info
 *
 * References:
 * - Semantic Versioning 2.0.0
 * - JSON Schema versioning best practices
 */

import type { ISecurityRule } from '../rule.interface';
import type { DiscoveryResult, SecurityFinding } from '../../mcp-server/entities/validation.types';
import { t } from '@mcp-verify/shared';

export class SchemaVersioningAbsentRule implements ISecurityRule {
  code = 'SEC-044';
  name = 'Schema Versioning Absent';
  severity: 'medium' = 'medium';

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    // Check server info for version
    const hasServerVersion = discovery.serverInfo?.version !== undefined;

    if (!hasServerVersion) {
      findings.push({
        severity: this.severity,
        message: t('sec_044_no_server_version'),
        component: 'server',
        ruleCode: this.code,
        remediation: t('sec_044_recommendation')
      });
    }

    return findings;
  }
}
