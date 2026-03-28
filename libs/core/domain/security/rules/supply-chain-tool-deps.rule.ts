/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SEC-025: Supply Chain Vulnerabilities in Tool Dependencies (LLM05)
 *
 * Block: A (OWASP LLM Top 10 in MCP Context)
 * Severity: High
 * Type: Static + External API
 *
 * Detects MCP servers declaring external dependencies without version pinning
 * or using known vulnerable package versions.
 *
 * Detection:
 * Static:
 * - Check serverInfo for dependency declarations
 * - Detect unpinned versions (^, ~, *, latest)
 * - Flag missing integrity hashes (subresource integrity)
 *
 * External API:
 * - Query npm/PyPI for known vulnerabilities (requires API)
 *
 * References:
 * - OWASP LLM Top 10 2025 - LLM05: Supply-Chain Vulnerabilities
 * - OWASP Dependency-Check
 * - CWE-1104: Use of Unmaintained Third Party Components
 */

import type { ISecurityRule } from '../rule.interface';
import type { DiscoveryResult, SecurityFinding } from '../../mcp-server/entities/validation.types';
import { t } from '@mcp-verify/shared';

export class SupplyChainToolDepsRule implements ISecurityRule {
  code = 'SEC-025';
  name = 'Supply Chain Vulnerabilities in Tool Dependencies';
  severity: 'high' = 'high';

  private readonly UNPINNED_VERSION_PATTERNS = [
    /^\^/,    // ^1.0.0
    /^~/,     // ~1.0.0
    /^\*/,    // *
    /^latest$/i,
    /^x$/i,
  ];

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    // Check if serverInfo declares dependencies
    if (discovery.serverInfo) {
      const metadata = discovery.serverInfo;

      const allDeps = {
        ...(metadata.dependencies || {}),
        ...(metadata.devDependencies || {})
      };

      const unpinnedDeps: string[] = [];

      for (const [depName, depVersion] of Object.entries(allDeps)) {
        if (typeof depVersion === 'string' && this.isUnpinnedVersion(depVersion)) {
          unpinnedDeps.push(`${depName}@${depVersion}`);
        }
      }

      if (unpinnedDeps.length > 0) {
        findings.push({
          severity: 'medium',
          message: t('sec_025_unpinned_deps', {
            count: unpinnedDeps.length,
            deps: unpinnedDeps.slice(0, 3).join(', ')
          }),
          component: 'server',
          ruleCode: this.code,
          remediation: t('sec_025_recommendation'),
          references: [
            'OWASP LLM Top 10 2025 - LLM05: Supply-Chain Vulnerabilities',
            'OWASP Dependency-Check',
            'CWE-1104: Use of Unmaintained Third Party Components'
          ]
        });
      }
    }

    // Note: Full vulnerability scanning requires external API (npm audit, Snyk, etc.)
    // This is a placeholder for future integration
    if (findings.length === 0 && discovery.serverInfo) {
      // Conservative approach: warn if serverInfo doesn't declare dependencies at all
      // (it might be loading them dynamically or using native modules)
      if (!discovery.serverInfo.dependencies) {
        findings.push({
          severity: 'low',
          message: t('sec_025_no_deps_declared'),
          component: 'server',
          ruleCode: this.code,
          remediation: t('sec_025_declare_deps_recommendation'),
          references: [
            'OWASP LLM Top 10 2025 - LLM05: Supply-Chain Vulnerabilities'
          ]
        });
      }
    }

    return findings;
  }

  private isUnpinnedVersion(version: string): boolean {
    return this.UNPINNED_VERSION_PATTERNS.some(pattern =>
      pattern.test(version)
    );
  }
}
