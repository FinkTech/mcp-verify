/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import { t } from '@mcp-verify/shared';
import type { Report, SecurityFinding } from '../mcp-server/entities/validation.types';
import type { Language } from './i18n';

/**
 * Generates SARIF (Static Analysis Results Interchange Format) reports.
 * Compatible with GitHub Security Scanning, GitLab, VS Code, etc.
 */
export class SarifGenerator {
  static generate(report: Report, lang: Language = 'en'): string {
    // Build the run object
    const run: Record<string, unknown> = {
      tool: {
        driver: {
          name: "mcp-verify",
          informationUri: "https://github.com/FinkTech/mcp-verify",
          version: "1.0.0",
          rules: this.extractRules(report, lang)
        }
      },
      results: report.security.findings.map(finding => this.mapFindingToResult(finding))
    };

    // Add versionControlProvenance if git info is available
    // This enables GitHub Code Scanning to map findings to source code
    if (report.gitInfo) {
      run.versionControlProvenance = [
        {
          repositoryUri: report.gitInfo.repositoryUri,
          revisionId: report.gitInfo.revisionId,
          branch: report.gitInfo.branch
        }
      ];
    }

    const sarif = {
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      version: "2.1.0",
      runs: [run]
    };

    return JSON.stringify(sarif, null, 2);
  }

  private static mapFindingToResult(finding: SecurityFinding) {
    return {
      ruleId: finding.ruleCode || 'MCP-UNKNOWN',
      level: this.mapSeverityToLevel(finding.severity),
      message: {
        text: finding.message
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: finding.location?.uri || finding.component || "mcp-server"
            },
            region: {
              startLine: 1 // We don't have line numbers for dynamic analysis, defaulting to 1
            }
          }
        }
      ],
      properties: {
        evidence: finding.evidence,
        remediation: finding.remediation
      }
    };
  }

  private static mapSeverityToLevel(severity: string): string {
    switch (severity) {
      case 'critical':
      case 'high':
        return 'error';
      case 'medium':
        return 'warning';
      case 'low':
        return 'note';
      default:
        return 'none';
    }
  }

  private static extractRules(report: Report, lang: Language = 'en') {
    // Unique rules found in the report
    const usedRules = new Set(report.security.findings.map(f => f.ruleCode));
    
    const baseUrl = `https://github.com/FinkTech/mcp-security/blob/main/docs/pdf/${lang}/`;
    
    // Detailed rule definitions for better SARIF integration (e.g. GitHub Code Scanning)
    const allRules = [
      { 
        id: 'SEC-001', 
        name: t('sec_auth_bypass_name', undefined, lang), 
        shortDescription: { text: t('sec_auth_bypass_desc', undefined, lang) },
        helpUri: baseUrl + 'SEC-001-Authentication.pdf',
        properties: { 
          tags: ['security', 'mcp', 'external/owasp/a07', 'CWE-287'],
          precision: 'high'
        }
      },
      { 
        id: 'SEC-002', 
        name: t('sec_command_injection_name', undefined, lang), 
        shortDescription: { text: t('sec_command_injection_desc', undefined, lang) },
        helpUri: baseUrl + 'SEC-002-CommandInject.pdf',
        properties: { 
          tags: ['security', 'mcp', 'external/owasp/a03', 'CWE-78'],
          precision: 'very-high'
        }
      },
      { 
        id: 'SEC-003', 
        name: t('sec_sql_injection_name', undefined, lang), 
        shortDescription: { text: t('sec_sql_injection_desc', undefined, lang) },
        helpUri: baseUrl + 'SEC-003-SQLInjection.pdf',
        properties: { 
          tags: ['security', 'mcp', 'external/owasp/a03', 'CWE-89'],
          precision: 'very-high'
        }
      },
      { 
        id: 'SEC-004', 
        name: t('sec_ssrf_name', undefined, lang), 
        shortDescription: { text: t('sec_ssrf_desc', undefined, lang) },
        helpUri: baseUrl + 'SEC-004-SSRF.pdf',
        properties: { 
          tags: ['security', 'mcp', 'external/owasp/a10', 'CWE-918'],
          precision: 'high'
        }
      },
      { 
        id: 'SEC-005', 
        name: t('sec_xxe_name', undefined, lang), 
        shortDescription: { text: t('sec_xxe_desc', undefined, lang) },
        helpUri: baseUrl + 'SEC-005-XXE.pdf',
        properties: { 
          tags: ['security', 'mcp', 'external/owasp/a05', 'CWE-611'],
          precision: 'high'
        }
      },
      { 
        id: 'SEC-006', 
        name: t('sec_insecure_deserialization_name', undefined, lang), 
        shortDescription: { text: t('sec_insecure_deserialization_desc', undefined, lang) },
        helpUri: baseUrl + 'SEC-006-Deserializat.pdf',
        properties: { 
          tags: ['security', 'mcp', 'external/owasp/a08', 'CWE-502'],
          precision: 'high'
        }
      },
      { 
        id: 'SEC-007', 
        name: t('sec_path_traversal_name', undefined, lang), 
        shortDescription: { text: t('sec_path_traversal_desc', undefined, lang) },
        helpUri: baseUrl + 'SEC-007-PathTraversal.pdf',
        properties: { 
          tags: ['security', 'mcp', 'external/owasp/a01', 'CWE-22'],
          precision: 'very-high'
        }
      },
      { 
        id: 'SEC-008', 
        name: t('sec_data_leakage_name', undefined, lang), 
        shortDescription: { text: t('sec_data_leakage_desc', undefined, lang) },
        helpUri: baseUrl + 'SEC-008-DataLeakage.pdf',
        properties: { 
          tags: ['security', 'mcp', 'data-privacy', 'CWE-200'],
          precision: 'medium'
        }
      },
      { 
        id: 'SEC-009', 
        name: t('sec_sensitive_exposure_name', undefined, lang), 
        shortDescription: { text: t('sec_sensitive_exposure_desc', undefined, lang) },
        helpUri: baseUrl + 'SEC-009-SensDataExp.pdf',
        properties: { 
          tags: ['security', 'mcp', 'external/owasp/a02', 'CWE-312'],
          precision: 'high'
        }
      },
      { 
        id: 'SEC-010', 
        name: t('sec_rate_limiting_name', undefined, lang), 
        shortDescription: { text: t('sec_rate_limiting_desc', undefined, lang) },
        helpUri: baseUrl + 'SEC-010-RateLimiting.pdf',
        properties: { 
          tags: ['security', 'mcp', 'availability', 'CWE-770'],
          precision: 'medium'
        }
      },
      { 
        id: 'SEC-011', 
        name: t('sec_redos_name', undefined, lang), 
        shortDescription: { text: t('sec_redos_desc', undefined, lang) },
        helpUri: baseUrl + 'SEC-011-ReDoS.pdf',
        properties: { 
          tags: ['security', 'mcp', 'availability', 'CWE-1333'],
          precision: 'medium'
        }
      },
      { 
        id: 'SEC-012', 
        name: t('sec_weak_crypto_name', undefined, lang), 
        shortDescription: { text: t('sec_weak_crypto_desc', undefined, lang) },
        helpUri: baseUrl + 'SEC-012-WeakCrypto.pdf',
        properties: { 
          tags: ['security', 'mcp', 'external/owasp/a02', 'CWE-327'],
          precision: 'high'
        }
      }
    ];

    return allRules.filter(r => usedRules.has(r.id));
  }
}
