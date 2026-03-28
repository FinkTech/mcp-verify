/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * XML External Entity (XXE) Injection Detection Rule (SEC-005)
 *
 * Detects potential XXE injection vulnerabilities in MCP server tools.
 * XXE attacks exploit XML parsers that process external entities, allowing
 * attackers to read files, perform SSRF, or cause denial of service.
 *
 * Validates:
 * - Tools that process XML documents
 * - XML parsers without external entity disabling
 * - Lack of input validation for XML content
 * - Missing security configurations in XML processing
 *
 * @module libs/core/domain/security/rules/xxe-injection.rule
 */

import { t } from '@mcp-verify/shared';
import { ISecurityRule } from '../rule.interface';
import type { DiscoveryResult, SecurityFinding } from '../../mcp-server/entities/validation.types';
import type { McpTool, JsonValue } from '../../shared/common.types';

export class XXEInjectionRule implements ISecurityRule {
  readonly code = 'SEC-005';
  get name() { return t('sec_xxe_name'); }
  get description() { return t('sec_xxe_desc'); }
  readonly helpUri = 'https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing';
  readonly tags = ['CWE-611', 'OWASP-A05:2021', 'XXE'];

  /**
   * Keywords indicating XML processing.
   */
  private readonly XML_KEYWORDS = [
    'xml', 'parse_xml', 'process_xml', 'xml_parser', 'xmlparser',
    'xpath', 'xslt', 'dom', 'sax', 'soap', 'rss', 'atom', 'svg'
  ];

  /**
   * File extensions that indicate XML content.
   */
  private readonly XML_EXTENSIONS = [
    '.xml', '.svg', '.rss', '.atom', '.xhtml', '.soap'
  ];

  /**
   * Indicators that external entities are properly disabled.
   */
  private readonly SAFE_INDICATORS = [
    'disable external entities', 'external entities disabled',
    'no external entities', 'xxe protection', 'secure xml parser',
    'defusedxml', 'resolve_entities=false', 'external_dtd=false',
    'load_dtd=false', 'no_network=true', 'feature_external_ges=false'
  ];

  /**
   * Dangerous XML parser configurations.
   */
  private readonly DANGEROUS_CONFIGS = [
    'dtd enabled', 'external entities enabled', 'resolve entities',
    'allow dtd', 'process external'
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
    const isXMLTool = this.isXMLTool(tool.name, tool.description);

    if (!isXMLTool) {
      return findings;
    }

    const hasSafeConfig = this.hasSafeConfiguration(tool.description);
    const hasDangerousConfig = this.hasDangerousConfiguration(tool.description);

    // CRITICAL: Tool mentions dangerous XML configuration
    if (hasDangerousConfig) {
      findings.push({
        severity: 'critical',
        message: t('finding_xxe_dangerous_parser', { tool: tool.name }),
        component: `tool:${tool.name}`,
        ruleCode: this.code,
        evidence: {
          risk: t('risk_xxe_vulnerability'),
          configuration: t('risk_xxe_external_entities')
        },
        remediation: t('remediation_xxe_disable')
      });
    }

    if (!tool.inputSchema?.properties) {
      // XML tool with no schema - might accept raw XML
      if (!hasSafeConfig) {
        findings.push({
          severity: 'critical',
          message: t('finding_xxe_no_schema', { tool: tool.name }),
          component: `tool:${tool.name}`,
          ruleCode: this.code,
          evidence: {
            risk: t('risk_xxe_unvalidated'),
            reason: t('no_input_parameters_defined')
          },
          remediation: t('remediation_xxe_strict')
        });
      }
      return findings;
    }

    // Analyze parameters
    for (const [paramName, paramConfig] of Object.entries(tool.inputSchema.properties)) {
      const config = paramConfig as Record<string, JsonValue>;

      // Check for XML-related parameters
      if (this.isXMLParameter(paramName, config)) {
        // No pattern validation for XML content
        if (!config.pattern && config.type === 'string') {
          const severity = hasSafeConfig ? 'medium' : 'critical';
          findings.push({
            severity,
            message: t('finding_xxe_no_pattern', { param: paramName }),
            component: `tool:${tool.name}`,
            ruleCode: this.code,
            location: { type: 'tool', name: tool.name, parameter: paramName },
            evidence: {
              risk: t('risk_xxe_malicious_entities'),
              hasSafeConfig
            },
            remediation: hasSafeConfig
              ? t('remediation_xxe_pattern')
              : t('remediation_xxe_critical')
          });
        }

        // Check for file upload parameters with XML extensions
        if (this.isFileUploadParam(paramName, config)) {
          const acceptedExtensions = this.getAcceptedExtensions(config);
          const hasXMLExtension = acceptedExtensions.some(ext =>
            this.XML_EXTENSIONS.includes(ext.toLowerCase())
          );

          if (hasXMLExtension && !hasSafeConfig) {
            findings.push({
              severity: 'critical',
              message: t('finding_xxe_uploads', { param: paramName }),
              component: `tool:${tool.name}`,
              ruleCode: this.code,
              location: { type: 'tool', name: tool.name, parameter: paramName },
              evidence: {
                acceptedExtensions,
                risk: t('risk_xxe_uploads')
              },
              remediation: t('remediation_xxe_uploads')
            });
          }
        }

        // Check for SVG uploads (SVG is XML-based)
        if (paramName.toLowerCase().includes('svg') || paramName.toLowerCase().includes('image')) {
          if (!hasSafeConfig) {
            findings.push({
              severity: 'high',
              message: t('finding_xxe_svg', { param: paramName }),
              component: `tool:${tool.name}`,
              ruleCode: this.code,
              location: { type: 'tool', name: tool.name, parameter: paramName },
              evidence: {
                risk: t('risk_xxe_svg')
              },
              remediation: t('remediation_xxe_svg')
            });
          }
        }
      }
    }

    // Overall warning if no safe configuration mentioned
    if (!hasSafeConfig && !hasDangerousConfig) {
      findings.push({
        severity: 'high',
        message: t('finding_xxe_no_protection', { tool: tool.name }),
        component: `tool:${tool.name}`,
        ruleCode: this.code,
        evidence: {
          missingIndicators: this.SAFE_INDICATORS.slice(0, 5).join(', ')
        },
        remediation: t('update_description_to_explicitly_state_that_extern')
      });
    }

    return findings;
  }

  private isXMLTool(name: string, description?: string): boolean {
    const text = `${name} ${description || ''}`.toLowerCase();
    return this.XML_KEYWORDS.some(kw => text.includes(kw));
  }

  private hasSafeConfiguration(description?: string): boolean {
    if (!description) return false;
    const text = description.toLowerCase();
    return this.SAFE_INDICATORS.some(indicator => text.includes(indicator));
  }

  private hasDangerousConfiguration(description?: string): boolean {
    if (!description) return false;
    const text = description.toLowerCase();
    return this.DANGEROUS_CONFIGS.some(config => text.includes(config));
  }

  private isXMLParameter(name: string, config: Record<string, JsonValue>): boolean {
    const xmlParamNames = [
      'xml', 'xmldata', 'xmlcontent', 'xmldocument', 'xmlstring',
      'svg', 'rss', 'soap', 'document', 'content', 'data'
    ];

    const nameLower = name.toLowerCase();
    const descLower = (typeof config.description === 'string' ? config.description : '').toLowerCase();

    return xmlParamNames.some(xp =>
      nameLower.includes(xp) || descLower.includes('xml')
    ) || config.format === 'xml';
  }

  private isFileUploadParam(name: string, config: Record<string, JsonValue>): boolean {
    const uploadNames = ['file', 'upload', 'attachment', 'document'];
    const nameLower = name.toLowerCase();

    return uploadNames.some(un => nameLower.includes(un)) ||
      config.format === 'binary' ||
      Boolean(config.contentMediaType);
  }

  private getAcceptedExtensions(config: Record<string, JsonValue>): string[] {
    const extensions: string[] = [];

    // Check pattern for file extensions
    if (typeof config.pattern === 'string') {
      const extMatch = config.pattern.match(/\.(xml|svg|rss|atom|xhtml)/gi);
      if (extMatch) {
        extensions.push(...extMatch);
      }
    }

    // Check description
    if (typeof config.description === 'string') {
      const descMatch = config.description.match(/\.(xml|svg|rss|atom|xhtml)/gi);
      if (descMatch) {
        extensions.push(...descMatch);
      }
    }

    return extensions;
  }
}
