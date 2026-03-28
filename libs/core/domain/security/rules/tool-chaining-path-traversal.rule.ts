/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SEC-039: Tool Chaining Path Traversal
 *
 * Block: B (Multi-Agent & Agentic Chain Attacks)
 * Severity: High
 * Type: Static + Fuzzer
 *
 * Detects tool chains where output from one tool can be manipulated to
 * perform path traversal attacks on downstream tools.
 *
 * Detection:
 * Static:
 * - Tool A outputs file paths consumed by Tool B
 * - Tool B performs file operations without path validation
 * - Missing path sanitization in tool chains
 *
 * Fuzzer:
 * - Chain tools with malicious paths (../../etc/passwd)
 *
 * References:
 * - CWE-22: Path Traversal (chained context)
 * - OWASP Path Traversal Prevention
 */

import type { ISecurityRule } from '../rule.interface';
import type { DiscoveryResult, SecurityFinding } from '../../mcp-server/entities/validation.types';
import type { McpTool } from '../../shared/common.types';
import { t } from '@mcp-verify/shared';

export class ToolChainingPathTraversalRule implements ISecurityRule {
  code = 'SEC-039';
  name = 'Tool Chaining Path Traversal';
  severity: 'high' = 'high';

  private readonly PATH_OUTPUT_PATTERNS = [
    /get.*path/i, /list.*files?/i, /find.*file/i,
    /search.*file/i, /locate/i, /resolve.*path/i,
    /get.*location/i, /fetch.*file.*path/i
  ];

  private readonly PATH_CONSUMER_PATTERNS = [
    /read.*file/i, /write.*file/i, /delete.*file/i,
    /open.*file/i, /load.*file/i, /save.*file/i,
    /move.*file/i, /copy.*file/i, /rename.*file/i
  ];

  private readonly PATH_PARAM_NAMES = [
    'path', 'file_path', 'filepath', 'filename', 'file',
    'location', 'directory', 'folder', 'dir'
  ];

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (!discovery.tools || discovery.tools.length === 0) {
      return findings;
    }

    // Find path producers and consumers
    const pathProducers = discovery.tools.filter(t => this.producesFilePaths(t));
    const pathConsumers = discovery.tools.filter(t => this.consumesFilePaths(t));

    // Check if path consumers have proper validation
    for (const consumer of pathConsumers) {
      const hasPathValidation = this.hasPathValidation(consumer);

      if (!hasPathValidation && pathProducers.length > 0) {
        findings.push({
          severity: this.severity,
          message: t('sec_039_path_traversal_chain', {
            toolName: consumer.name,
            producers: pathProducers.map(p => p.name).slice(0, 3).join(', ')
          }),
          component: `tool:${consumer.name}`,
          ruleCode: this.code,
          remediation: t('sec_039_recommendation'),
          references: [
            'CWE-22: Improper Limitation of a Pathname to a Restricted Directory',
            'OWASP Path Traversal Prevention Cheat Sheet',
            'Multi-Agent Security - Data Flow Validation'
          ]
        });
      }
    }

    return findings;
  }

  private producesFilePaths(tool: McpTool): boolean {
    // Check name pattern
    const nameMatches = this.PATH_OUTPUT_PATTERNS.some(pattern =>
      pattern.test(tool.name)
    );
    if (nameMatches) return true;

    // Check description
    if (tool.description) {
      const descLower = tool.description.toLowerCase();
      const descMatches = this.PATH_OUTPUT_PATTERNS.some(pattern =>
        pattern.test(descLower)
      );
      if (descMatches) return true;

      // Check if description mentions returning paths
      const mentionsPaths = descLower.includes('path') || descLower.includes('file') || descLower.includes('location');
      const mentionsReturn = descLower.includes('return') || descLower.includes('output') || descLower.includes('result');
      if (mentionsPaths && mentionsReturn) return true;
    }

    return false;
  }

  private consumesFilePaths(tool: McpTool): boolean {
    // Check name pattern
    const nameMatches = this.PATH_CONSUMER_PATTERNS.some(pattern =>
      pattern.test(tool.name)
    );
    if (nameMatches) return true;

    // Check for path parameters
    if (tool.inputSchema?.properties) {
      for (const propName of Object.keys(tool.inputSchema.properties)) {
        const propLower = propName.toLowerCase();
        const isPathParam = this.PATH_PARAM_NAMES.some(name =>
          propLower === name || propLower.includes(name)
        );
        if (isPathParam) return true;
      }
    }

    return false;
  }

  private hasPathValidation(tool: McpTool): boolean {
    // Check description for validation keywords
    if (tool.description) {
      const descLower = tool.description.toLowerCase();
      const validationKeywords = [
        'validate path', 'sanitize path', 'normalize path',
        'check path', 'verify path', 'whitelist', 'allowed paths',
        'path validation', 'secure path'
      ];

      const hasValidation = validationKeywords.some(keyword =>
        descLower.includes(keyword)
      );
      if (hasValidation) return true;
    }

    // Check if path parameters have pattern constraints
    if (tool.inputSchema?.properties) {
      for (const [propName, propSchema] of Object.entries(tool.inputSchema.properties)) {
        const propLower = propName.toLowerCase();
        const isPathParam = this.PATH_PARAM_NAMES.some(name =>
          propLower === name || propLower.includes(name)
        );

        if (isPathParam) {
          const schema = propSchema as {
            pattern?: string;
            format?: string;
            enum?: unknown[];
            [key: string]: unknown;
          };

          // Check for validation constraints
          const hasPattern = Boolean(schema.pattern);
          const hasFormat = schema.format === 'uri' || schema.format === 'uri-reference';
          const hasEnum = Boolean(schema.enum && schema.enum.length > 0);

          if (hasPattern || hasFormat || hasEnum) {
            return true;
          }
        }
      }
    }

    return false;
  }
}
