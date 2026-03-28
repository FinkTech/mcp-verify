/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Path Traversal Detection Rule (SEC-007)
 *
 * Detects potential path traversal vulnerabilities in MCP server tools and resources.
 *
 * Validates:
 * - Tool parameters that accept file paths without proper validation
 * - Weak regex patterns that don't block directory traversal sequences
 * - Dynamic resource URIs with dangerous wildcards
 *
 * @module libs/core/domain/security/rules/path-traversal.rule
 */

import { t, compileRegexSafe, isSafePattern } from '@mcp-verify/shared';
import { ISecurityRule } from '../rule.interface';
import type { DiscoveryResult, SecurityFinding } from '../../mcp-server/entities/validation.types';
import type { McpTool, McpResource, JsonValue } from '../../shared/common.types';

/**
 * Path Traversal security rule implementation.
 *
 * Analyzes MCP server discovery data for path traversal vulnerabilities
 * in file operations, resource URIs, and tool parameters.
 */
export class PathTraversalRule implements ISecurityRule {
  readonly code = 'SEC-007';
  get name() { return t('sec_path_traversal_name'); }
  get description() { return t('sec_path_traversal_desc'); }
  readonly helpUri = 'https://owasp.org/www-community/attacks/Path_Traversal';
  readonly tags = ['CWE-22', 'OWASP-A01:2021', 'Local File Inclusion'];

  /**
   * Dangerous path traversal patterns that should be blocked.
   * These patterns represent common directory traversal attack vectors.
   */
  private readonly TRAVERSAL_PATTERNS = [
    /\.\.[\/\\]/,           // Basic ../ or ..\
    /%2e%2e[%2f%5c]/i,      // URL-encoded ../ or ..\
    /\.\.[\/\\]\.\.[\/\\]/, // Multiple traversal sequences
    /[\/\\]etc[\/\\]/,      // Unix system paths
    /[\/\\]var[\/\\]/,      // Unix var directory
    /[\/\\]home[\/\\]/,     // Unix home directories
    /C:\\?\?[Ww]indows/,    // Windows system paths
    /C:\\?\?[Uu]sers/,      // Windows user directories
    /\\\\?\?["\/\\]/,      // UNC paths
  ];

  /**
   * Keywords in parameter names/descriptions that indicate file path parameters.
   */
  private readonly PATH_INDICATORS = [
    'path',
    'file',
    'filename',
    'filepath',
    'directory',
    'dir',
    'folder',
    'location',
  ];

  /**
   * Evaluates the MCP server for path traversal vulnerabilities.
   * 
   * @param discovery - Complete MCP server discovery data
   * @returns Array of security findings (empty if no issues found)
   */
  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    // Analyze tools for path traversal risks
    if (discovery.tools) {
      for (const tool of discovery.tools) {
        findings.push(...this.analyzeToolParameters(tool));
      }
    }

    // Analyze resources for dangerous URI patterns
    if (discovery.resources) {
      for (const resource of discovery.resources) {
        findings.push(...this.analyzeResourceURI(resource));
      }
    }

    return findings;
  }

  /**
   * Analyzes a tool's input schema for path traversal vulnerabilities.
   * 
   * @param tool - MCP tool definition
   * @returns Array of findings for this tool
   */
  private analyzeToolParameters(tool: McpTool): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    // Check if tool has input schema
    if (!tool.inputSchema?.properties) {
      return findings;
    }

    const properties = tool.inputSchema.properties;

    // Analyze each parameter
    for (const [paramName, paramConfig] of Object.entries(properties)) {
      const config = paramConfig as Record<string, JsonValue>;

      // Check if this parameter looks like a file path
      if (!this.isPathParameter(paramName, config)) {
        continue;
      }

      // CRITICAL: Path parameter without any validation pattern
      if (!config.pattern) {
        findings.push({
          severity: 'high',
          message: t('finding_path_traversal_no_pattern', { tool: tool.name, param: paramName }),
          component: `tool:${tool.name}`,
          ruleCode: this.code,
          location: {
            type: 'tool',
            name: tool.name,
            parameter: paramName,
          },
          evidence: {
            toolName: tool.name,
            parameterName: paramName,
            parameterType: config.type,
            description: config.description || t('no_description'),
            hasPattern: false,
          },
          remediation: t('remediation_path_traversal_add_pattern', { param: paramName }),
        });
        continue;
      }

      // CRITICAL: Path parameter with weak validation pattern
      // Type guard: pattern must be a string to be validated
      if (typeof config.pattern !== 'string') {
        continue;
      }
      const weaknessResult = this.isWeakPattern(config.pattern);
      if (weaknessResult.isWeak) {
        findings.push({
          severity: 'critical',
          message: t('finding_path_traversal_weak_pattern', { tool: tool.name, param: paramName }),
          component: `tool:${tool.name}`,
          ruleCode: this.code,
          location: {
            type: 'tool',
            name: tool.name,
            parameter: paramName,
          },
          evidence: {
            toolName: tool.name,
            parameterName: paramName,
            currentPattern: config.pattern,
            allowsTraversal: weaknessResult.matchedPatterns,
            testInput: weaknessResult.dangerousInput ?? '',
          },
          remediation: t('remediation_path_traversal_weak_pattern', { pattern: config.pattern }),
        });
      }
    }

    return findings;
  }

  /**
   * Analyzes a resource URI for path traversal risks.
   * 
   * @param resource - MCP resource definition
   * @returns Array of findings for this resource
   */
  private analyzeResourceURI(resource: McpResource): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const uri = resource.uri || '';

    // Check for dynamic URI templates (variables or wildcards)
    const hasDynamicSegments = this.hasDynamicURI(uri);

    if (!hasDynamicSegments) {
      return findings; // Static URIs without dynamic segments are safe from path traversal
    }

    // 1. Check for dangerous URIs with dynamic segments (e.g., direct system file access with user input)
    for (const pattern of this.TRAVERSAL_PATTERNS) {
      if (pattern.test(uri)) {
        findings.push({
          severity: 'critical',
          message: t('finding_path_traversal_static_uri', { resource: resource.name || t('unknown'), uri }),
          component: `resource:${resource.name || t('unknown')}`,
          ruleCode: this.code,
          location: {
            type: 'resource',
            uri: resource.uri,
            name: resource.name,
          },
          evidence: {
            resourceName: resource.name || t('unknown'),
            uri: resource.uri,
            matchedPattern: pattern.toString(),
            risk: t('static_resource_points_to_sensitive_system_path'),
          },
          remediation: t('avoid_exposing_sensitive_system_files_as_static_re'),
        });
        break; // Only one finding per URI is enough
      }
    }

    // 2. Dynamic URIs without domain restrictions are risky

    // Dynamic URIs without domain restrictions are risky
    findings.push({
      severity: 'high',
      message: t('finding_path_traversal_dynamic_uri', { resource: resource.name || t('unknown') }),
      component: `resource:${resource.name || t('unknown')}`,
      ruleCode: this.code,
      location: {
        type: 'resource',
        uri: resource.uri,
        name: resource.name,
      },
      evidence: {
        resourceName: resource.name || t('unknown'),
        uri: resource.uri,
        mimeType: resource.mimeType ?? null,
        hasDynamicSegments: true,
        dynamicIndicators: this.extractDynamicIndicators(uri),
      },
      remediation: t('ensure_the_server_validates_and_sanitizes_uri_para'),
    });

    // Check if URI contains file:// scheme with dynamic parts
    if (uri.startsWith('file://') && hasDynamicSegments) {
      findings.push({
        severity: 'critical',
        message: t('finding_path_traversal_file_scheme', { resource: resource.name || t('unknown') }),
        component: `resource:${resource.name || t('unknown')}`,
        ruleCode: this.code,
        location: {
          type: 'resource',
          uri: resource.uri,
          name: resource.name,
        },
        evidence: {
          resourceName: resource.name || t('unknown'),
          uri: resource.uri,
          scheme: 'file://',
          risk: t('direct_filesystem_access_with_dynamic_paths'),
        },
        remediation: t('avoid_using_file_uris_with_dynamic_segments_if_nec'),
      });
    }

    return findings;
  }

  /**
   * Determines if a parameter is likely a file path based on its name and description.
   * 
   * @param paramName - Parameter name
   * @param config - Parameter configuration object
   * @returns true if parameter appears to be a path
   */
  private isPathParameter(paramName: string, config: Record<string, JsonValue>): boolean {
    const paramNameLower = paramName.toLowerCase();
    const description = (typeof config.description === 'string' ? config.description : '').toLowerCase();
    const type = config.type;

    // Must be a string type
    if (type !== 'string') {
      return false;
    }

    // Check parameter name for path indicators
    const nameMatch = this.PATH_INDICATORS.some(indicator =>
      paramNameLower.includes(indicator)
    );

    // Check description for path indicators
    const descriptionMatch = this.PATH_INDICATORS.some(indicator =>
      description.includes(indicator)
    );

    return nameMatch || descriptionMatch;
  }

  /**
   * Tests if a regex pattern is weak and allows path traversal.
   * 
   * @param pattern - The regex pattern to test
   * @returns Object indicating if pattern is weak and what it allows
   */
  private isWeakPattern(pattern: string): {
    isWeak: boolean;
    matchedPatterns: string[];
    dangerousInput?: string;
  } {
    const matchedPatterns: string[] = [];

    // ReDoS Protection: Reject extremely long patterns that could cause DoS
    if (pattern.length > 1000) {
      return {
        isWeak: true,
        matchedPatterns: [t('evidence_redos_too_long')],
        dangerousInput: pattern.substring(0, 50) + '...'
      };
    }

    // ReDoS Protection: Detect known dangerous regex patterns
    const redosPatterns = [
      /(\w+\*)+/,          // Nested quantifiers: (a+)*
      /(\w+)+\1/,          // Backreference with quantifier
      /(\w\|)+/            // Alternation with quantifier
    ];

    for (const redosPattern of redosPatterns) {
      if (redosPattern.test(pattern)) {
        return {
          isWeak: true,
          matchedPatterns: [t('evidence_redos_pattern')],
          dangerousInput: pattern
        };
      }
    }

    // Test dangerous inputs against the pattern
    const dangerousInputs = [
      '../../etc/passwd',
      '..\\..\\windows\\system32\\config\\sam',
      '%2e%2e%2f%2e%2e%2fetc%2fpasswd',
      '/etc/shadow',
      'C:\\Windows\\System32\\config\\sam',
    ];

    try {
      // ReDoS Protection: Check pattern safety before compilation
      if (!isSafePattern(pattern)) {
        // Pattern contains dangerous constructs (nested quantifiers, etc.)
        return {
          isWeak: true,
          matchedPatterns: [t('evidence_redos_vulnerable')],
          dangerousInput: pattern
        };
      }

      // Compile regex with timeout protection
      const { regex, timedOut, error } = compileRegexSafe(pattern, undefined, { timeout: 100 });

      if (timedOut || !regex) {
        // Regex compilation or test took too long - mark as weak
        return {
          isWeak: true,
          matchedPatterns: [t('evidence_redos_timeout')],
          dangerousInput: pattern
        };
      }

      for (const dangerousInput of dangerousInputs) {
        if (regex.test(dangerousInput)) {
          matchedPatterns.push(dangerousInput);
        }
      }

      // Additional check: does the pattern explicitly allow traversal sequences?
      for (const traversalPattern of this.TRAVERSAL_PATTERNS) {
        // Create a test string that would match the traversal pattern
        const testStrings = [
          '../test',
          '..\\test',
          'test/../etc',
          '/etc/passwd',
        ];

        for (const testStr of testStrings) {
          if (regex.test(testStr) && traversalPattern.test(testStr)) {
            matchedPatterns.push(`Pattern allows: ${testStr}`);
          }
        }
      }

      return {
        isWeak: matchedPatterns.length > 0,
        matchedPatterns,
        dangerousInput: matchedPatterns[0],
      };
    } catch (error) {
      // Invalid regex - this itself is a finding but not our concern here
      return {
        isWeak: false,
        matchedPatterns: [],
      };
    }
  }

  /**
   * Checks if a URI contains dynamic segments (variables, wildcards).
   * 
   * @param uri - The URI to check
   * @returns true if URI has dynamic segments
   */
  private hasDynamicURI(uri: string): boolean {
    // Common URI template patterns
    const dynamicPatterns = [
      /\{[^}]+\}/,        // {variable}
      /\$\{[^}]+\}/,      // ${variable}
      /\*/,               // wildcards
      /.*\[.*\]/,           // [patterns]
      /:[\w]+/,           // :param (Express-style)
    ];

    return dynamicPatterns.some(pattern => pattern.test(uri));
  }

  /**
   * Extracts dynamic indicators from a URI for evidence.
   * 
   * @param uri - The URI to analyze
   * @returns Array of dynamic segment indicators found
   */
  private extractDynamicIndicators(uri: string): string[] {
    const indicators: string[] = [];

    const patterns = [
      { regex: /\{([^}]+)\}/g, type: 'curly brace variable' },
      { regex: /\$\{([^}]+)\}/g, type: 'template variable' },
      { regex: /\*/g, type: 'wildcard' },
      { regex: /\*\[([^\]]+)\]/g, type: 'bracket pattern' },
      { regex: /:(\w+)/g, type: 'colon parameter' },
    ];

    for (const { regex, type } of patterns) {
      const matches = uri.match(regex);
      if (matches) {
        indicators.push(`${type}: ${matches.join(', ')}`);
      }
    }

    return indicators;
  }
}
