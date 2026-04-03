/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SEC-054: API Endpoint Hijacking via Config Override (CVE-2026-21852)
 *
 * Block: D (AI Weaponization & Supply Chain MCP)
 * Severity: Critical
 * Type: Static (Pre-Execution)
 *
 * Detects MCP config files that override API base URLs to non-official domains.
 * This is the exact vector of CVE-2026-21852: API keys exfiltrate on FIRST request,
 * before any trust prompt.
 *
 * Detection:
 * Static:
 * - Scan all config files for API endpoint overrides
 * - Check environment variables: ANTHROPIC_BASE_URL, OPENAI_BASE_URL, etc.
 * - Whitelist official endpoints only
 * - Flag localhost/non-official domains as critical
 *
 * References:
 * - CVE-2026-21852: API Endpoint Hijacking in MCP Config
 * - Check Point Research: MCP Security (Vector 3)
 * - CWE-494: Download of Code Without Integrity Check
 */

import type { ISecurityRule } from '../rule.interface';
import type { DiscoveryResult, SecurityFinding } from '../../mcp-server/entities/validation.types';
import { t } from '@mcp-verify/shared';

interface McpServerConfig {
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  [key: string]: unknown;
}

interface McpConfig {
  mcpServers?: Record<string, McpServerConfig>;
  [key: string]: unknown;
}

export class ApiEndpointHijackingRule implements ISecurityRule {
  code = 'SEC-054';
  name = 'API Endpoint Hijacking via Config Override';
  severity: 'critical' = 'critical';

  private readonly OFFICIAL_ENDPOINTS = [
    'api.anthropic.com',
    'api.openai.com',
    'generativelanguage.googleapis.com',
    'api.together.xyz',
    'api.cohere.ai',
    'api.mistral.ai'
  ];

  private readonly API_ENV_VARS = [
    'ANTHROPIC_BASE_URL',
    'ANTHROPIC_API_URL',
    'OPENAI_BASE_URL',
    'OPENAI_API_URL',
    'API_BASE_URL',
    'API_URL',
    'BASE_URL',
    'GEMINI_API_URL',
    'GEMINI_BASE_URL',
    'LLM_API_URL',
    'LLM_BASE_URL'
  ];

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (!discovery.tools || discovery.tools.length === 0) {
      return findings;
    }

    // Keywords indicating endpoint registration/hijacking
    const ENDPOINT_KEYWORDS = [
      'register_endpoint', 'register endpoint', 'endpoint',
      'hijack', 'override endpoint', 'replace endpoint',
      'api endpoint', 'endpoint_path', 'route registration'
    ];

    // Keywords indicating security issues
    const INSECURE_KEYWORDS = [
      'without checking', 'without verification', 'without validation',
      'sin verificar', 'sin validación', 'no verification',
      'collision', 'override', 'replace'
    ];

    for (const tool of discovery.tools) {
      const toolText = `${tool.name} ${tool.description || ''}`.toLowerCase();

      // Check if tool mentions endpoint operations
      const hasEndpointOperation = ENDPOINT_KEYWORDS.some(kw => toolText.includes(kw));

      if (!hasEndpointOperation) continue;

      // Check for security issues
      const hasSecurityIssue = INSECURE_KEYWORDS.some(kw => toolText.includes(kw));

      // Check for endpoint_path parameter
      let hasEndpointParam = false;
      if (tool.inputSchema && typeof tool.inputSchema === 'object') {
        const schema = tool.inputSchema as Record<string, any>;
        if (schema.properties) {
          for (const paramName of Object.keys(schema.properties)) {
            if (paramName.toLowerCase().includes('endpoint') ||
                paramName.toLowerCase().includes('path') ||
                paramName.toLowerCase().includes('route')) {
              hasEndpointParam = true;
              break;
            }
          }
        }
      }

      if (hasSecurityIssue || (hasEndpointOperation && hasEndpointParam)) {
        findings.push({
          severity: 'critical',
          message: t('sec_054_tool_endpoint_hijacking', { tool: tool.name }),
          component: `tool:${tool.name}`,
          ruleCode: this.code,
          location: { type: 'tool', name: tool.name },
          evidence: {
            risk: 'Tool can register or hijack API endpoints without proper validation',
            detectedOperation: hasEndpointParam ? 'Endpoint registration with path parameter' : 'Endpoint manipulation without validation'
          },
          remediation: t('sec_054_recommendation'),
          references: [
            'CVE-2026-21852: API Endpoint Hijacking in MCP Config',
            'Check Point Research: MCP Security (Vector 3)',
            'CWE-494: Download of Code Without Integrity Check'
          ]
        });
      }
    }

    return findings;
  }

  /**
   * Evaluates a specific MCP config file for API endpoint hijacking
   */
  evaluateConfigFile(configPath: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    try {
      const fs = require('fs');
      if (!fs.existsSync(configPath)) {
        return findings;
      }

      const content = fs.readFileSync(configPath, 'utf-8');
      const config: McpConfig = JSON.parse(content);

      if (config.mcpServers) {
        for (const [serverName, serverConfig] of Object.entries(config.mcpServers)) {
          const serverFindings = this.analyzeServerEnv(serverName, serverConfig);
          findings.push(...serverFindings);
        }
      }

      // Also check top-level env if present
      const topLevelEnv = (config as { env?: Record<string, string> }).env;
      if (topLevelEnv) {
        const topLevelFindings = this.analyzeEnvVars('global', topLevelEnv);
        findings.push(...topLevelFindings);
      }
    } catch (error) {
      // Ignore parse errors - not our concern in this rule
    }

    return findings;
  }

  private analyzeServerEnv(serverName: string, serverConfig: McpServerConfig): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (!serverConfig.env) {
      return findings;
    }

    const envFindings = this.analyzeEnvVars(serverName, serverConfig.env);
    findings.push(...envFindings);

    return findings;
  }

  private analyzeEnvVars(serverName: string, env: Record<string, string>): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    for (const [envVar, envValue] of Object.entries(env)) {
      const envVarUpper = envVar.toUpperCase();

      // Check if this is an API endpoint variable
      const isApiEndpoint = this.API_ENV_VARS.some(apiVar =>
        envVarUpper.includes(apiVar) || envVarUpper === apiVar
      );

      if (isApiEndpoint) {
        const isOfficial = this.isOfficialEndpoint(envValue);

        if (!isOfficial) {
          const isLocalhost = this.isLocalhostEndpoint(envValue);
          const severity = isLocalhost ? 'high' : 'critical';

          findings.push({
            severity,
            message: t('sec_054_endpoint_hijacking', {
              serverName,
              envVar,
              value: envValue
            }),
            component: `config:${serverName}`,
            ruleCode: this.code,
            remediation: t('sec_054_recommendation'),
            references: [
              'CVE-2026-21852: API Endpoint Hijacking in MCP Config',
              'Check Point Research: MCP Security (Vector 3)',
              'CWE-494: Download of Code Without Integrity Check'
            ]
          });
        }
      }
    }

    return findings;
  }

  private isOfficialEndpoint(url: string): boolean {
    try {
      const urlObj = new URL(url);
      const hostname = urlObj.hostname.toLowerCase();

      return this.OFFICIAL_ENDPOINTS.some(official =>
        hostname === official || hostname.endsWith(`.${official}`)
      );
    } catch {
      // Invalid URL format
      return false;
    }
  }

  private isLocalhostEndpoint(url: string): boolean {
    try {
      const urlObj = new URL(url);
      const hostname = urlObj.hostname.toLowerCase();

      return hostname === 'localhost' ||
        hostname === '127.0.0.1' ||
        hostname === '0.0.0.0' ||
        hostname === '::1' ||
        hostname.startsWith('192.168.') ||
        hostname.startsWith('10.') ||
        hostname.startsWith('172.');
    } catch {
      return false;
    }
  }
}
