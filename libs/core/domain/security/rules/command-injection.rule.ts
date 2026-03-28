/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Command Injection Detection Rule (SEC-002)
 * 
 * Detects potential command injection vulnerabilities in MCP server tools.
 * 
 * Validates:
 * - Tools that appear to execute system commands based on naming conventions
 * - Input parameters that lack strict validation patterns for shell-sensitive characters
 * 
 * @module libs/core/domain/security/rules/command-injection.rule
 */

import { t, compileRegexSafe, isSafePattern } from '@mcp-verify/shared';
import { ISecurityRule } from '../rule.interface';
import type { DiscoveryResult, SecurityFinding } from '../../mcp-server/entities/validation.types';
import type { McpTool, JsonValue } from '../../shared/common.types';

export class CommandInjectionRule implements ISecurityRule {
  readonly code = 'SEC-002';
  get name() { return t('sec_command_injection_name'); }
  get description() { return t('sec_command_injection_desc'); }
  readonly helpUri = 'https://owasp.org/www-community/attacks/Command_Injection';
  readonly tags = ['CWE-78', 'OWASP-A03:2021', 'OS Command Injection'];

  /**
   * Dangerous characters that are often used in shell injection attacks.
   * Detecting these in "allowed" patterns suggests a weak regex.
   */
  private readonly SHELL_CHARACTERS = [
    ';', '&', '|', '`', '$', '(', ')', '<', '>', '\\', '!', '\n'
  ];

  /**
   * Keywords that strongly suggest a tool executes system commands.
   */
  private readonly EXECUTION_KEYWORDS = [
    'exec', 'execute', 'run', 'system', 'spawn', 'shell', 'bash', 'cmd', 'powershell'
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
    const isExecutionTool = this.isExecutionTool(tool.name, tool.description);

    if (!tool.inputSchema?.properties) {
      // If it's an execution tool but has no schema, it might just run a fixed command (safer, but still risky)
      if (isExecutionTool) {
        findings.push({
          severity: 'medium',
          message: t('finding_cmd_injection_no_schema', { tool: tool.name }),
          component: `tool:${tool.name}`,
          ruleCode: this.code,
          evidence: { toolName: tool.name, description: tool.description ?? null }
        });
      }
      return findings;
    }

    for (const [paramName, paramConfig] of Object.entries(tool.inputSchema.properties)) {
      const config = paramConfig as Record<string, JsonValue>;

      // If the tool is known to execute commands, ALL string parameters must be strictly validated
      // If the tool is generic, we look for parameters that might be arguments (args, command, input)

      const isArgumentParam = ['arg', 'args', 'command', 'cmd', 'input', 'script'].some(k => paramName.toLowerCase().includes(k));

      if ((isExecutionTool || isArgumentParam) && config.type === 'string') {
        if (!config.pattern) {
          findings.push({
            severity: 'critical',
            message: t('finding_cmd_injection_no_validation', { param: paramName, tool: tool.name }),
            component: `tool:${tool.name}`,
            ruleCode: this.code,
            location: { type: 'tool', name: tool.name, parameter: paramName },
            evidence: {
              risk: t('risk_cmd_injection_unsanitized'),
              parameter: paramName
            },
            remediation: t('remediation_cmd_injection_whitelist')
          });
        } else if (typeof config.pattern === 'string') {
          // Check if pattern allows shell characters (type guard: pattern must be string)
          const weakResult = this.isWeakPattern(config.pattern);
          if (weakResult.isWeak) {
            findings.push({
              severity: 'critical',
              message: t('finding_cmd_injection_weak_validation', { param: paramName }),
              component: `tool:${tool.name}`,
              ruleCode: this.code,
              location: { type: 'tool', name: tool.name, parameter: paramName },
              evidence: {
                pattern: config.pattern,
                allowedShellChars: weakResult.allowedChars
              },
              remediation: t('remediation_cmd_injection_strengthen')
            });
          }
        }
      }
    }

    return findings;
  }

  private isExecutionTool(name: string, description?: string): boolean {
    const text = `${name} ${description || ''}`.toLowerCase();
    return this.EXECUTION_KEYWORDS.some(kw => text.includes(kw));
  }

  private isWeakPattern(pattern: string): { isWeak: boolean; allowedChars: string[] } {
    // ReDoS Protection: Reject extremely long patterns
    if (pattern.length > 1000) {
      return { isWeak: true, allowedChars: [t('evidence_redos_too_long')] };
    }

    // ReDoS Protection: Detect dangerous regex patterns
    const redosPatterns = [
      /(\w+\*)+/,
      /(\w+)+\1/,
      /(\w\|)+/
    ];
    for (const redosPattern of redosPatterns) {
      if (redosPattern.test(pattern)) {
        return { isWeak: true, allowedChars: [t('evidence_redos_pattern')] };
      }
    }

    try {
      // ReDoS Protection: Check pattern safety before compilation
      if (!isSafePattern(pattern)) {
        // Pattern contains dangerous constructs (nested quantifiers, etc.)
        return { isWeak: true, allowedChars: [t('evidence_redos_vulnerable')] };
      }

      // Compile regex with timeout protection
      const { regex, timedOut, error } = compileRegexSafe(pattern, undefined, { timeout: 100 });

      if (timedOut || !regex) {
        // Regex compilation or test took too long - mark as weak
        return { isWeak: true, allowedChars: [t('evidence_redos_timeout')] };
      }

      // Simplistic check: does the regex match dangerous characters?
      // A "strong" regex usually uses start/end anchors ^...$ and a character class.
      // If it contains '.', it often matches everything.
      const allowedChars: string[] = [];

      for (const char of this.SHELL_CHARACTERS) {
        if (regex.test(`test${char}test`) || regex.test(char)) {
          allowedChars.push(char);
        }
      }

      return {
        isWeak: allowedChars.length > 0,
        allowedChars
      };
    } catch (e) {
      return { isWeak: false, allowedChars: [] };
    }
  }
}
