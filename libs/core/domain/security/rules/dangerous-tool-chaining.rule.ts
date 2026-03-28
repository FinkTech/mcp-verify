/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Dangerous Tool Chaining Potential Detection Rule (SEC-020)
 *
 * Detects tools designed to output executable code, scripts, or commands
 * that could be chained with execution tools, creating injection vulnerabilities.
 * Also identifies tools that accept output from other tools without sanitization.
 *
 * Validates:
 * - Tools that generate executable code (scripts, SQL, commands)
 * - Tools accepting unsanitized input from other tool outputs
 * - Code generation tools without safety warnings
 * - Dynamic query/command builders
 *
 * Attack vectors:
 * - Chaining code generation → execution tools
 * - Passing malicious LLM output directly to execution
 * - SQL injection via query generation chains
 * - Command injection via script generation chains
 *
 * Note: This rule provides advisory warnings, not blocking findings.
 *
 * @module libs/core/domain/security/rules/dangerous-tool-chaining.rule
 */

import { t } from '@mcp-verify/shared';
import { ISecurityRule } from '../rule.interface';
import type { DiscoveryResult, SecurityFinding } from '../../mcp-server/entities/validation.types';
import type { McpTool } from '../../shared/common.types';

export class DangerousToolChainingRule implements ISecurityRule {
  readonly code = 'SEC-020';
  get name() { return t('sec_tool_chaining_name'); }
  get description() { return t('sec_tool_chaining_desc'); }
  readonly helpUri = 'https://owasp.org/www-project-top-ten/2017/A1_2017-Injection';
  readonly tags = ['CWE-94', 'CWE-913', 'OWASP-A03:2021', 'Code Injection'];

  /**
   * Keywords indicating code/script generation
   */
  private readonly CODE_GENERATION_KEYWORDS = [
    'generate code', 'code generation', 'generate script', 'script generation',
    'returns code', 'outputs code', 'produces code',
    'code generator', 'script generator',
    'build query', 'generate sql', 'construct command',
    'compile', 'transpile', 'codegen'
  ];

  /**
   * Keywords in tool names suggesting code generation
   */
  private readonly CODE_GEN_TOOL_NAMES = [
    'codegen', 'code_gen', 'generate_code',
    'script_gen', 'scriptgen', 'generate_script',
    'query_builder', 'sql_builder', 'command_builder',
    'template_compiler'
  ];

  /**
   * Output field names that suggest executable content
   */
  private readonly EXECUTABLE_OUTPUT_FIELDS = [
    'code', 'script', 'query', 'sql', 'command',
    'executable', 'shellscript', 'bash', 'python',
    'javascript', 'typescript', 'dockerfile'
  ];

  /**
   * Keywords indicating execution of external input
   */
  private readonly EXECUTION_INPUT_KEYWORDS = [
    'execute input', 'run from', 'eval',
    'accepts code', 'input code', 'code from',
    'dynamic execution', 'runtime execution'
  ];

  /**
   * Safety indicators (mitigating factors)
   */
  private readonly SAFETY_KEYWORDS = [
    'sanitize', 'sanitized', 'validate', 'validated',
    'escape', 'escaped', 'safe', 'sandbox',
    'review', 'manual review', 'approve', 'approval required'
  ];

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (discovery.tools) {
      // First pass: Identify code generation tools
      const codeGenTools: McpTool[] = [];
      const executionTools: McpTool[] = [];

      for (const tool of discovery.tools) {
        if (this.isCodeGenerationTool(tool)) {
          codeGenTools.push(tool);
          findings.push(...this.analyzeCodeGenTool(tool));
        }

        if (this.isExecutionTool(tool)) {
          executionTools.push(tool);
        }
      }

      // Second pass: Detect dangerous chaining potential
      if (codeGenTools.length > 0 && executionTools.length > 0) {
        findings.push({
          severity: 'medium',
          message: t('finding_tool_chaining_potential', {
            codeGenCount: codeGenTools.length,
            execCount: executionTools.length
          }),
          component: 'server',
          ruleCode: this.code,
          evidence: {
            codeGenerationTools: codeGenTools.map(t => t.name),
            executionTools: executionTools.map(t => t.name),
            risk: t('risk_tool_chaining_injection')
          },
          remediation: t('remediation_tool_chaining_validate')
        });
      }
    }

    return findings;
  }

  private isCodeGenerationTool(tool: McpTool): boolean {
    const text = `${tool.name} ${tool.description || ''}`.toLowerCase();

    // Check tool name patterns
    if (this.CODE_GEN_TOOL_NAMES.some(pattern => tool.name.toLowerCase().includes(pattern))) {
      return true;
    }

    // Check description keywords
    if (this.CODE_GENERATION_KEYWORDS.some(kw => text.includes(kw))) {
      return true;
    }

    return false;
  }

  private isExecutionTool(tool: McpTool): boolean {
    const text = `${tool.name} ${tool.description || ''}`.toLowerCase();

    const executionKeywords = [
      'execute', 'exec', 'run', 'eval',
      'invoke', 'call', 'process'
    ];

    return executionKeywords.some(kw => text.includes(kw));
  }

  private analyzeCodeGenTool(tool: McpTool): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const text = `${tool.name} ${tool.description || ''}`.toLowerCase();

    // Check if safety measures are mentioned
    const hasSafetyKeyword = this.SAFETY_KEYWORDS.some(kw => text.includes(kw));

    // Identify output type
    const outputTypes: string[] = [];
    this.EXECUTABLE_OUTPUT_FIELDS.forEach(field => {
      if (text.includes(field)) {
        outputTypes.push(field);
      }
    });

    // Warning: Code generation without safety mentions
    if (!hasSafetyKeyword) {
      findings.push({
        severity: 'medium',
        message: t('finding_tool_chaining_codegen_no_safety', {
          tool: tool.name
        }),
        component: `tool:${tool.name}`,
        ruleCode: this.code,
        location: { type: 'tool', name: tool.name },
        evidence: {
          toolType: 'code generation',
          outputTypes: outputTypes.length > 0 ? outputTypes : ['code'],
          safetyMentioned: false,
          risk: t('risk_tool_chaining_unsafe_output')
        },
        remediation: t('remediation_tool_chaining_add_warning')
      });
    }

    // Check if tool accepts input for code generation
    if (tool.inputSchema?.properties) {
      const inputFields = Object.keys(tool.inputSchema.properties);
      const dangerousInputs = inputFields.filter(field =>
        ['template', 'input', 'source', 'data', 'content'].some(kw =>
          field.toLowerCase().includes(kw)
        )
      );

      if (dangerousInputs.length > 0) {
        findings.push({
          severity: 'low',
          message: t('finding_tool_chaining_dynamic_gen', {
            tool: tool.name,
            params: dangerousInputs.join(', ')
          }),
          component: `tool:${tool.name}`,
          ruleCode: this.code,
          location: { type: 'tool', name: tool.name },
          evidence: {
            dynamicInputs: dangerousInputs,
            risk: t('risk_tool_chaining_template_injection')
          },
          remediation: t('remediation_tool_chaining_sanitize_input')
        });
      }
    }

    return findings;
  }
}
