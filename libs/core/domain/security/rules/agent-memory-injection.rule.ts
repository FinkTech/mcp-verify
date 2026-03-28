/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SEC-041: Agent Memory Injection
 *
 * Block: B (Multi-Agent & Agentic Chain Attacks)
 * Severity: Critical
 * Type: Static + Fuzzer
 *
 * Detects tools that allow injecting malicious data into agent memory,
 * context, or long-term storage that persists across sessions.
 *
 * Detection:
 * Static:
 * - Tools writing to persistent memory without validation
 * - Missing sanitization for memory/context updates
 * - Tools accepting "system" or "instruction" type memory entries
 *
 * Fuzzer:
 * - Inject malicious memory entries
 * - Test if they persist and affect future agent behavior
 *
 * References:
 * - Multi-Agent Security Framework (MASF) 2024 - Memory Isolation
 * - OWASP LLM Top 10 - LLM01 (memory context)
 * - CWE-502: Deserialization of Untrusted Data
 */

import type { ISecurityRule } from '../rule.interface';
import type { DiscoveryResult, SecurityFinding } from '../../mcp-server/entities/validation.types';
import type { McpTool } from '../../shared/common.types';
import { t } from '@mcp-verify/shared';

export class AgentMemoryInjectionRule implements ISecurityRule {
  code = 'SEC-041';
  name = 'Agent Memory Injection';
  severity: 'critical' = 'critical';

  private readonly MEMORY_WRITE_PATTERNS = [
    /add.*memory/i, /store.*memory/i, /save.*memory/i,
    /update.*memory/i, /set.*memory/i, /persist.*memory/i,
    /write.*context/i, /add.*context/i, /update.*context/i,
    /remember/i, /memorize/i, /learn/i
  ];

  private readonly DANGEROUS_MEMORY_TYPES = [
    'system', 'instruction', 'directive', 'rule',
    'policy', 'constraint', 'behavior', 'personality'
  ];

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (!discovery.tools || discovery.tools.length === 0) {
      return findings;
    }

    for (const tool of discovery.tools) {
      const writesToMemory = this.writesToAgentMemory(tool);

      if (writesToMemory) {
        const hasValidation = this.hasMemoryValidation(tool);
        const allowsDangerousTypes = this.allowsDangerousMemoryTypes(tool);

        if (!hasValidation || allowsDangerousTypes) {
          const severity = allowsDangerousTypes ? 'critical' : 'high';

          findings.push({
            severity,
            message: t('sec_041_memory_injection', {
              toolName: tool.name,
              issue: allowsDangerousTypes
                ? 'allows system/instruction memory types'
                : 'missing memory validation'
            }),
            component: `tool:${tool.name}`,
            ruleCode: this.code,
            remediation: t('sec_041_recommendation'),
            references: [
              'Multi-Agent Security Framework (MASF) 2024 - Memory Isolation',
              'OWASP LLM Top 10 - LLM01: Prompt Injection (Memory Context)',
              'CWE-502: Deserialization of Untrusted Data'
            ]
          });
        }
      }
    }

    return findings;
  }

  private writesToAgentMemory(tool: McpTool): boolean {
    // Check name pattern
    const nameMatches = this.MEMORY_WRITE_PATTERNS.some(pattern =>
      pattern.test(tool.name)
    );
    if (nameMatches) return true;

    // Check description
    if (tool.description) {
      const descLower = tool.description.toLowerCase();
      const descMatches = this.MEMORY_WRITE_PATTERNS.some(pattern =>
        pattern.test(descLower)
      );
      if (descMatches) return true;

      // Check for memory/context keywords
      const memoryKeywords = ['memory', 'context', 'history', 'session', 'state'];
      const hasMemoryKeyword = memoryKeywords.some(kw => descLower.includes(kw));
      const mentionsWrite = descLower.includes('write') || descLower.includes('save') || descLower.includes('store') || descLower.includes('add');

      if (hasMemoryKeyword && mentionsWrite) return true;
    }

    // Check for memory parameters
    if (tool.inputSchema?.properties) {
      for (const propName of Object.keys(tool.inputSchema.properties)) {
        const propLower = propName.toLowerCase();
        if (propLower.includes('memory') || propLower.includes('context') || propLower.includes('remember')) {
          return true;
        }
      }
    }

    return false;
  }

  private hasMemoryValidation(tool: McpTool): boolean {
    // Check description for validation keywords
    if (tool.description) {
      const descLower = tool.description.toLowerCase();
      const validationKeywords = [
        'validate', 'sanitize', 'filter', 'verify',
        'check', 'whitelist', 'allowed types'
      ];

      const hasValidation = validationKeywords.some(keyword =>
        descLower.includes(keyword)
      );
      if (hasValidation) return true;
    }

    // Check if memory parameters have constraints
    if (tool.inputSchema?.properties) {
      for (const [propName, propSchema] of Object.entries(tool.inputSchema.properties)) {
        const propLower = propName.toLowerCase();
        const isMemoryParam = propLower.includes('memory') || propLower.includes('content') || propLower.includes('data');

        if (isMemoryParam) {
          const schema = propSchema as {
            pattern?: string;
            format?: string;
            enum?: unknown[];
            maxLength?: number;
            [key: string]: unknown;
          };

          const hasConstraints = schema.pattern || schema.format || schema.enum || schema.maxLength;
          if (hasConstraints) return true;
        }
      }
    }

    return false;
  }

  private allowsDangerousMemoryTypes(tool: McpTool): boolean {
    if (!tool.inputSchema?.properties) {
      return false;
    }

    // Check for "type" or "memory_type" parameter
    for (const [propName, propSchema] of Object.entries(tool.inputSchema.properties)) {
      const propLower = propName.toLowerCase();

      if (propLower === 'type' || propLower === 'memory_type' || propLower === 'entry_type') {
        const schema = propSchema as {
          enum?: string[];
          [key: string]: unknown;
        };

        // If enum exists, check if it includes dangerous types
        if (schema.enum) {
          const enumValues = schema.enum.map(v => String(v).toLowerCase());
          const hasDangerousType = this.DANGEROUS_MEMORY_TYPES.some(dangerous =>
            enumValues.includes(dangerous)
          );

          if (hasDangerousType) return true;
        } else {
          // No enum = accepts any type = dangerous
          return true;
        }
      }
    }

    return false;
  }
}
