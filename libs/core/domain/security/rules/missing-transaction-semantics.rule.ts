/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * SEC-060: Missing Transaction Semantics for Critical Operations
 *
 * Block: D (AI Weaponization & Supply Chain)
 * Severity: High
 * Type: Static + Semantic
 *
 * Detects tools that perform multi-step critical operations without
 * transaction semantics (atomicity, rollback, undo mechanisms).
 * Critical for autonomous agents that may fail mid-operation.
 *
 * Detection:
 * Static:
 * - Tools with multi-step operations without rollback parameters
 * - Batch/bulk operations without transaction mentions
 * - Financial/data modification tools without undo capability
 *
 * Semantic:
 * - LLM analyzes if tool description mentions atomic operations
 * - Evaluates if tool provides rollback/compensation mechanisms
 *
 * References:
 * - ACID Properties in Distributed Systems
 * - Saga Pattern for Long-Running Transactions
 * - CWE-362: Concurrent Execution using Shared Resource
 */

import type { ISecurityRule } from '../rule.interface';
import type { DiscoveryResult, SecurityFinding } from '../../mcp-server/entities/validation.types';
import type { McpTool } from '../../shared/common.types';
import { t } from '@mcp-verify/shared';

export class MissingTransactionSemanticsRule implements ISecurityRule {
  code = 'SEC-060';
  name = 'Missing Transaction Semantics for Critical Operations';
  severity: 'high' = 'high';

  private readonly MULTI_STEP_KEYWORDS = [
    'batch', 'bulk', 'multiple', 'mass', 'all',
    'cascade', 'recursive', 'chain', 'sequence'
  ];

  private readonly CRITICAL_OPERATION_KEYWORDS = [
    'delete', 'remove', 'update', 'modify', 'transfer',
    'payment', 'transaction', 'commit', 'apply', 'execute'
  ];

  private readonly TRANSACTION_KEYWORDS = [
    'transaction', 'atomic', 'rollback', 'undo', 'revert',
    'compensate', 'saga', 'two-phase', '2pc', 'commit'
  ];

  private readonly ROLLBACK_PARAM_NAMES = [
    'transaction_id', 'rollback_on_error', 'atomic',
    'dry_run', 'simulate', 'preview', 'undo_token'
  ];

  evaluate(discovery: DiscoveryResult): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (!discovery.tools || discovery.tools.length === 0) {
      return findings;
    }

    for (const tool of discovery.tools) {
      const isMultiStep = this.isMultiStepOperation(tool);
      const isCritical = this.isCriticalOperation(tool);

      if (isMultiStep && isCritical) {
        const hasTransactionSemantics = this.hasTransactionSemantics(tool);

        if (!hasTransactionSemantics) {
          findings.push({
            severity: this.severity,
            message: t('sec_060_missing_transaction', {
              toolName: tool.name
            }),
            component: `tool:${tool.name}`,
            ruleCode: this.code,
            remediation: t('sec_060_recommendation'),
            references: [
              'ACID Properties in Distributed Systems',
              'Saga Pattern for Long-Running Transactions',
              'CWE-362: Concurrent Execution using Shared Resource'
            ]
          });
        }
      }
    }

    return findings;
  }

  private isMultiStepOperation(tool: McpTool): boolean {
    const nameLower = tool.name.toLowerCase();
    const descLower = tool.description?.toLowerCase() || '';

    // Check for multi-step keywords
    const hasMultiStepKeyword = this.MULTI_STEP_KEYWORDS.some(keyword =>
      nameLower.includes(keyword) || descLower.includes(keyword)
    );

    if (hasMultiStepKeyword) return true;

    // Check for array parameters (indicates batch operations)
    if (tool.inputSchema?.properties) {
      for (const [propName, propSchema] of Object.entries(tool.inputSchema.properties)) {
        const schema = propSchema as { type?: string | string[]; items?: unknown };
        const types = Array.isArray(schema.type) ? schema.type : [schema.type];

        if (types.includes('array') && schema.items) {
          // Check if array contains complex objects (multi-step indicator)
          const items = schema.items as { type?: string };
          if (items.type === 'object') {
            return true;
          }
        }
      }
    }

    return false;
  }

  private isCriticalOperation(tool: McpTool): boolean {
    const nameLower = tool.name.toLowerCase();
    const descLower = tool.description?.toLowerCase() || '';

    return this.CRITICAL_OPERATION_KEYWORDS.some(keyword =>
      nameLower.includes(keyword) || descLower.includes(keyword)
    );
  }

  private hasTransactionSemantics(tool: McpTool): boolean {
    // Check description for transaction keywords
    if (tool.description) {
      const descLower = tool.description.toLowerCase();
      const hasTransactionKeyword = this.TRANSACTION_KEYWORDS.some(keyword =>
        descLower.includes(keyword)
      );
      if (hasTransactionKeyword) return true;
    }

    // Check for rollback/transaction parameters
    if (tool.inputSchema?.properties) {
      const paramNames = Object.keys(tool.inputSchema.properties).map(p => p.toLowerCase());

      const hasRollbackParam = this.ROLLBACK_PARAM_NAMES.some(param =>
        paramNames.includes(param)
      );
      if (hasRollbackParam) return true;
    }

    return false;
  }
}
